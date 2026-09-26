"""脱敏发布凭证 API 端到端测试。"""

from __future__ import annotations

import sqlite3

import pytest
from fastapi.testclient import TestClient

from app import publishing
from app.main import app


@pytest.fixture
def client(tmp_path, monkeypatch) -> TestClient:
    db = tmp_path / "publish.db"
    monkeypatch.setenv("REDACTION_DB_PATH", str(db))
    # lifespan 中的 init_db 也读取该环境变量。
    with TestClient(app) as c:
        yield c


def publish(client: TestClient, payload: object):
    return client.post("/redact/publish", json=payload)  # type: ignore[arg-type]


PAYLOAD = {
    "text": "你好，世界！",
    "fragments": [
        {"id": 1, "weight": 5, "start": 0, "end": 3},
        {"id": 2, "weight": 3, "start": 0, "end": 2},
        {"id": 3, "weight": 1, "start": 2, "end": 5},
    ],
}


# ---------------------------------------------------------------------------
# 发布
# ---------------------------------------------------------------------------


def test_publish_matches_redact_selection(client: TestClient) -> None:
    resp = publish(client, PAYLOAD)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["credential_id"] == 1
    assert data["selected_ids"] == [1]
    assert data["masked_text"] == "███世界！"
    assert len(data["chain_value"]) == 64
    assert all(ch in "0123456789abcdef" for ch in data["chain_value"])


def test_publish_ids_increment_and_chain_links(client: TestClient) -> None:
    first = publish(client, PAYLOAD).json()
    second = publish(
        client,
        {
            "text": "abcdef",
            "fragments": [
                {"id": 1, "weight": 1, "start": 0, "end": 3},
                {"id": 2, "weight": 1, "start": 3, "end": 6},
            ],
        },
    ).json()
    assert first["credential_id"] == 1
    assert second["credential_id"] == 2
    assert first["chain_value"] != second["chain_value"]

    # 重算第二条链值，应引用第一条的库存链值
    from app.main import REDACT_REQUEST_SCHEMA  # noqa: F401
    from app import publishing as p

    cred = p.get_credential(2)
    assert cred is not None
    assert p.compute_chain_value(
        cred.seq,
        cred.masked_text,
        cred.ranges,
        cred.text_digest,
        first["chain_value"],
    ) == second["chain_value"] == cred.chain_value


def test_publish_persists_ranges_but_not_plaintext(client: TestClient, tmp_path) -> None:
    publish(client, PAYLOAD)
    db = tmp_path / "publish.db"
    conn = sqlite3.connect(db)
    rows = conn.execute(
        "SELECT masked_text, ranges_json, text_digest, chain_value "
        "FROM redaction_publish"
    ).fetchall()
    conn.close()
    assert len(rows) == 1
    masked_text, ranges_json, text_digest, chain_value = rows[0]
    assert masked_text == "███世界！"
    assert ranges_json == "[[0,3]]"
    salt_hex, hash_hex = text_digest.split("$")
    assert len(salt_hex) == 64 and len(hash_hex) == 64
    assert len(chain_value) == 64
    # 原文“你好，世界！”不得落盘
    assert "你好，世界！".encode("utf-8") not in db.read_bytes()


def test_publish_empty_fragments_persists_full_text_as_masked(client: TestClient) -> None:
    data = publish(client, {"text": "abc", "fragments": []}).json()
    assert data["credential_id"] == 1
    assert data["selected_ids"] == []
    assert data["masked_text"] == "abc"
    verify = client.get(
        f"/redact/publish/{data['credential_id']}/verify",
        params={"chain_value": data["chain_value"]},
    ).json()
    assert verify["valid"] is True
    assert verify["first_broken_id"] is None


@pytest.mark.parametrize(
    "payload",
    [
        {"fragments": []},
        {"text": 123, "fragments": []},
        {"text": "abc", "fragments": {}},
        {"text": "abc", "fragments": [{"id": 1, "weight": 0, "start": 0, "end": 1}]},
        {"text": "abc", "fragments": [{"id": 1, "weight": 1, "start": 2, "end": 1}]},
        {"text": "abc", "fragments": [{"id": 1, "weight": 1, "start": 0, "end": 4}]},
        {
            "text": "abc",
            "fragments": [
                {"id": 1, "weight": 1, "start": 0, "end": 1},
                {"id": 1, "weight": 1, "start": 1, "end": 2},
            ],
        },
    ],
)
def test_publish_reuses_redact_validation(client: TestClient, payload: object) -> None:
    resp = publish(client, payload)
    assert resp.status_code == 400
    assert "detail" in resp.json()


def test_publish_invalid_json_returns_400(client: TestClient) -> None:
    resp = client.post(
        "/redact/publish",
        content="{not json",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# 核验
# ---------------------------------------------------------------------------


def test_verify_valid_chain(client: TestClient) -> None:
    first = publish(client, PAYLOAD).json()
    second = publish(client, PAYLOAD).json()

    # 核验最新凭证：1..2 整链重算
    resp = client.get(
        f"/redact/publish/{second['credential_id']}/verify",
        params={"chain_value": second["chain_value"]},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data == {
        "credential_id": 2,
        "valid": True,
        "first_broken_id": None,
        "chain_value_matches": True,
        "server_chain_value": second["chain_value"],
    }

    # 旧凭证仍可凭当时留存的链值核验（截至该凭证重算）
    resp = client.get(
        "/redact/publish/1/verify",
        params={"chain_value": first["chain_value"]},
    )
    assert resp.json()["valid"] is True
    assert resp.json()["server_chain_value"] == first["chain_value"]


def test_verify_wrong_chain_value(client: TestClient) -> None:
    data = publish(client, PAYLOAD).json()
    resp = client.get(
        f"/redact/publish/{data['credential_id']}/verify",
        params={"chain_value": "f" * 64},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["valid"] is False
    assert body["first_broken_id"] is None  # 链本身完整，只是留存值不符
    assert body["chain_value_matches"] is False
    assert body["server_chain_value"] == data["chain_value"]


def test_verify_detects_tampered_record_and_first_broken(client: TestClient, tmp_path) -> None:
    first = publish(client, PAYLOAD).json()
    second = publish(client, PAYLOAD).json()

    db = tmp_path / "publish.db"
    conn = sqlite3.connect(db)
    conn.execute(
        "UPDATE redaction_publish SET masked_text = ? WHERE seq = 1",
        ("被篡改",),
    )
    conn.commit()
    conn.close()

    # 用第二凭证发布时的链值核验：链在编号 1 处断裂
    resp = client.get(
        "/redact/publish/2/verify",
        params={"chain_value": second["chain_value"]},
    )
    body = resp.json()
    assert resp.status_code == 200
    assert body["valid"] is False
    assert body["first_broken_id"] == 1

    # 单独核验编号 1 同样报 1 断裂；旧留存链值不再匹配
    resp = client.get(
        "/redact/publish/1/verify",
        params={"chain_value": first["chain_value"]},
    )
    body = resp.json()
    assert body["valid"] is False
    assert body["first_broken_id"] == 1
    assert body["chain_value_matches"] is False


def test_verify_missing_credential_returns_404(client: TestClient) -> None:
    resp = client.get("/redact/publish/999/verify", params={"chain_value": "a" * 64})
    assert resp.status_code == 404
    assert resp.json() == {"detail": "凭证不存在"}


def test_verify_missing_chain_value_returns_400(client: TestClient) -> None:
    publish(client, PAYLOAD)
    resp = client.get("/redact/publish/1/verify")
    assert resp.status_code == 400
    assert "chain_value" in resp.json()["detail"]


@pytest.mark.parametrize("bad", ["", "abc", "F" * 64, "g" * 64, "a" * 63, "a" * 65, "a" * 64 + " "])
def test_verify_malformed_chain_value_returns_400(client: TestClient, bad: str) -> None:
    publish(client, PAYLOAD)
    resp = client.get("/redact/publish/1/verify", params={"chain_value": bad})
    assert resp.status_code == 400, resp.text
    assert "chain_value" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# 并发发布
# ---------------------------------------------------------------------------


def test_concurrent_publish_keeps_sequential_chain(client: TestClient) -> None:
    import concurrent.futures

    def publish_one(i: int):
        return publish(
            client,
            {
                "text": f"原文{i}",
                "fragments": [{"id": 1, "weight": 1, "start": 0, "end": 1}],
            },
        ).json()

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(publish_one, range(30)))

    ids = sorted(r["credential_id"] for r in results)
    assert ids == list(range(1, 31))
    assert len({r["chain_value"] for r in results}) == 30

    # 从 1 核验到 30，链完整
    last_chain = next(r["chain_value"] for r in results if r["credential_id"] == 30)
    body = client.get(
        "/redact/publish/30/verify", params={"chain_value": last_chain}
    ).json()
    assert body["valid"] is True
    assert body["first_broken_id"] is None


def test_publish_and_verify_in_openapi(client: TestClient) -> None:
    schema = client.get("/openapi.json").json()
    assert "/redact/publish" in schema["paths"]
    assert "/redact/publish/{credential_id}/verify" in schema["paths"]
    assert schema["paths"]["/redact/publish"]["post"]["tags"] == ["脱敏发布凭证"]


# ---------------------------------------------------------------------------
# 便携核验包：导出
# ---------------------------------------------------------------------------


def _publish_n(client: TestClient, n: int) -> list[dict]:
    results = []
    for i in range(n):
        resp = publish(
            client,
            {
                "text": f"原文编号{i}内容",
                "fragments": [
                    {"id": 1, "weight": 1, "start": 0, "end": 2},
                    {"id": 2, "weight": 1, "start": 2, "end": 4},
                ],
            },
        )
        assert resp.status_code == 200, resp.text
        results.append(resp.json())
    return results


def test_export_returns_ordered_package(client: TestClient) -> None:
    published = _publish_n(client, 3)
    resp = client.get("/redact/publish/3/export")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["tail_seq"] == 3
    assert [r["seq"] for r in data["records"]] == [1, 2, 3]
    first = data["records"][0]
    assert set(first) == {"seq", "masked_text", "ranges", "text_digest", "chain_value"}
    assert first["masked_text"] == "████0内容"
    assert first["ranges"] == [[0, 2], [2, 4]]
    assert first["chain_value"] == published[0]["chain_value"]
    salt, digest = first["text_digest"].split("$")
    assert len(salt) == 64 and len(digest) == 64

    # 前缀导出 1..2
    resp = client.get("/redact/publish/2/export")
    assert [r["seq"] for r in resp.json()["records"]] == [1, 2]


def test_export_unknown_id_returns_404(client: TestClient) -> None:
    _publish_n(client, 1)
    resp = client.get("/redact/publish/2/export")
    assert resp.status_code == 404
    assert resp.json() == {"detail": "凭证不存在"}
    resp = client.get("/redact/publish/0/export")
    assert resp.status_code == 404
    assert resp.json() == {"detail": "凭证不存在"}


def test_export_non_integer_id_rejected(client: TestClient) -> None:
    resp = client.get("/redact/publish/abc/export")
    assert resp.status_code == 422


def test_export_package_contains_no_plaintext(client: TestClient) -> None:
    secret = "机密原文绝不导出到包里"
    publish(
        client,
        {
            "text": secret,
            "fragments": [{"id": 1, "weight": 1, "start": 0, "end": len(secret)}],
        },
    )
    resp = client.get("/redact/publish/1/export")
    blob = resp.content
    assert secret.encode("utf-8") not in blob
    assert "绝不导出".encode("utf-8") not in blob
    assert resp.json()["records"][0]["masked_text"] == "█" * len(secret)


# ---------------------------------------------------------------------------
# 便携核验包：离线核验
# ---------------------------------------------------------------------------


def _export(client: TestClient, seq: int) -> dict:
    resp = client.get(f"/redact/publish/{seq}/export")
    assert resp.status_code == 200, resp.text
    return resp.json()


def _verify_package(client: TestClient, package: object, chain_value: object):
    return client.post(
        "/redact/publish/verify-package",
        json={"package": package, "chain_value": chain_value},
    )


def test_verify_package_roundtrip_valid(client: TestClient) -> None:
    published = _publish_n(client, 3)
    package = _export(client, 3)
    resp = _verify_package(client, package, published[-1]["chain_value"])
    assert resp.status_code == 200, resp.text
    assert resp.json() == {
        "credential_id": 3,
        "valid": True,
        "first_broken_id": None,
        "chain_value_matches": True,
        "server_chain_value": published[-1]["chain_value"],
    }

    # 前缀包凭发布编号 2 时留存的链值核验
    prefix = _export(client, 2)
    resp = _verify_package(client, prefix, published[1]["chain_value"])
    assert resp.json()["valid"] is True
    assert resp.json()["credential_id"] == 2


def test_verify_package_shuffled_order_still_valid(client: TestClient) -> None:
    published = _publish_n(client, 3)
    package = _export(client, 3)
    package["records"] = list(reversed(package["records"]))
    resp = _verify_package(client, package, published[-1]["chain_value"])
    assert resp.status_code == 200
    assert resp.json()["valid"] is True
    assert resp.json()["first_broken_id"] is None


def test_verify_package_wrong_saved_chain_value(client: TestClient) -> None:
    _publish_n(client, 2)
    package = _export(client, 2)
    resp = _verify_package(client, package, "f" * 64)
    body = resp.json()
    assert resp.status_code == 200
    assert body["valid"] is False
    assert body["first_broken_id"] is None  # 链本身完整，只是留存值不符
    assert body["chain_value_matches"] is False
    assert body["server_chain_value"] == package["records"][-1]["chain_value"]


def test_verify_package_detects_missing_record(client: TestClient) -> None:
    published = _publish_n(client, 3)
    package = _export(client, 3)
    package["records"] = [
        r for r in package["records"] if r["seq"] != 2
    ]
    resp = _verify_package(client, package, published[-1]["chain_value"])
    body = resp.json()
    assert resp.status_code == 200
    assert body["valid"] is False
    assert body["first_broken_id"] == 2

    # 缺失末端记录：server_chain_value 为 null
    package = _export(client, 3)
    package["records"] = [
        r for r in package["records"] if r["seq"] != 3
    ]
    body = _verify_package(client, package, published[-1]["chain_value"]).json()
    assert body["first_broken_id"] == 3
    assert body["server_chain_value"] is None
    assert body["valid"] is False


def test_verify_package_detects_tampered_content(client: TestClient) -> None:
    published = _publish_n(client, 3)
    package = _export(client, 3)
    package["records"][1]["masked_text"] = "被篡改的遮盖正文"
    body = _verify_package(client, package, published[-1]["chain_value"]).json()
    assert body["valid"] is False
    assert body["first_broken_id"] == 2


def test_verify_package_detects_tampered_chain_value(client: TestClient) -> None:
    published = _publish_n(client, 2)
    package = _export(client, 2)
    package["records"][0]["chain_value"] = "a" * 64
    body = _verify_package(client, package, published[-1]["chain_value"]).json()
    assert body["valid"] is False
    assert body["first_broken_id"] == 1


def test_verify_package_detects_tampered_ranges(client: TestClient) -> None:
    published = _publish_n(client, 2)
    package = _export(client, 2)
    package["records"][1]["ranges"] = [[2, 4], [0, 2]]
    body = _verify_package(client, package, published[-1]["chain_value"]).json()
    assert body["first_broken_id"] == 2
    assert body["valid"] is False


def test_verify_package_detects_duplicate_seq(client: TestClient) -> None:
    published = _publish_n(client, 3)
    package = _export(client, 3)
    package["records"].append(dict(package["records"][0]))
    body = _verify_package(client, package, published[-1]["chain_value"]).json()
    assert body["valid"] is False
    assert body["first_broken_id"] == 1


def test_verify_package_does_not_touch_database(
    client: TestClient, monkeypatch
) -> None:
    published = _publish_n(client, 2)
    package = _export(client, 2)

    # 核验期间任何 SQLite 连接尝试都应直接失败：证明接口不访问数据库。
    def forbid_connect(*_args, **_kwargs):
        raise AssertionError("verify-package 不应访问数据库")

    monkeypatch.setattr(publishing.sqlite3, "connect", forbid_connect)
    resp = _verify_package(client, package, published[-1]["chain_value"])
    assert resp.status_code == 200
    assert resp.json()["valid"] is True


def test_verify_package_invalid_json_returns_400(client: TestClient) -> None:
    resp = client.post(
        "/redact/publish/verify-package",
        content="{not json",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 400


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"package": {"tail_seq": 1, "records": []}},
        {"chain_value": "a" * 64},
        {"package": {"tail_seq": 1, "records": []}, "chain_value": "z" * 64},
        {"package": {"tail_seq": 1, "records": []}, "chain_value": "A" * 64},
        {"package": {"tail_seq": 1, "records": []}, "chain_value": "a" * 63},
        {"package": {"tail_seq": 1, "records": []}, "chain_value": 123},
        # 包结构错误
        {"package": [], "chain_value": "a" * 64},
        {"package": {"records": []}, "chain_value": "a" * 64},
        {"package": {"tail_seq": 0, "records": []}, "chain_value": "a" * 64},
        {"package": {"tail_seq": -1, "records": []}, "chain_value": "a" * 64},
        {"package": {"tail_seq": True, "records": []}, "chain_value": "a" * 64},
        {"package": {"tail_seq": "2", "records": []}, "chain_value": "a" * 64},
        {"package": {"tail_seq": 1, "records": {}}, "chain_value": "a" * 64},
        # 记录字段错误
        {
            "package": {"tail_seq": 1, "records": [{}]},
            "chain_value": "a" * 64,
        },
        {
            "package": {
                "tail_seq": 1,
                "records": [
                    {
                        "seq": 0,
                        "masked_text": "x",
                        "ranges": [],
                        "text_digest": f"{'b' * 64}${'c' * 64}",
                        "chain_value": "d" * 64,
                    }
                ],
            },
            "chain_value": "a" * 64,
        },
        {
            "package": {
                "tail_seq": 1,
                "records": [
                    {
                        "seq": 2,
                        "masked_text": "x",
                        "ranges": [],
                        "text_digest": f"{'b' * 64}${'c' * 64}",
                        "chain_value": "d" * 64,
                    }
                ],
            },
            "chain_value": "a" * 64,
        },
        {
            "package": {
                "tail_seq": 1,
                "records": [
                    {
                        "seq": 1,
                        "masked_text": 3,
                        "ranges": [],
                        "text_digest": f"{'b' * 64}${'c' * 64}",
                        "chain_value": "d" * 64,
                    }
                ],
            },
            "chain_value": "a" * 64,
        },
        {
            "package": {
                "tail_seq": 1,
                "records": [
                    {
                        "seq": 1,
                        "masked_text": "x",
                        "ranges": [[0, 1, 2]],
                        "text_digest": f"{'b' * 64}${'c' * 64}",
                        "chain_value": "d" * 64,
                    }
                ],
            },
            "chain_value": "a" * 64,
        },
        {
            "package": {
                "tail_seq": 1,
                "records": [
                    {
                        "seq": 1,
                        "masked_text": "x",
                        "ranges": [[1, 1]],
                        "text_digest": f"{'b' * 64}${'c' * 64}",
                        "chain_value": "d" * 64,
                    }
                ],
            },
            "chain_value": "a" * 64,
        },
        {
            "package": {
                "tail_seq": 1,
                "records": [
                    {
                        "seq": 1,
                        "masked_text": "x",
                        "ranges": [["0", 1]],
                        "text_digest": f"{'b' * 64}${'c' * 64}",
                        "chain_value": "d" * 64,
                    }
                ],
            },
            "chain_value": "a" * 64,
        },
        {
            "package": {
                "tail_seq": 1,
                "records": [
                    {
                        "seq": 1,
                        "masked_text": "x",
                        "ranges": [],
                        "text_digest": "not-a-digest",
                        "chain_value": "d" * 64,
                    }
                ],
            },
            "chain_value": "a" * 64,
        },
        {
            "package": {
                "tail_seq": 1,
                "records": [
                    {
                        "seq": 1,
                        "masked_text": "x",
                        "ranges": [],
                        "text_digest": f"{'b' * 63}${'c' * 64}",
                        "chain_value": "d" * 64,
                    }
                ],
            },
            "chain_value": "a" * 64,
        },
        {
            "package": {
                "tail_seq": 1,
                "records": [
                    {
                        "seq": 1,
                        "masked_text": "x",
                        "ranges": [],
                        "text_digest": f"{'B' * 64}${'c' * 64}",
                        "chain_value": "d" * 64,
                    }
                ],
            },
            "chain_value": "a" * 64,
        },
        {
            "package": {
                "tail_seq": 1,
                "records": [
                    {
                        "seq": 1,
                        "masked_text": "x",
                        "ranges": [],
                        "text_digest": f"{'b' * 64}${'c' * 64}",
                        "chain_value": "d" * 63,
                    }
                ],
            },
            "chain_value": "a" * 64,
        },
    ],
)
def test_verify_package_malformed_returns_400(
    client: TestClient, payload: object
) -> None:
    resp = client.post("/redact/publish/verify-package", json=payload)
    assert resp.status_code == 400, resp.text
    assert "detail" in resp.json()


def test_export_and_verify_package_in_openapi(client: TestClient) -> None:
    schema = client.get("/openapi.json").json()
    assert "/redact/publish/{credential_id}/export" in schema["paths"]
    assert "/redact/publish/verify-package" in schema["paths"]
    export_path = schema["paths"]["/redact/publish/{credential_id}/export"]
    verify_path = schema["paths"]["/redact/publish/verify-package"]
    assert export_path["get"]["tags"] == ["脱敏发布凭证"]
    assert verify_path["post"]["tags"] == ["脱敏发布凭证"]
