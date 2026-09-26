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
