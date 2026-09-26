"""便携核验包导出（export）与离线核验（verify-package）端到端测试。"""

from __future__ import annotations

import copy

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


PAYLOAD = {
    "text": "你好，世界！",
    "fragments": [
        {"id": 1, "weight": 5, "start": 0, "end": 3},
        {"id": 2, "weight": 3, "start": 0, "end": 2},
    ],
}

SECOND = {
    "text": "abcdef",
    "fragments": [
        {"id": 1, "weight": 1, "start": 0, "end": 3},
        {"id": 2, "weight": 1, "start": 3, "end": 6},
    ],
}


def publish(client: TestClient, payload: object) -> dict:
    resp = client.post("/redact/publish", json=payload)  # type: ignore[arg-type]
    assert resp.status_code == 200, resp.text
    return resp.json()


def export(client: TestClient, seq: int):
    return client.get(f"/redact/publish/{seq}/export")


def verify_package(client: TestClient, package: object, tail_chain_value: object):
    return client.post(
        "/redact/publish/verify-package",
        json={"package": package, "tail_chain_value": tail_chain_value},
    )


def publish_two(client: TestClient) -> tuple[dict, dict]:
    return publish(client, PAYLOAD), publish(client, SECOND)


# ---------------------------------------------------------------------------
# 导出
# ---------------------------------------------------------------------------


def test_export_returns_ordered_records(client: TestClient) -> None:
    first, second = publish_two(client)

    resp = export(client, 2)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["through_seq"] == 2
    assert [r["seq"] for r in data["records"]] == [1, 2]

    rec1, rec2 = data["records"]
    assert rec1 == {
        "seq": 1,
        "masked_text": "███世界！",
        "ranges": [[0, 3]],
        "text_digest": rec1["text_digest"],
        "chain_value": first["chain_value"],
    }
    assert rec2["masked_text"] == "██████"
    assert rec2["ranges"] == [[0, 3], [3, 6]]
    assert rec2["chain_value"] == second["chain_value"]
    # 带盐原文摘要形如 "<64 位盐 hex>$<64 位摘要 hex>"
    for record in (rec1, rec2):
        salt_hex, hash_hex = record["text_digest"].split("$")
        assert len(salt_hex) == 64 and len(hash_hex) == 64


def test_export_prefix_returns_only_records_through_id(client: TestClient) -> None:
    first, _second = publish_two(client)
    data = export(client, 1).json()
    assert data["through_seq"] == 1
    assert len(data["records"]) == 1
    assert data["records"][0]["chain_value"] == first["chain_value"]


def test_export_package_contains_no_plaintext(client: TestClient) -> None:
    # 全文遮盖，响应中任何位置都不应出现原文。
    publish(
        client,
        {
            "text": "机密原文绝不外泄",
            "fragments": [{"id": 1, "weight": 1, "start": 0, "end": 8}],
        },
    )
    resp = export(client, 1)
    assert resp.status_code == 200
    assert "机密原文绝不外泄" not in resp.text
    assert resp.json()["records"][0]["masked_text"] == "████████"


def test_export_unknown_id_returns_404(client: TestClient) -> None:
    resp = export(client, 999)
    assert resp.status_code == 404
    assert resp.json() == {"detail": "凭证不存在"}

    publish(client, PAYLOAD)
    assert export(client, 2).status_code == 404


def test_export_function_returns_ordered_records(client: TestClient, tmp_path) -> None:
    # 直接验证底层导出函数：返回 1..tail_seq 的有序记录，编号不存在为 None。
    publish_two(client)
    db = str(tmp_path / "publish.db")
    records = publishing.export_credentials_through(2, path=db)
    assert records is not None
    assert [r.seq for r in records] == [1, 2]
    assert publishing.export_credentials_through(3, path=db) is None


# ---------------------------------------------------------------------------
# 离线核验：通过
# ---------------------------------------------------------------------------


def test_verify_package_round_trip_valid(client: TestClient) -> None:
    _first, second = publish_two(client)
    package = export(client, 2).json()

    resp = verify_package(client, package, second["chain_value"])
    assert resp.status_code == 200, resp.text
    assert resp.json() == {
        "through_seq": 2,
        "valid": True,
        "first_broken_id": None,
        "tail_chain_value_matches": True,
    }


def test_verify_package_prefix_export_with_old_tail(client: TestClient) -> None:
    first, _second = publish_two(client)
    # 只导出到 1，用第 1 条发布时留存的链值核验。
    package = export(client, 1).json()
    body = verify_package(client, package, first["chain_value"]).json()
    assert body["valid"] is True
    assert body["through_seq"] == 1


def test_verify_package_does_not_touch_database(
    client: TestClient, monkeypatch
) -> None:
    _first, second = publish_two(client)
    package = export(client, 2).json()

    def forbidden_connect(path: str):  # pragma: no cover - 被调用即失败
        raise AssertionError("verify-package 不应访问数据库")

    monkeypatch.setattr(publishing, "_connect", forbidden_connect)
    body = verify_package(client, package, second["chain_value"]).json()
    assert body["valid"] is True


# ---------------------------------------------------------------------------
# 离线核验：断裂与末端链值不符
# ---------------------------------------------------------------------------


def test_verify_package_detects_tampered_content(client: TestClient) -> None:
    _first, second = publish_two(client)
    package = export(client, 2).json()
    package["records"][0]["masked_text"] = "被篡改"

    body = verify_package(client, package, second["chain_value"]).json()
    assert body["valid"] is False
    assert body["first_broken_id"] == 1
    assert body["tail_chain_value_matches"] is False


def test_verify_package_detects_tampered_chain_value(client: TestClient) -> None:
    _first, second = publish_two(client)
    package = export(client, 2).json()
    package["records"][1]["chain_value"] = "f" * 64

    body = verify_package(client, package, second["chain_value"]).json()
    assert body["valid"] is False
    assert body["first_broken_id"] == 2


def test_verify_package_detects_missing_record(client: TestClient) -> None:
    _first, second = publish_two(client)
    package = export(client, 2).json()

    # 删掉中间的第 1 条：缺号 1
    del package["records"][0]
    body = verify_package(client, copy.deepcopy(package), second["chain_value"]).json()
    assert body["valid"] is False
    assert body["first_broken_id"] == 1

    # 删掉末尾的第 2 条（through_seq 仍为 2）：尾部缺号 2
    package = export(client, 2).json()
    del package["records"][1]
    body = verify_package(client, package, second["chain_value"]).json()
    assert body["valid"] is False
    assert body["first_broken_id"] == 2


def test_verify_package_wrong_tail_chain_value(client: TestClient) -> None:
    publish_two(client)
    package = export(client, 2).json()

    body = verify_package(client, package, "f" * 64).json()
    assert body["valid"] is False
    assert body["first_broken_id"] is None  # 链本身完整，只是留存值不符
    assert body["tail_chain_value_matches"] is False


# ---------------------------------------------------------------------------
# 离线核验：格式错误一律 400
# ---------------------------------------------------------------------------


def _valid_package(client: TestClient) -> tuple[dict, str]:
    _first, second = publish_two(client)
    return export(client, 2).json(), second["chain_value"]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda body: body.pop("package"),
        lambda body: body.pop("tail_chain_value"),
        lambda body: body.update(package="not-an-object"),
        lambda body: body["package"].pop("through_seq"),
        lambda body: body["package"].pop("records"),
        lambda body: body["package"].update(through_seq=0),
        lambda body: body["package"].update(through_seq="2"),
        lambda body: body["package"].update(through_seq=True),
        lambda body: body["package"].update(records=[]),
        lambda body: body["package"].update(records="not-a-list"),
        lambda body: body["package"].update(
            records=body["package"]["records"] + [body["package"]["records"][0]]
        ),  # 记录数超过 through_seq
        lambda body: body["package"]["records"][0].pop("seq"),
        lambda body: body["package"]["records"][0].pop("masked_text"),
        lambda body: body["package"]["records"][0].pop("ranges"),
        lambda body: body["package"]["records"][0].pop("text_digest"),
        lambda body: body["package"]["records"][0].pop("chain_value"),
        lambda body: body["package"]["records"][0].update(seq=0),
        lambda body: body["package"]["records"][0].update(seq=True),
        lambda body: body["package"]["records"][0].update(masked_text=123),
        lambda body: body["package"]["records"][0].update(ranges="not-a-list"),
        lambda body: body["package"]["records"][0].update(ranges=[[0]]),
        lambda body: body["package"]["records"][0].update(ranges=[[0, 1, 2]]),
        lambda body: body["package"]["records"][0].update(ranges=[[-1, 2]]),
        lambda body: body["package"]["records"][0].update(ranges=[[2, 1]]),
        lambda body: body["package"]["records"][0].update(ranges=[[0, True]]),
        lambda body: body["package"]["records"][0].update(text_digest=42),
        lambda body: body["package"]["records"][0].update(chain_value="xyz"),
        lambda body: body["package"]["records"][0].update(chain_value="F" * 64),
        lambda body: body.update(tail_chain_value="xyz"),
        lambda body: body.update(tail_chain_value="F" * 64),
        lambda body: body.update(tail_chain_value=123),
    ],
)
def test_verify_package_malformed_returns_400(client: TestClient, mutate) -> None:
    package, tail = _valid_package(client)
    body = {"package": package, "tail_chain_value": tail}
    mutate(body)
    resp = client.post("/redact/publish/verify-package", json=body)
    assert resp.status_code == 400, resp.text
    assert "detail" in resp.json()


def test_verify_package_invalid_json_returns_400(client: TestClient) -> None:
    resp = client.post(
        "/redact/publish/verify-package",
        content="{not json",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 400


def test_verify_package_non_object_body_returns_400(client: TestClient) -> None:
    resp = client.post("/redact/publish/verify-package", json=[1, 2, 3])
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# OpenAPI
# ---------------------------------------------------------------------------


def test_export_and_verify_package_in_openapi(client: TestClient) -> None:
    schema = client.get("/openapi.json").json()
    assert "/redact/publish/{credential_id}/export" in schema["paths"]
    assert "/redact/publish/verify-package" in schema["paths"]
    export_op = schema["paths"]["/redact/publish/{credential_id}/export"]["get"]
    verify_op = schema["paths"]["/redact/publish/verify-package"]["post"]
    assert export_op["tags"] == ["脱敏发布凭证"]
    assert verify_op["tags"] == ["脱敏发布凭证"]
