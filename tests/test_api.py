"""API 端到端测试。"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def post(payload: object) -> object:
    return client.post("/redact", json=payload)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 正常流程
# ---------------------------------------------------------------------------


def test_end_to_end_overlapping_and_masking() -> None:
    resp = post(
        {
            "text": "你好，世界！",
            "fragments": [
                {"id": 1, "weight": 5, "start": 0, "end": 3},
                {"id": 2, "weight": 3, "start": 0, "end": 2},
                {"id": 3, "weight": 1, "start": 2, "end": 5},
            ],
        }
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    # 片段 1（[0,3) 权重 5）与 2、3 都冲突；2+3 相邻可组合（权重 4）。
    # 按权重总和取 1，尽管 2+3 遮盖字符更多。
    assert data["selected_ids"] == [1]
    assert data["rejected_ids"] == [2, 3]
    # 原文 0..3 为“你好，”，遮盖后保留“世界！”。
    assert data["masked_text"] == "███世界！"


def test_adjacent_fragments_both_selected() -> None:
    resp = post(
        {
            "text": "abcdef",
            "fragments": [
                {"id": 2, "weight": 1, "start": 3, "end": 6},
                {"id": 1, "weight": 1, "start": 0, "end": 3},
            ],
        }
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["selected_ids"] == [1, 2]
    assert data["rejected_ids"] == []
    assert data["masked_text"] == "██████"


def test_empty_fragment_list_returns_original_text() -> None:
    resp = post({"text": "abc", "fragments": []})
    assert resp.status_code == 200
    assert resp.json() == {"selected_ids": [], "rejected_ids": [], "masked_text": "abc"}


def test_string_ids_supported_and_sorted() -> None:
    resp = post(
        {
            "text": "abc",
            "fragments": [
                {"id": "x", "weight": 1, "start": 0, "end": 1},
                {"id": "a", "weight": 1, "start": 1, "end": 2},
            ],
        }
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["selected_ids"] == ["a", "x"]
    assert data["rejected_ids"] == []
    assert data["masked_text"] == "██c"


def test_health_and_root() -> None:
    assert client.get("/health").json() == {"status": "ok"}
    assert client.get("/").status_code == 200


def test_openapi_available() -> None:
    schema = client.get("/openapi.json").json()
    assert "/redact" in schema["paths"]


# ---------------------------------------------------------------------------
# 拒绝类输入：全部 400
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        # 缺字段
        {"fragments": []},
        {"text": "abc"},
        # 类型错误
        {"text": 123, "fragments": []},
        {"text": "abc", "fragments": {}},
        # 片段缺字段 / 类型错误
        {"text": "abc", "fragments": [{"id": 1, "weight": 1, "start": 0}]},
        {"text": "abc", "fragments": [{"id": 1, "weight": "1", "start": 0, "end": 1}]},
        {"text": "abc", "fragments": [{"id": 1.0, "weight": 1, "start": 0, "end": 1}]},
        {"text": "abc", "fragments": [{"id": True, "weight": 1, "start": 0, "end": 1}]},
        {"text": "abc", "fragments": [{"id": 1, "weight": True, "start": 0, "end": 1}]},
        {"text": "abc", "fragments": [{"id": 1, "weight": 1, "start": 0.5, "end": 1}]},
        {"id": None},
        # 权重非正
        {"text": "abc", "fragments": [{"id": 1, "weight": 0, "start": 0, "end": 1}]},
        {"text": "abc", "fragments": [{"id": 1, "weight": -2, "start": 0, "end": 1}]},
        # 越界
        {"text": "abc", "fragments": [{"id": 1, "weight": 1, "start": 0, "end": 4}]},
        {"text": "abc", "fragments": [{"id": 1, "weight": 1, "start": -1, "end": 2}]},
        # 空片段 / 反向
        {"text": "abc", "fragments": [{"id": 1, "weight": 1, "start": 1, "end": 1}]},
        {"text": "abc", "fragments": [{"id": 1, "weight": 1, "start": 2, "end": 1}]},
        # 重复 ID
        {"text": "abc", "fragments": [
            {"id": 1, "weight": 1, "start": 0, "end": 1},
            {"id": 1, "weight": 1, "start": 1, "end": 2},
        ]},
        # ID 类型混用
        {"text": "abc", "fragments": [
            {"id": 1, "weight": 1, "start": 0, "end": 1},
            {"id": "1", "weight": 1, "start": 1, "end": 2},
        ]},
        # 空字符串 ID
        {"text": "abc", "fragments": [{"id": "", "weight": 1, "start": 0, "end": 1}]},
    ],
)
def test_invalid_payloads_rejected_with_400(payload: object) -> None:
    resp = post(payload)
    assert resp.status_code == 400, payload
    assert "detail" in resp.json()


def test_invalid_json_body_rejected_with_400() -> None:
    resp = client.post("/redact", content="{not json", headers={"Content-Type": "application/json"})
    assert resp.status_code == 400


def test_empty_body_rejected_with_400() -> None:
    resp = client.post("/redact", content=b"", headers={"Content-Type": "application/json"})
    assert resp.status_code == 400


def test_extra_fields_are_ignored() -> None:
    resp = post(
        {
            "text": "abc",
            "fragments": [{"id": 1, "weight": 1, "start": 0, "end": 1, "note": "x"}],
            "request_id": "r-1",
        }
    )
    assert resp.status_code == 200
    assert resp.json()["selected_ids"] == [1]
