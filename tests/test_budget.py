"""POST /redact/budget 端到端测试，以及 select_fragments_with_budget 单元测试。"""

from __future__ import annotations

from itertools import combinations

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.redaction import Fragment, select_fragments, select_fragments_with_budget

client = TestClient(app)


def post(payload: object) -> object:
    return client.post("/redact/budget", json=payload)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 核心算法单元测试
# ---------------------------------------------------------------------------


def f(fid: int, weight: int, start: int, end: int) -> Fragment:
    return Fragment(id=fid, weight=weight, start=start, end=end)


def test_budget_zero_selects_nothing() -> None:
    frags = [f(1, 5, 0, 3), f(2, 1, 3, 6)]
    assert select_fragments_with_budget(frags, 0) == ()


def test_budget_empty_fragments() -> None:
    assert select_fragments_with_budget([], 10) == ()
    assert select_fragments_with_budget([], 0) == ()


def test_budget_adjacent_fragments_both_fit() -> None:
    frags = [f(2, 1, 3, 6), f(1, 1, 0, 3)]
    # 预算恰好等于两个片段长度之和（相邻可组合）时同时入选。
    assert select_fragments_with_budget(frags, 6) == (1, 2)
    # 预算只够一个片段：两者权重、长度相同，按 ID 升序取 1。
    assert select_fragments_with_budget(frags, 3) == (1,)


def test_budget_limits_total_masked_chars() -> None:
    # 片段 1 [0,4) 权重 5、长度 4；片段 2 [0,2) 权重 4、长度 2。
    frags = [f(1, 5, 0, 4), f(2, 4, 0, 2)]
    # 预算 4：无约束最优 1 入选。
    assert select_fragments_with_budget(frags, 4) == (1,)
    # 预算 3：片段 1 超预算，只能选片段 2。
    assert select_fragments_with_budget(frags, 3) == (2,)
    assert select_fragments_with_budget(frags, 2) == (2,)
    # 预算 1：谁都放不下。
    assert select_fragments_with_budget(frags, 1) == ()


def test_budget_prefers_weight_then_chars_then_id_list() -> None:
    # [0,3) 权重 5（长 3）；[0,2) 权重 3（长 2）+[2,5) 权重 1（长 3），
    # 组合权重 4、长 5。预算 5 时权重 5 > 4，选 1。
    frags = [f(1, 5, 0, 3), f(2, 3, 0, 2), f(3, 1, 2, 5)]
    assert select_fragments_with_budget(frags, 5) == (1,)
    # 预算 4：片段 1 长 3 可入选（权重 5），2+3 总长 5 超预算，
    # 单独的 3（权重 1）不如 1，仍选 1。
    assert select_fragments_with_budget(frags, 4) == (1,)

    # 权重并列时取遮盖码点更多者：
    # [0,2) 权重 3（长 2）与 [0,1)+[1,2) 权重 2+1（长 2）长度相同 -> 看 ID 列表。
    a = [f(2, 3, 0, 2), f(1, 2, 0, 1), f(3, 1, 1, 2)]
    assert select_fragments_with_budget(a, 2) == (1, 3)

    # 权重与长度都并列：[0,1) 上的 {5} 与 {6}，取 ID 小者。
    b = [f(6, 1, 0, 1), f(5, 1, 0, 1)]
    assert select_fragments_with_budget(b, 1) == (5,)


def test_budget_matches_unconstrained_when_budget_large() -> None:
    frags = [f(1, 5, 0, 3), f(2, 3, 0, 2), f(3, 1, 2, 5)]
    assert select_fragments_with_budget(frags, 100) == select_fragments(frags)
    # 恰好等于全部区间长度之和（3+2+3=8）时也等价于无约束。
    assert select_fragments_with_budget(frags, 8) == select_fragments(frags)


def test_budget_string_ids() -> None:
    frags = [
        Fragment(id="b", weight=1, start=0, end=1),
        Fragment(id="a", weight=1, start=1, end=2),
    ]
    assert select_fragments_with_budget(frags, 2) == ("a", "b")
    assert select_fragments_with_budget(frags, 1) == ("a",)


# ---------------------------------------------------------------------------
# 随机化正确性：预算 DP 结果必须与带预算的 2^n 暴力枚举一致。
# ---------------------------------------------------------------------------


def _brute_force_budget(
    frags: list[Fragment], budget: int
) -> tuple[int, ...]:
    def compatible(subset: tuple[Fragment, ...]) -> bool:
        ordered = sorted(subset, key=lambda x: x.start)
        return all(a.end <= b.start for a, b in zip(ordered, ordered[1:]))

    best: tuple[int, int, tuple[int, ...]] | None = None
    for size in range(len(frags) + 1):
        for subset in combinations(frags, size):
            total_len = sum(x.length for x in subset)
            if total_len > budget or not compatible(subset):
                continue
            key = (
                sum(x.weight for x in subset),
                total_len,
                tuple(sorted(x.id for x in subset)),
            )
            if (
                best is None
                or key[:2] > best[:2]
                or (key[:2] == best[:2] and key[2] < best[2])
            ):
                best = key
    assert best is not None
    return best[2]


def test_budget_dp_matches_brute_force_random() -> None:
    import random

    rng = random.Random(20260926)
    for trial in range(300):
        n = rng.randint(0, 7)
        horizon = rng.randint(1, 8)
        ids = rng.sample(range(100), n) if n else []
        frags: list[Fragment] = []
        for i in range(n):
            start = rng.randrange(horizon)
            end = rng.randrange(start + 1, horizon + 1)
            frags.append(Fragment(id=ids[i], weight=rng.randint(1, 4), start=start, end=end))
        budget = rng.randint(0, horizon + 2)
        expected = _brute_force_budget(frags, budget)
        assert select_fragments_with_budget(frags, budget) == expected, (
            f"trial {trial}: budget={budget} frags={frags}"
        )


# ---------------------------------------------------------------------------
# /redact/budget 正常流程
# ---------------------------------------------------------------------------


def test_budget_end_to_end_truncates_combination() -> None:
    resp = post(
        {
            "text": "你好，世界！",
            "fragments": [
                {"id": 1, "weight": 5, "start": 0, "end": 3},
                {"id": 2, "weight": 3, "start": 0, "end": 2},
                {"id": 3, "weight": 1, "start": 2, "end": 5},
            ],
            "max_masked_chars": 3,
        }
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    # 无预算时片段 1（权重 5）入选；预算 3 下片段 1 恰好放得下。
    assert data["selected_ids"] == [1]
    assert data["rejected_ids"] == [2, 3]
    assert data["masked_text"] == "███世界！"
    assert data["used_chars"] == 3


def test_budget_forces_smaller_combination() -> None:
    # 片段 1 [0,4) 权重 5 超出预算 3；片段 2 [0,2) 权重 3 可入选。
    resp = post(
        {
            "text": "abcdef",
            "fragments": [
                {"id": 1, "weight": 5, "start": 0, "end": 4},
                {"id": 2, "weight": 3, "start": 0, "end": 2},
            ],
            "max_masked_chars": 3,
        }
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["selected_ids"] == [2]
    assert data["rejected_ids"] == [1]
    assert data["masked_text"] == "██cdef"
    assert data["used_chars"] == 2


def test_budget_zero_returns_unmasked_text() -> None:
    resp = post(
        {
            "text": "你好，世界！",
            "fragments": [
                {"id": 1, "weight": 5, "start": 0, "end": 3},
                {"id": 2, "weight": 3, "start": 3, "end": 6},
            ],
            "max_masked_chars": 0,
        }
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {
        "selected_ids": [],
        "rejected_ids": [1, 2],
        "masked_text": "你好，世界！",
        "used_chars": 0,
    }


def test_budget_zero_empty_fragments() -> None:
    resp = post({"text": "abc", "fragments": [], "max_masked_chars": 0})
    assert resp.status_code == 200
    assert resp.json() == {
        "selected_ids": [],
        "rejected_ids": [],
        "masked_text": "abc",
        "used_chars": 0,
    }


def test_budget_adjacent_fragments_share_budget() -> None:
    resp = post(
        {
            "text": "abcdef",
            "fragments": [
                {"id": 1, "weight": 1, "start": 0, "end": 3},
                {"id": 2, "weight": 1, "start": 3, "end": 6},
            ],
            "max_masked_chars": 6,
        }
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["selected_ids"] == [1, 2]
    assert data["rejected_ids"] == []
    assert data["masked_text"] == "██████"
    assert data["used_chars"] == 6


def test_budget_string_ids() -> None:
    resp = post(
        {
            "text": "abc",
            "fragments": [
                {"id": "x", "weight": 1, "start": 0, "end": 1},
                {"id": "a", "weight": 1, "start": 1, "end": 2},
            ],
            "max_masked_chars": 1,
        }
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["selected_ids"] == ["a"]
    assert data["rejected_ids"] == ["x"]
    # 片段 "a" 位于 [1,2)，遮盖文本第 2 个码点。
    assert data["masked_text"] == "a█c"
    assert data["used_chars"] == 1


def test_budget_large_equals_redact() -> None:
    payload = {
        "text": "你好，世界！",
        "fragments": [
            {"id": 1, "weight": 5, "start": 0, "end": 3},
            {"id": 2, "weight": 3, "start": 0, "end": 2},
            {"id": 3, "weight": 1, "start": 2, "end": 5},
        ],
    }
    redact = client.post("/redact", json=payload).json()
    resp = post({**payload, "max_masked_chars": 100})
    assert resp.status_code == 200
    data = resp.json()
    assert data["selected_ids"] == redact["selected_ids"]
    assert data["rejected_ids"] == redact["rejected_ids"]
    assert data["masked_text"] == redact["masked_text"]
    assert data["used_chars"] == 3


def test_budget_extra_fields_are_ignored() -> None:
    resp = post(
        {
            "text": "abc",
            "fragments": [{"id": 1, "weight": 1, "start": 0, "end": 1, "note": "x"}],
            "max_masked_chars": 1,
            "request_id": "r-1",
        }
    )
    assert resp.status_code == 200
    assert resp.json()["selected_ids"] == [1]


def test_openapi_lists_budget_path() -> None:
    schema = client.get("/openapi.json").json()
    assert "/redact/budget" in schema["paths"]
    assert "/redact" in schema["paths"]
    assert "/redact/revise" in schema["paths"]


# ---------------------------------------------------------------------------
# 拒绝类输入：全部 400
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        # 缺 max_masked_chars
        {"text": "abc", "fragments": []},
        # 非法预算：负数 / 浮点 / 布尔 / 字符串 / None
        {"text": "abc", "fragments": [], "max_masked_chars": -1},
        {"text": "abc", "fragments": [], "max_masked_chars": 1.0},
        {"text": "abc", "fragments": [], "max_masked_chars": 0.5},
        {"text": "abc", "fragments": [], "max_masked_chars": True},
        {"text": "abc", "fragments": [], "max_masked_chars": False},
        {"text": "abc", "fragments": [], "max_masked_chars": "3"},
        {"text": "abc", "fragments": [], "max_masked_chars": None},
        # text / fragments 的校验规则与 /redact 一致
        {"fragments": [], "max_masked_chars": 1},
        {"text": 123, "fragments": [], "max_masked_chars": 1},
        {"text": "abc", "fragments": {}, "max_masked_chars": 1},
        {"text": "abc",
         "fragments": [{"id": 1, "weight": 0, "start": 0, "end": 1}],
         "max_masked_chars": 1},
        {"text": "abc",
         "fragments": [{"id": 1, "weight": 1, "start": 0, "end": 4}],
         "max_masked_chars": 1},
    ],
)
def test_budget_invalid_payloads_rejected_with_400(payload: object) -> None:
    resp = post(payload)
    assert resp.status_code == 400, payload
    assert "detail" in resp.json()


def test_budget_invalid_json_body_rejected_with_400() -> None:
    resp = client.post(
        "/redact/budget", content="{not json", headers={"Content-Type": "application/json"}
    )
    assert resp.status_code == 400


def test_budget_empty_body_rejected_with_400() -> None:
    resp = client.post(
        "/redact/budget", content=b"", headers={"Content-Type": "application/json"}
    )
    assert resp.status_code == 400
