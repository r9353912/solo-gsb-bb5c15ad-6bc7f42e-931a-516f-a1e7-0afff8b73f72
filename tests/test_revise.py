"""POST /redact/revise 端到端测试，以及 apply_edits / migrate_fragment 单元测试。"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.redaction import Edit, Fragment, apply_edits, migrate_fragment

client = TestClient(app)


def post(payload: object) -> object:
    return client.post("/redact/revise", json=payload)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# apply_edits 单元测试
# ---------------------------------------------------------------------------


def e(start: int, end: int, replacement: str) -> Edit:
    return Edit(start=start, end=end, replacement=replacement)


def test_apply_no_edits_returns_original() -> None:
    assert apply_edits("abc", []) == "abc"


def test_apply_replace_delete_insert() -> None:
    assert apply_edits("abcdef", [e(1, 3, "XY")]) == "aXYdef"
    assert apply_edits("abcdef", [e(1, 3, "")]) == "adef"
    assert apply_edits("abcdef", [e(2, 2, "XY")]) == "abXYcdef"


def test_apply_multiple_edits_at_once() -> None:
    # 区间均按原文定位：删首字符、删尾两字符同时进行。
    assert apply_edits("abcdef", [e(0, 1, "X"), e(4, 6, "")]) == "Xbcd"
    # 相邻替换。
    assert apply_edits("abcdef", [e(0, 2, "A"), e(2, 4, "B")]) == "ABef"
    # 同一位置的插入先于同起点的替换生效。
    assert apply_edits("abcdef", [e(2, 4, "R"), e(2, 2, "I")]) == "abIRef"


def test_apply_edits_astral_code_points() -> None:
    assert apply_edits("a😀b", [e(1, 2, "X")]) == "aXb"
    assert apply_edits("", [e(0, 0, "🎉")]) == "🎉"


# ---------------------------------------------------------------------------
# migrate_fragment 单元测试
# ---------------------------------------------------------------------------


def f(fid: int, start: int, end: int) -> Fragment:
    return Fragment(id=fid, weight=1, start=start, end=end)


def test_migrate_no_edits_keeps_interval() -> None:
    assert migrate_fragment(f(1, 2, 4), []) == f(1, 2, 4)


def test_migrate_shifts_by_cumulative_delta_of_prior_edits() -> None:
    frag = f(1, 5, 7)
    edits = [e(0, 2, ""), e(3, 3, "ABCD"), e(4, 5, "XY")]  # 位移 -2 +4 +1
    assert migrate_fragment(frag, edits) == f(1, 8, 10)


def test_migrate_delete_or_replace_intersecting_invalidates() -> None:
    frag = f(1, 2, 5)
    assert migrate_fragment(frag, [e(0, 3, "")]) is None  # 覆盖起点
    assert migrate_fragment(frag, [e(4, 6, "")]) is None  # 覆盖终点
    assert migrate_fragment(frag, [e(2, 5, "Z")]) is None  # 完全重合
    assert migrate_fragment(frag, [e(3, 4, "Z")]) is None  # 被包含


def test_migrate_adjacent_delete_or_replace_keeps_and_shifts() -> None:
    frag = f(1, 2, 4)
    # 紧邻片段之前的删除：整段左移。
    assert migrate_fragment(frag, [e(0, 2, "")]) == f(1, 0, 2)
    # 紧邻片段之后的删除：不受影响。
    assert migrate_fragment(frag, [e(4, 6, "")]) == f(1, 2, 4)


def test_migrate_insertion_strictly_inside_invalidates() -> None:
    frag = f(1, 2, 5)
    assert migrate_fragment(frag, [e(3, 3, "X")]) is None
    assert migrate_fragment(frag, [e(2, 5, ""), e(3, 3, "X")]) is None


def test_migrate_insertion_at_start_shifts_whole_fragment() -> None:
    assert migrate_fragment(f(1, 2, 4), [e(2, 2, "XYZ")]) == f(1, 5, 7)


def test_migrate_insertion_at_end_does_not_expand() -> None:
    assert migrate_fragment(f(1, 2, 4), [e(4, 4, "XYZ")]) == f(1, 2, 4)


def test_migrate_insertion_before_or_after() -> None:
    frag = f(1, 2, 4)
    assert migrate_fragment(frag, [e(0, 0, "AB")]) == f(1, 4, 6)
    assert migrate_fragment(frag, [e(6, 6, "AB")]) == f(1, 2, 4)


# ---------------------------------------------------------------------------
# /redact/revise 正常流程
# ---------------------------------------------------------------------------


def test_revise_end_to_end() -> None:
    resp = post(
        {
            "text": "你好，世界！",
            "fragments": [
                {"id": 1, "weight": 5, "start": 0, "end": 2},
                {"id": 2, "weight": 3, "start": 3, "end": 5},
            ],
            "edits": [
                {"start": 2, "end": 3, "replacement": "！"},
                {"start": 6, "end": 6, "replacement": "再见"},
            ],
        }
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["revised_text"] == "你好！世界！再见"
    assert data["invalidated_ids"] == []
    # 两个片段均未被编辑波及：替换区间与片段相邻，插入在文末。
    assert data["selected_ids"] == [1, 2]
    assert data["rejected_ids"] == []
    assert data["masked_text"] == "██！██！再见"


def test_revise_delete_intersection_invalidates_and_shifts_rest() -> None:
    resp = post(
        {
            "text": "abcdef",
            "fragments": [
                {"id": 1, "weight": 1, "start": 1, "end": 3},  # 与删除相交 -> 作废
                {"id": 2, "weight": 1, "start": 4, "end": 6},  # 前方删除 -> 左移 2
            ],
            "edits": [{"start": 2, "end": 4, "replacement": ""}],
        }
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["revised_text"] == "abef"
    assert data["invalidated_ids"] == [1]
    assert data["selected_ids"] == [2]
    assert data["rejected_ids"] == []
    # 片段 2 迁移为 [2,4)，即修订后文本中的 "ef"。
    assert data["masked_text"] == "ab██"


def test_revise_insertion_strictly_inside_invalidates() -> None:
    resp = post(
        {
            "text": "abcdef",
            "fragments": [{"id": 1, "weight": 1, "start": 1, "end": 4}],
            "edits": [{"start": 3, "end": 3, "replacement": "X"}],
        }
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["revised_text"] == "abcXdef"
    assert data["invalidated_ids"] == [1]
    assert data["selected_ids"] == []
    assert data["rejected_ids"] == []
    assert data["masked_text"] == "abcXdef"


def test_revise_insertion_at_start_shifts_fragment_right() -> None:
    resp = post(
        {
            "text": "abcdef",
            "fragments": [{"id": 1, "weight": 1, "start": 1, "end": 3}],
            "edits": [{"start": 1, "end": 1, "replacement": "XY"}],
        }
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["revised_text"] == "aXYbcdef"
    # 插入在片段起点：整段右移且不作废，插入内容不并入片段。
    assert data["invalidated_ids"] == []
    assert data["selected_ids"] == [1]
    assert data["masked_text"] == "aXY██def"


def test_revise_insertion_at_end_does_not_expand_fragment() -> None:
    resp = post(
        {
            "text": "abcdef",
            "fragments": [{"id": 1, "weight": 1, "start": 1, "end": 3}],
            "edits": [{"start": 3, "end": 3, "replacement": "XY"}],
        }
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["revised_text"] == "abcXYdef"
    # 插入在片段终点：不扩展片段，区间不变。
    assert data["invalidated_ids"] == []
    assert data["selected_ids"] == [1]
    assert data["masked_text"] == "a██XYdef"


def test_revise_cumulative_displacement() -> None:
    resp = post(
        {
            "text": "abcdefgh",
            "fragments": [{"id": 1, "weight": 1, "start": 5, "end": 7}],  # "fg"
            "edits": [
                {"start": 0, "end": 2, "replacement": ""},      # 位移 -2
                {"start": 3, "end": 3, "replacement": "ABCD"},  # 位移 +4
            ],
        }
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["revised_text"] == "cABCDdefgh"
    assert data["invalidated_ids"] == []
    # 片段整体右移 2 码点："fg" 现位于 [7,9)。
    assert data["masked_text"] == "cABCDde██h"


def test_revise_selection_only_among_kept_fragments() -> None:
    resp = post(
        {
            "text": "abcdef",
            "fragments": [
                {"id": 1, "weight": 1, "start": 0, "end": 2},
                {"id": 2, "weight": 1, "start": 1, "end": 3},  # 与 1 重叠
                {"id": 3, "weight": 1, "start": 4, "end": 6},  # 被删除 -> 作废
            ],
            "edits": [{"start": 4, "end": 6, "replacement": ""}],
        }
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["revised_text"] == "abcd"
    assert data["invalidated_ids"] == [3]
    # 保留片段 1、2 权重与长度均并列，取 ID 升序字典序最小者。
    assert data["selected_ids"] == [1]
    assert data["rejected_ids"] == [2]
    assert data["masked_text"] == "██cd"


def test_revise_empty_edits_matches_redact() -> None:
    payload = {
        "text": "你好，世界！",
        "fragments": [
            {"id": 1, "weight": 5, "start": 0, "end": 3},
            {"id": 2, "weight": 3, "start": 0, "end": 2},
            {"id": 3, "weight": 1, "start": 2, "end": 5},
        ],
    }
    redact = client.post("/redact", json=payload).json()
    resp = post({**payload, "edits": []})
    assert resp.status_code == 200
    data = resp.json()
    assert data["revised_text"] == payload["text"]
    assert data["invalidated_ids"] == []
    assert data["selected_ids"] == redact["selected_ids"]
    assert data["rejected_ids"] == redact["rejected_ids"]
    assert data["masked_text"] == redact["masked_text"]


def test_revise_string_ids_sorted_in_all_lists() -> None:
    resp = post(
        {
            "text": "abcdef",
            "fragments": [
                {"id": "b", "weight": 1, "start": 0, "end": 2},  # 被替换 -> 作废
                {"id": "a", "weight": 1, "start": 3, "end": 4},
                {"id": "c", "weight": 1, "start": 4, "end": 5},  # 与 a 相邻，均入选
            ],
            "edits": [{"start": 0, "end": 2, "replacement": "Q"}],
        }
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["revised_text"] == "Qcdef"
    assert data["invalidated_ids"] == ["b"]
    assert data["selected_ids"] == ["a", "c"]
    assert data["rejected_ids"] == []
    # 片段 a、c 各左移 1 码点。
    assert data["masked_text"] == "Qc██f"


def test_revise_astral_code_points() -> None:
    resp = post(
        {
            "text": "a😀b😀c",  # 5 个码点
            "fragments": [{"id": 1, "weight": 1, "start": 1, "end": 2}],
            "edits": [{"start": 0, "end": 0, "replacement": "🎉"}],
        }
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["revised_text"] == "🎉a😀b😀c"
    assert data["invalidated_ids"] == []
    assert data["masked_text"] == "🎉a█b😀c"


def test_revise_adjacent_edits_and_boundary_insertions_allowed() -> None:
    resp = post(
        {
            "text": "abcdef",
            "fragments": [{"id": 1, "weight": 1, "start": 4, "end": 6}],
            "edits": [
                {"start": 0, "end": 2, "replacement": "A"},   # 相邻替换
                {"start": 2, "end": 4, "replacement": "BC"},
                {"start": 4, "end": 4, "replacement": "I"},   # 替换终点处的插入
            ],
        }
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["revised_text"] == "ABCIef"
    assert data["invalidated_ids"] == []
    # 片段 [4,6)：替换 A 位移 -1、BC 位移 0，插入在片段起点位移 +1，
    # 累计位移 0，仍覆盖修订后文本 [4,6) 的 "ef"。
    assert data["masked_text"] == "ABCI██"


def test_revise_empty_text_with_insertion() -> None:
    resp = post({"text": "", "fragments": [], "edits": [{"start": 0, "end": 0, "replacement": "新"}]})
    assert resp.status_code == 200
    data = resp.json()
    assert data["revised_text"] == "新"
    assert data["masked_text"] == "新"


def test_revise_extra_fields_are_ignored() -> None:
    resp = post(
        {
            "text": "abc",
            "fragments": [],
            "edits": [{"start": 0, "end": 1, "replacement": "X", "note": "n"}],
            "request_id": "r-1",
        }
    )
    assert resp.status_code == 200
    assert resp.json()["revised_text"] == "Xbc"


def test_openapi_lists_revise_path() -> None:
    schema = client.get("/openapi.json").json()
    assert "/redact/revise" in schema["paths"]
    assert "/redact" in schema["paths"]


# ---------------------------------------------------------------------------
# 拒绝类输入：全部 400
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        # 缺字段 / 顶层类型错误
        {"text": "abc", "fragments": []},                       # 缺 edits
        {"fragments": [], "edits": []},                         # 缺 text
        {"text": "abc", "edits": []},                           # 缺 fragments
        {"text": "abc", "fragments": [], "edits": {}},          # edits 不是数组
        [1, 2, 3],                                              # 请求体不是对象
        # 编辑字段缺失 / 类型错误
        {"text": "abc", "fragments": [], "edits": [{"start": 0, "end": 1}]},
        {"text": "abc", "fragments": [], "edits": [1]},
        {"text": "abc", "fragments": [], "edits": [{"start": 0.5, "end": 1, "replacement": ""}]},
        {"text": "abc", "fragments": [], "edits": [{"start": True, "end": 1, "replacement": ""}]},
        {"text": "abc", "fragments": [], "edits": [{"start": 0, "end": "1", "replacement": ""}]},
        {"text": "abc", "fragments": [], "edits": [{"start": 0, "end": 1, "replacement": 5}]},
        {"text": "abc", "fragments": [], "edits": [{"start": 0, "end": 1, "replacement": None}]},
        # 越界 / 逆序
        {"text": "abc", "fragments": [], "edits": [{"start": -1, "end": 1, "replacement": ""}]},
        {"text": "abc", "fragments": [], "edits": [{"start": 0, "end": 4, "replacement": ""}]},
        {"text": "abc", "fragments": [], "edits": [{"start": 4, "end": 4, "replacement": "x"}]},
        {"text": "abc", "fragments": [], "edits": [{"start": 2, "end": 1, "replacement": ""}]},
        # 编辑彼此重叠
        {"text": "abcdef", "fragments": [], "edits": [
            {"start": 0, "end": 2, "replacement": ""},
            {"start": 1, "end": 3, "replacement": ""},
        ]},
        {"text": "abcdef", "fragments": [], "edits": [  # 完全相同的两个编辑
            {"start": 0, "end": 2, "replacement": "A"},
            {"start": 0, "end": 2, "replacement": "B"},
        ]},
        {"text": "abcdef", "fragments": [], "edits": [  # 插入点落在另一编辑区间内部
            {"start": 0, "end": 3, "replacement": "A"},
            {"start": 1, "end": 1, "replacement": "B"},
        ]},
        # 同一位置的多次插入
        {"text": "abcdef", "fragments": [], "edits": [
            {"start": 2, "end": 2, "replacement": "X"},
            {"start": 2, "end": 2, "replacement": "Y"},
        ]},
        {"text": "abcdef", "fragments": [], "edits": [  # 三次同位置插入（乱序给出）
            {"start": 2, "end": 2, "replacement": "X"},
            {"start": 0, "end": 1, "replacement": "Z"},
            {"start": 2, "end": 2, "replacement": "Y"},
        ]},
        # 片段校验依旧生效（按原文定位）
        {"text": "abc", "fragments": [{"id": 1, "weight": 1, "start": 0, "end": 4}], "edits": []},
        {"text": "abc", "fragments": [{"id": 1, "weight": 0, "start": 0, "end": 1}], "edits": []},
    ],
)
def test_revise_invalid_payloads_rejected_with_400(payload: object) -> None:
    resp = post(payload)
    assert resp.status_code == 400, payload
    assert "detail" in resp.json()


def test_revise_invalid_json_body_rejected_with_400() -> None:
    resp = client.post(
        "/redact/revise", content="{not json", headers={"Content-Type": "application/json"}
    )
    assert resp.status_code == 400


def test_revise_empty_body_rejected_with_400() -> None:
    resp = client.post("/redact/revise", content=b"", headers={"Content-Type": "application/json"})
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# 随机化正确性：apply_edits + migrate_fragment 与逐字符追踪的参考实现一致。
# ---------------------------------------------------------------------------


def test_migration_matches_character_tracking_reference_random() -> None:
    import random

    def char_shift(x: int, edits: list[Edit]) -> int:
        """原码点 x 在修订后文本中的位移：插入在 x 或其之前计入，
        非插入编辑在 x 之前结束计入。"""
        total = 0
        for edit in edits:
            if edit.is_insertion:
                if edit.start <= x:
                    total += edit.delta
            elif edit.end <= x:
                total += edit.delta
        return total

    rng = random.Random(20260926)
    for trial in range(400):
        n = rng.randrange(0, 10)
        text = "".join(rng.choice("abc😀！") for _ in range(n))

        # 从所有相邻码点缝里抽出互不重叠的编辑，保证同一位置最多一个插入。
        edits: list[Edit] = []
        cursor = 0
        while cursor <= n:
            if rng.random() < 0.35:
                if cursor == n or rng.random() < 0.5:  # 纯插入
                    edits.append(e(cursor, cursor, rng.choice(["x", "YZ", ""])))
                    cursor += 1
                else:  # 删除或替换
                    end = rng.randint(cursor + 1, min(n, cursor + 3))
                    edits.append(e(cursor, end, rng.choice(["", "q", "QR"])))
                    cursor = end + 1
            else:
                cursor += 1

        revised = apply_edits(text, edits)

        m = rng.randrange(0, 6)
        frags: list[Fragment] = []
        for fid in range(m):
            start = rng.randrange(n) if n > 0 else 0
            end = rng.randint(start + 1, n) if n > 0 else 0
            if start < end:
                frags.append(Fragment(id=fid, weight=1, start=start, end=end))

        for frag in frags:
            should_invalidate = any(
                (not edit.is_insertion and edit.start < frag.end and frag.start < edit.end)
                or (edit.is_insertion and frag.start < edit.start < frag.end)
                for edit in edits
            )
            migrated = migrate_fragment(frag, edits)
            if should_invalidate:
                assert migrated is None, f"trial {trial}: {frag} 应作废"
                continue
            assert migrated is not None, f"trial {trial}: {frag} 不应作废"
            # 参考实现：片段首字符位置为新区间起点；末字符位置 +1 为终点。
            new_start = frag.start + char_shift(frag.start, edits)
            new_end = frag.end - 1 + char_shift(frag.end - 1, edits) + 1
            assert (migrated.start, migrated.end) == (new_start, new_end), (
                f"trial {trial}: {frag} 迁移为 {migrated}，参考 {[new_start, new_end]}"
            )
            # 迁移后的区间在修订后文本中合法，且内容与原片段一致。
            assert revised[migrated.start : migrated.end] == text[frag.start : frag.end]
