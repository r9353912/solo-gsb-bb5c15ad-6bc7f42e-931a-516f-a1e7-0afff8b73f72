"""核心算法单元测试。"""

from __future__ import annotations

from itertools import combinations

from app.redaction import Fragment, MASK_CHAR, mask_text, select_fragments


def f(fid: int, weight: int, start: int, end: int) -> Fragment:
    return Fragment(id=fid, weight=weight, start=start, end=end)


def test_empty_input_selects_nothing() -> None:
    assert select_fragments([]) == ()


def test_non_overlapping_all_selected_including_adjacent() -> None:
    frags = [f(2, 1, 3, 5), f(1, 2, 0, 3)]
    assert select_fragments(frags) == (1, 2)


def test_overlapping_prefers_higher_weight() -> None:
    # [0,5) 权重 5 vs [0,3)+[3,5) 权重 3+1=4
    frags = [f(1, 5, 0, 5), f(2, 3, 0, 3), f(3, 1, 3, 5)]
    assert select_fragments(frags) == (1,)


def test_weight_tie_prefers_more_chars() -> None:
    # 两组权重同为 5：单片段覆盖 5 码点，组合只覆盖 3 码点。
    frags = [f(1, 5, 0, 5), f(2, 3, 0, 2), f(3, 2, 2, 3)]
    assert select_fragments(frags) == (1,)


def test_full_tie_prefers_smallest_id_list_lexicographically() -> None:
    # {1} 与 {2} 权重、长度完全相同，取 ID 较小者。
    frags = [f(2, 1, 0, 1), f(1, 1, 0, 1)]
    assert select_fragments(frags) == (1,)

    # 比较完整升序列表：[2] < [2, 1] 不可能；此处 [1, 3] < [2]。
    frags = [f(1, 1, 0, 1), f(3, 1, 0, 1), f(2, 2, 1, 2)]
    assert select_fragments(frags) == (1, 2)


def test_string_ids_lexicographic() -> None:
    frags = [
        Fragment(id="b", weight=1, start=0, end=1),
        Fragment(id="a", weight=1, start=0, end=1),
    ]
    assert select_fragments(frags) == ("a",)


def test_mask_text_simple_and_adjacent() -> None:
    text = "你好，世界！"  # 6 个码点
    frags = [f(1, 1, 0, 2), f(2, 1, 3, 5)]
    masked = mask_text(text, frags)
    assert masked == MASK_CHAR * 2 + "，" + MASK_CHAR * 2 + "！"
    assert len(masked) == len(text)


def test_mask_text_handles_astral_code_points() -> None:
    text = "a😀b"  # 4 个码点：a, 😀(代理对), b -> 索引 0,1,2,3
    masked = mask_text(text, [f(1, 1, 1, 2)])
    assert masked == "a" + MASK_CHAR + "b"


# ---------------------------------------------------------------------------
# 随机化正确性：动态规划结果必须与 2^n 暴力枚举一致。
# ---------------------------------------------------------------------------


def _brute_force(frags: list[Fragment]) -> tuple[int, ...]:
    def compatible(subset: tuple[Fragment, ...]) -> bool:
        ordered = sorted(subset, key=lambda x: x.start)
        return all(a.end <= b.start for a, b in zip(ordered, ordered[1:]))

    best: tuple[int, int, tuple[int, ...]] | None = None
    for size in range(len(frags) + 1):
        for subset in combinations(frags, size):
            if not compatible(subset):
                continue
            key = (
                sum(x.weight for x in subset),
                sum(x.length for x in subset),
                tuple(sorted(x.id for x in subset)),
            )
            candidate = (key[0], key[1], key[2])
            if (
                best is None
                or candidate[:2] > best[:2]
                or (candidate[:2] == best[:2] and candidate[2] < best[2])
            ):
                best = candidate
    assert best is not None
    return best[2]


def test_dp_matches_brute_force_random() -> None:
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
        expected = _brute_force(frags)
        assert select_fragments(frags) == expected, f"trial {trial}: {frags}"
