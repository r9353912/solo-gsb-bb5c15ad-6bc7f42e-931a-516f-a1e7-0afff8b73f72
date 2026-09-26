"""敏感片段选择与遮盖的核心算法。

本模块与 HTTP 框架解耦，便于单元测试。

约定：
- 文本位置按 Unicode 码点（Python ``str`` 的索引）计数，区间为左闭右开
  ``[start, end)``；``[0, 3)`` 与 ``[3, 5)`` 互不重叠，可同时入选。
- 片段 ID 允许为整数或字符串，一次请求内类型须一致。
- 编辑（``Edit``）把原文 ``[start, end)`` 替换为 ``replacement``；
  ``start == end`` 时为纯插入，``replacement == ""`` 时为纯删除。
  一批编辑须互不重叠，应用时按起点排序后一次性生效。
"""

from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass
from typing import Sequence

# 遮盖字符：U+2588 FULL BLOCK，一个码点对应一个被遮盖码点。
MASK_CHAR = "█"

ID = int | str


@dataclass(frozen=True)
class Fragment:
    """一条候选敏感片段。"""

    id: ID
    weight: int
    start: int
    end: int

    @property
    def length(self) -> int:
        return self.end - self.start


@dataclass(frozen=True)
class Edit:
    """一处对原文的编辑：把 ``[start, end)`` 替换为 ``replacement``。"""

    start: int
    end: int
    replacement: str

    @property
    def is_insertion(self) -> bool:
        """纯插入（空区间）。"""
        return self.start == self.end

    @property
    def delta(self) -> int:
        """该编辑引起的码点位移（新长度 - 旧长度）。"""
        return len(self.replacement) - (self.end - self.start)


def apply_edits(text: str, edits: Sequence[Edit]) -> str:
    """把互不重叠的编辑一次性应用到原文，返回修订后文本。

    所有区间均按原文定位；编辑之间互不影响（同一位置的插入先于
    同起点的替换生效）。调用方须保证编辑已经过校验、互不重叠。
    """
    parts: list[str] = []
    cursor = 0
    for edit in sorted(edits, key=lambda e: (e.start, e.end)):
        parts.append(text[cursor : edit.start])
        parts.append(edit.replacement)
        cursor = edit.end
    parts.append(text[cursor:])
    return "".join(parts)


def migrate_fragment(fragment: Fragment, edits: Sequence[Edit]) -> Fragment | None:
    """把片段区间迁移到修订后文本；被编辑波及时返回 ``None``（作废）。

    作废规则：
    - 删除/替换区间与片段有交集；
    - 插入点严格落在片段内部（``start < p < end``）。

    迁移规则（片段长度不变，整体平移）：
    - 插入在片段起点：整段右移，插入内容不并入片段；
    - 插入在片段终点：不扩展片段，区间不变；
    - 其余情况按前方编辑的累计码点位移平移区间。
    """
    shift = 0
    for edit in edits:
        if edit.is_insertion:
            if fragment.start < edit.start < fragment.end:
                return None
            if edit.start <= fragment.start:
                shift += edit.delta
        else:
            if edit.start < fragment.end and fragment.start < edit.end:
                return None
            if edit.end <= fragment.start:
                shift += edit.delta
    return Fragment(
        id=fragment.id,
        weight=fragment.weight,
        start=fragment.start + shift,
        end=fragment.end + shift,
    )


def _insert_sorted(ids: tuple[ID, ...], value: ID) -> tuple[ID, ...]:
    """把 ``value`` 有序插入已升序排列的 ``ids``。"""
    lo, hi = 0, len(ids)
    while lo < hi:
        mid = (lo + hi) // 2
        if ids[mid] < value:
            lo = mid + 1
        else:
            hi = mid
    return ids[:lo] + (value,) + ids[lo:]


def select_fragments(fragments: Sequence[Fragment]) -> tuple[ID, ...]:
    """从候选片段中选出互不重叠的最优组合。

    目标依次为：
    1. 权重总和最大；
    2. 权重总和并列时，遮盖字符数最多；
    3. 仍并列时，取入选 ID 升序列表字典序最小者。

    使用带权区间调度动态规划，按右端点排序，``p[i]`` 指向与第 ``i`` 个
    片段相容（``end <= start``）的最后一个片段。

    返回入选 ID 的升序元组。
    """
    if not fragments:
        return ()

    # 唯一确定的排序，便于结果可复现；最优解由比较目标决定，与顺序无关。
    ordered = sorted(fragments, key=lambda f: (f.end, f.start, f.id))
    ends = [f.end for f in ordered]

    # dp[i]：仅考虑前 i 个片段（ordered[0:i]）时的最优状态
    #   (权重总和, 遮盖字符数, 入选 ID 升序元组)
    dp: list[tuple[int, int, tuple[ID, ...]]] = [(0, 0, ())]

    for i, frag in enumerate(ordered, start=1):
        p = bisect_right(ends, frag.start, 0, i - 1)
        base_weight, base_len, base_ids = dp[p]
        take = (
            base_weight + frag.weight,
            base_len + frag.length,
            _insert_sorted(base_ids, frag.id),
        )
        skip = dp[i - 1]
        # 元组按 (权重, 字符数, ID 列表字典序) 比较；前两项求最大，
        # 第三项取字典序最小。
        if take[:2] > skip[:2] or (take[:2] == skip[:2] and take[2] < skip[2]):
            dp.append(take)
        else:
            dp.append(skip)

    return dp[-1][2]


def select_fragments_with_budget(
    fragments: Sequence[Fragment], max_masked_chars: int
) -> tuple[ID, ...]:
    """从候选片段中选出遮盖码点总数不超过预算的最优互不重叠组合。

    目标依次为：
    1. 权重总和最大；
    2. 权重总和并列时，遮盖码点总数最多；
    3. 仍并列时，取入选 ID 升序列表字典序最小者。

    与 :func:`select_fragments` 相比多一个预算约束：入选区间长度之和
    （即遮盖码点数）不得超过 ``max_masked_chars``。相邻区间仍可同时入选。

    使用按右端点排序的二维动态规划：``dp[i][b]`` 表示仅考虑前 ``i`` 个
    片段、遮盖码点总数不超过 ``b`` 时的最优状态。时间复杂度
    O(n * min(max_masked_chars, 全部区间长度之和))。

    返回入选 ID 的升序元组。
    """
    if not fragments or max_masked_chars <= 0:
        return ()

    ordered = sorted(fragments, key=lambda f: (f.end, f.start, f.id))

    # 预算不小于所有区间长度之和时与无预算约束等价，直接复用一维 DP。
    if max_masked_chars >= sum(frag.length for frag in ordered):
        return select_fragments(ordered)

    ends = [frag.end for frag in ordered]

    def better(
        take: tuple[int, int, tuple[ID, ...]],
        skip: tuple[int, int, tuple[ID, ...]],
    ) -> bool:
        # 前两项（权重、遮盖码点数）求最大，第三项 ID 升序列表取字典序最小。
        return take[:2] > skip[:2] or (take[:2] == skip[:2] and take[2] < skip[2])

    zero: tuple[int, int, tuple[ID, ...]] = (0, 0, ())
    # rows[i][b]：仅考虑前 i 个片段、遮盖码点总数不超过 b 时的最优状态
    #   (权重总和, 遮盖码点数, 入选 ID 升序元组)
    rows: list[list[tuple[int, int, tuple[ID, ...]]]] = [
        [zero] * (max_masked_chars + 1)
    ]

    for i, frag in enumerate(ordered, start=1):
        # p：与第 i 个片段相容（end <= start）的最后一个片段下标。
        p = bisect_right(ends, frag.start, 0, i - 1)
        compatible_row = rows[p]
        current: list[tuple[int, int, tuple[ID, ...]]] = []
        for budget in range(max_masked_chars + 1):
            skip = rows[i - 1][budget]
            if budget < frag.length:
                current.append(skip)
                continue
            base_weight, base_len, base_ids = compatible_row[budget - frag.length]
            take = (
                base_weight + frag.weight,
                base_len + frag.length,
                _insert_sorted(base_ids, frag.id),
            )
            current.append(take if better(take, skip) else skip)
        rows.append(current)

    return rows[-1][max_masked_chars][2]



def mask_text(text: str, fragments: Sequence[Fragment]) -> str:
    """用等长的 ``█`` 遮盖入选片段覆盖到的码点。

    ``fragments`` 须已保证互不重叠（相邻可以）。重叠区域只遮盖一次。
    """
    covered = bytearray(len(text))
    for frag in fragments:
        covered[frag.start : frag.end] = b"\x01" * frag.length
    chars = list(text)
    for i, flag in enumerate(covered):
        if flag:
            chars[i] = MASK_CHAR
    return "".join(chars)
