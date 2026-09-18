"""IPv4 CIDR 遮蔽分析核心逻辑（纯标准库实现，无 Web 依赖）。

规则按输入顺序逐条处理；对第 i 条规则，此前 i-1 条规则
（allow 与 deny 合并后的并集）已经覆盖的地址构成“遮蔽集合”。
规则自身地址区间减去遮蔽集合后，剩余部分无损压缩为数量最少的
IPv4 CIDR 列表，并按覆盖比例分类：

- full      全生效：规则地址均未被此前规则覆盖
- partial   部分遮蔽：部分地址此前已被覆盖
- shadowed  完全遮蔽：全部地址此前已被覆盖
"""
from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network, ip_network
from typing import Iterable, Sequence

#: 整个 IPv4 地址空间的地址数量（2^32）
V4_SPACE = 1 << 32

FULL = "full"
PARTIAL = "partial"
SHADOWED = "shadowed"

STATUS_LABELS = {
    FULL: "全生效",
    PARTIAL: "部分遮蔽",
    SHADOWED: "完全遮蔽",
}


class InvalidCIDRError(ValueError):
    """非法 CIDR（格式错误、主机位非零、IPv6 等）。"""


def parse_cidr_v4(text: str) -> tuple[int, int, str]:
    """严格解析单个 IPv4 CIDR。

    返回 ``(起始地址整数, 结束地址整数, 规范化 CIDR 字符串)``。
    纯 IP（无前缀）按 /32 处理；IPv6 与任何非法输入抛出
    :class:`InvalidCIDRError`。
    """
    if not isinstance(text, str):
        raise InvalidCIDRError("CIDR 必须是字符串")
    raw = text.strip()
    if not raw:
        raise InvalidCIDRError("CIDR 不能为空")
    try:
        net = ip_network(raw, strict=True)
    except ValueError as exc:
        raise InvalidCIDRError(f"非法 CIDR: {text!r}（{exc}）") from exc
    if not isinstance(net, IPv4Network):
        raise InvalidCIDRError(f"仅支持 IPv4，不支持 IPv6: {text!r}")
    start = int(net.network_address)
    end = start + net.num_addresses - 1
    return start, end, str(net)


def merge_intervals(intervals: Iterable[Sequence[int]]) -> list[tuple[int, int]]:
    """合并若干 ``[start, end]`` 闭区间为有序、互不相交的最小区间集。

    首尾相接（相邻）的区间也会被合并，以便后续跨碎片做整体压缩。
    """
    ordered = sorted((int(s), int(e)) for s, e in intervals)
    merged: list[tuple[int, int]] = []
    for start, end in ordered:
        if start > end:
            raise ValueError("区间起点不能大于终点")
        if not merged or start > merged[-1][1] + 1:
            merged.append((start, end))
        elif end > merged[-1][1]:
            merged[-1] = (merged[-1][0], end)
    return merged


def subtract_covered(
    rule: tuple[int, int], covered: Sequence[tuple[int, int]]
) -> list[tuple[int, int]]:
    """计算 ``rule`` 闭区间减去已覆盖区间集 ``covered`` 后的剩余碎片。

    ``covered`` 须为有序、互不相交的区间（由 :func:`merge_intervals` 产出）。
    """
    start, end = rule
    remaining: list[tuple[int, int]] = []
    cur = start
    for cov_start, cov_end in covered:
        if cov_end < cur:
            continue  # 覆盖区间完全在当前游标之前
        if cov_start > end:
            break  # 覆盖区间已越过规则末端
        if cov_start > cur:
            remaining.append((cur, cov_start - 1))
        cur = max(cur, cov_end + 1)
        if cur > end:
            break
    if cur <= end:
        remaining.append((cur, end))
    return remaining


def range_to_cidrs(start: int, end: int) -> list[str]:
    """把单个连续 IPv4 地址区间无损压缩为数量最少的 CIDR 列表。

    贪心：每一步取以当前地址为起点、不越过区间末端的最大 2 的幂
    对齐块。该算法是 range-to-CIDR 的标准最优算法（块数最少）。
    """
    cidrs: list[str] = []
    cur = start
    while cur <= end:
        remaining = end - cur + 1
        # 当前地址的最低置位决定最大对齐块；地址 0 可对齐整个 /0。
        alignment_block = V4_SPACE if cur == 0 else (cur & -cur)
        size = min(alignment_block, 1 << (remaining.bit_length() - 1))
        prefixlen = 32 - (size.bit_length() - 1)
        cidrs.append(f"{IPv4Address(cur)}/{prefixlen}")
        cur += size
    return cidrs


def compress_intervals(intervals: Sequence[tuple[int, int]]) -> list[str]:
    """把碎片区间先合并，再压缩为全局数量最少的 CIDR 列表。"""
    cidrs: list[str] = []
    for start, end in merge_intervals(intervals):
        cidrs.extend(range_to_cidrs(start, end))
    return cidrs


def analyze_rules(
    rules: Sequence[tuple[str, str]],
) -> dict:
    """分析有序 (action, cidr) 规则列表的遮蔽情况。

    返回可直接 JSON 序列化的结果字典；``rules`` 为空时抛出
    :class:`ValueError`（Web 层通常已以 422 拦截）。
    """
    if not rules:
        raise ValueError("规则集不能为空")

    covered: list[tuple[int, int]] = []
    result_rules: list[dict] = []
    effective_totals = {"allow": 0, "deny": 0}
    status_counts = {FULL: 0, PARTIAL: 0, SHADOWED: 0}

    for index, (action, raw_cidr) in enumerate(rules):
        action = action.strip().lower()
        if action not in ("allow", "deny"):
            raise ValueError(f"非法 action: {action!r}")

        start, end, cidr = parse_cidr_v4(raw_cidr)
        total_addresses = end - start + 1

        remaining = subtract_covered((start, end), covered)
        effective_addresses = sum(b - a + 1 for a, b in remaining)
        covered_addresses = total_addresses - effective_addresses

        if effective_addresses == 0:
            status = SHADOWED
        elif effective_addresses == total_addresses:
            status = FULL
        else:
            status = PARTIAL

        effective_cidrs = compress_intervals(remaining)

        effective_totals[action] += effective_addresses
        status_counts[status] += 1

        result_rules.append(
            {
                "index": index,
                "action": action,
                "cidr": cidr,
                "status": status,
                "status_label": STATUS_LABELS[status],
                "total_addresses": total_addresses,
                "covered_addresses": covered_addresses,
                "effective_addresses": effective_addresses,
                "effective_cidrs": effective_cidrs,
            }
        )

        # 本规则（无论 allow/deny）的地址全部并入“已覆盖”集合
        covered = merge_intervals([*covered, (start, end)])

    return {
        "rule_count": len(rules),
        "rules": result_rules,
        "summary": {
            "full": status_counts[FULL],
            "partial": status_counts[PARTIAL],
            "shadowed": status_counts[SHADOWED],
            "effective_allow_addresses": effective_totals["allow"],
            "effective_deny_addresses": effective_totals["deny"],
        },
    }
