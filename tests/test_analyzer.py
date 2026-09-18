"""核心分析逻辑的单元测试。"""
import random

import pytest
from ipaddress import IPv4Network, collapse_addresses, ip_network

from app.analyzer import (
    InvalidCIDRError,
    analyze_rules,
    compress_intervals,
    merge_intervals,
    parse_cidr_v4,
    range_to_cidrs,
    subtract_covered,
)


# ---------- 解析 ----------

def test_parse_basic_cidr():
    start, end, text = parse_cidr_v4("10.0.0.0/8")
    assert start == 10 << 24
    assert end == (10 << 24) + (1 << 24) - 1
    assert text == "10.0.0.0/8"


def test_parse_bare_ip_is_32():
    start, end, text = parse_cidr_v4("192.168.1.1")
    assert start == end
    assert text == "192.168.1.1/32"


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "   ",
        "10.0.0.0/33",
        "10.0.0.0/-1",
        "10.0.0",
        "999.0.0.0/8",
        "10.0.0.1/8",  # 主机位非零（strict）
        "not-a-cidr",
        "10.0.0.0/8/8",
        "2001:db8::/32",  # IPv6
        "::1/128",
        "fe80::1",
    ],
)
def test_parse_rejects_invalid_and_ipv6(bad):
    with pytest.raises(InvalidCIDRError):
        parse_cidr_v4(bad)


# ---------- 区间与压缩 ----------

def test_subtract_disjoint_and_overlap():
    covered = [(10, 20), (40, 50)]
    assert subtract_covered((0, 100), covered) == [(0, 9), (21, 39), (51, 100)]
    assert subtract_covered((10, 20), covered) == []
    assert subtract_covered((15, 45), covered) == [(21, 39)]
    assert subtract_covered((0, 5), covered) == [(0, 5)]


def test_merge_includes_adjacent():
    assert merge_intervals([(5, 9), (1, 3), (10, 12), (1, 2)]) == [(1, 3), (5, 12)]
    assert merge_intervals([]) == []


def test_range_to_cidrs_single_block():
    start, end, _ = parse_cidr_v4("10.0.0.0/16")
    assert range_to_cidrs(start, end) == ["10.0.0.0/16"]


def test_range_to_cidrs_full_space_is_slash0():
    assert range_to_cidrs(0, (1 << 32) - 1) == ["0.0.0.0/0"]


def test_compress_split_hole_is_minimal():
    # /8 挖掉开头的 /16，贪心结果必须与手工最优分块一致
    start, end, _ = parse_cidr_v4("10.0.0.0/8")
    pieces = subtract_covered((start, end), [parse_cidr_v4("10.0.0.0/16")[:2]])
    cidrs = compress_intervals(pieces)
    assert cidrs == [
        "10.1.0.0/16",
        "10.2.0.0/15",
        "10.4.0.0/14",
        "10.8.0.0/13",
        "10.16.0.0/12",
        "10.32.0.0/11",
        "10.64.0.0/10",
        "10.128.0.0/9",
    ]
    # 无损：数量守恒
    assert sum(IPv4Network(c).num_addresses for c in cidrs) == (1 << 24) - (1 << 16)


# ---------- 规则分析 ----------

def test_full_partial_shadowed_and_totals():
    result = analyze_rules(
        [
            ("allow", "10.0.0.0/8"),  # full, 2^24
            ("deny", "10.1.0.0/16"),  # shadowed
            ("allow", "192.168.0.0/16"),  # full, 2^16
            ("deny", "10.0.0.0/7"),  # partial: 只 11.0.0.0/8 生效
        ]
    )
    statuses = [r["status"] for r in result["rules"]]
    assert statuses == ["full", "shadowed", "full", "partial"]

    last = result["rules"][3]
    assert last["effective_addresses"] == 1 << 24
    assert last["covered_addresses"] == 1 << 24
    assert last["effective_cidrs"] == ["11.0.0.0/8"]

    summary = result["summary"]
    assert summary["full"] == 2
    assert summary["partial"] == 1
    assert summary["shadowed"] == 1
    assert summary["effective_allow_addresses"] == (1 << 24) + (1 << 16)
    assert summary["effective_deny_addresses"] == 1 << 24


def test_cross_action_shadowing():
    # 先前的 allow 同样遮蔽后面的 deny
    result = analyze_rules([("allow", "0.0.0.0/0"), ("deny", "8.8.8.8/32")])
    assert result["rules"][1]["status"] == "shadowed"
    assert result["rules"][1]["effective_cidrs"] == []
    assert result["summary"]["effective_deny_addresses"] == 0
    assert result["summary"]["effective_allow_addresses"] == 1 << 32


def test_order_matters_and_duplicates_shadow():
    first = analyze_rules([("allow", "10.1.0.0/16"), ("deny", "10.0.0.0/8")])
    second = analyze_rules([("deny", "10.0.0.0/8"), ("allow", "10.1.0.0/16")])
    assert first["rules"][1]["status"] == "partial"
    assert second["rules"][1]["status"] == "shadowed"

    dup = analyze_rules([("allow", "1.2.3.0/24"), ("allow", "1.2.3.0/24")])
    assert dup["rules"][1]["status"] == "shadowed"
    # 重复地址不重复计入
    assert dup["summary"]["effective_allow_addresses"] == 256


def test_empty_rules_rejected():
    with pytest.raises(ValueError):
        analyze_rules([])


def test_adjacent_fragments_merge_before_compress():
    # /30 中先遮蔽末端两个地址，剩余 .0/.1 相邻且 /31 对齐 -> 必须合并为单个 /31
    # （若不在压缩前合并相邻碎片，会退化为两个 /32）
    result = analyze_rules(
        [
            ("deny", "10.0.0.2/31"),
            ("allow", "10.0.0.0/30"),
        ]
    )
    last = result["rules"][1]
    assert last["effective_cidrs"] == ["10.0.0.0/31"]
    assert last["status"] == "partial"

    # 相邻但不对齐的两个地址（.1/.2）无法合并，最优仍是两个 /32
    result2 = analyze_rules(
        [
            ("deny", "10.0.0.0/32"),
            ("deny", "10.0.0.3/32"),
            ("allow", "10.0.0.0/30"),
        ]
    )
    assert result2["rules"][2]["effective_cidrs"] == [
        "10.0.0.1/32",
        "10.0.0.2/32",
    ]


# ---------- 属性测试：与 ipaddress 标准库 oracle 对比 ----------

def test_random_rules_oracle():
    rng = random.Random(20260918)
    universe = list(ip_network("10.0.0.0/16").subnets(new_prefix=24))  # 256 个 /24
    for _ in range(30):
        picked = rng.sample(universe, k=rng.randint(1, 12))
        actions = [rng.choice(["allow", "deny"]) for _ in picked]

        result = analyze_rules([(a, str(net)) for a, net in zip(actions, picked)])

        claimed: set = set()
        seen_effective: set = set()
        for net, res in zip(picked, result["rules"]):
            remaining = set(net) - claimed
            # 标准库给出的最少 CIDR 分块
            expected = [str(c) for c in collapse_addresses(remaining)]
            assert res["effective_cidrs"] == expected

            rebuilt = set()
            for c in res["effective_cidrs"]:
                rebuilt |= set(ip_network(c))
            assert rebuilt == remaining  # 无损
            assert not rebuilt & seen_effective  # 生效集合两两不相交
            seen_effective |= rebuilt
            claimed |= set(net)

        summary = result["summary"]
        assert summary["effective_allow_addresses"] == sum(
            r["effective_addresses"] for r in result["rules"] if r["action"] == "allow"
        )
        assert summary["effective_deny_addresses"] == sum(
            r["effective_addresses"] for r in result["rules"] if r["action"] == "deny"
        )
        assert (
            sum(r["effective_addresses"] for r in result["rules"])
            == len(seen_effective)
        )
