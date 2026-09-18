"""FastAPI 接口测试。"""
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def post_analyze(rules):
    return client.post("/analyze", json={"rules": rules})


def test_root_and_health():
    assert client.get("/").status_code == 200
    assert client.get("/health").json() == {"status": "ok"}


def test_analyze_full_partial_shadowed():
    resp = post_analyze(
        [
            {"action": "allow", "cidr": "10.0.0.0/8"},
            {"action": "deny", "cidr": "10.1.0.0/16"},
            {"action": "ALLOW", "cidr": "192.168.0.0/16"},
            {"action": "deny", "cidr": "10.0.0.0/7"},
        ]
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["rule_count"] == 4
    assert [r["status"] for r in body["rules"]] == [
        "full",
        "shadowed",
        "full",
        "partial",
    ]
    # action 大小写不敏感并规范化
    assert body["rules"][2]["action"] == "allow"
    assert body["rules"][0]["status_label"] == "全生效"
    assert body["rules"][3]["effective_cidrs"] == ["11.0.0.0/8"]
    assert body["summary"] == {
        "full": 2,
        "partial": 1,
        "shadowed": 1,
        "effective_allow_addresses": (1 << 24) + (1 << 16),
        "effective_deny_addresses": 1 << 24,
    }


def test_bare_ip_accepted_as_32():
    resp = post_analyze([{"action": "allow", "cidr": "8.8.8.8"}])
    assert resp.status_code == 200
    rule = resp.json()["rules"][0]
    assert rule["cidr"] == "8.8.8.8/32"
    assert rule["total_addresses"] == 1
    assert rule["status"] == "full"


def test_empty_rules_422():
    assert client.post("/analyze", json={"rules": []}).status_code == 422
    assert client.post("/analyze", json={}).status_code == 422


def test_invalid_cidr_422():
    for bad in ["10.0.0.0/33", "10.0.0.1/8", "garbage", "9.9.9.9/99"]:
        resp = post_analyze([{"action": "allow", "cidr": bad}])
        assert resp.status_code == 422, bad
        assert resp.json()["detail"]


def test_ipv6_422():
    for bad in ["2001:db8::/32", "::1", "fe80::1/64"]:
        assert post_analyze([{"action": "allow", "cidr": bad}]).status_code == 422, bad


def test_bad_action_422():
    assert post_analyze(
        [{"action": "permit", "cidr": "10.0.0.0/8"}]
    ).status_code == 422


def test_missing_field_422():
    assert client.post("/analyze", json={"rules": [{"cidr": "10.0.0.0/8"}]}).status_code == 422
    assert client.post("/analyze", json={"rules": [{"action": "allow"}]}).status_code == 422


def test_non_list_body_422():
    assert client.post("/analyze", json={"rules": "nope"}).status_code == 422


def test_malformed_json_422():
    resp = client.post(
        "/analyze",
        content="{not json",
        headers={"content-type": "application/json"},
    )
    assert resp.status_code == 422


def test_openapi_docs_available():
    assert client.get("/openapi.json").status_code == 200
    assert client.get("/docs").status_code == 200


# ---------- /compare ----------

def post_compare(left, right):
    return client.post("/compare", json={"left": left, "right": right})


def test_compare_equivalent():
    resp = post_compare(
        {
            "rules": [
                {"action": "allow", "cidr": "10.0.0.0/8"},
                {"action": "deny", "cidr": "10.1.0.0/16"},  # 被上一条遮蔽
            ],
            "default_action": "deny",
        },
        {
            "rules": [{"action": "allow", "cidr": "10.0.0.0/8"}],
            "default_action": "deny",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["equivalent"] is True
    assert body["differing_addresses"] == 0
    assert body["differences"] == []


def test_compare_differences_grouped_by_actions():
    resp = post_compare(
        {
            "rules": [
                {"action": "allow", "cidr": "10.0.0.0/8"},
                {"action": "deny", "cidr": "11.0.0.0/8"},
            ],
            "default_action": "deny",
        },
        {
            "rules": [
                {"action": "deny", "cidr": "10.0.0.0/8"},
                {"action": "allow", "cidr": "11.0.0.0/8"},
            ],
            "default_action": "deny",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["equivalent"] is False
    assert body["differing_addresses"] == 2 * (1 << 24)
    assert body["differences"] == [
        {
            "left_action": "allow",
            "right_action": "deny",
            "address_count": 1 << 24,
            "cidrs": ["10.0.0.0/8"],
        },
        {
            "left_action": "deny",
            "right_action": "allow",
            "address_count": 1 << 24,
            "cidrs": ["11.0.0.0/8"],
        },
    ]


def test_compare_default_action_only_and_case_insensitive():
    resp = post_compare(
        {"rules": [], "default_action": "ALLOW"},
        {"rules": [], "default_action": "deny"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["differences"] == [
        {
            "left_action": "allow",
            "right_action": "deny",
            "address_count": 1 << 32,
            "cidrs": ["0.0.0.0/0"],
        }
    ]
    same = post_compare(
        {"rules": [], "default_action": "allow"},
        {"rules": [], "default_action": "Allow"},
    )
    assert same.json()["equivalent"] is True


def test_compare_validation_422():
    ok = {"rules": [], "default_action": "deny"}
    # 任一侧非法 CIDR / 主机位非零 / IPv6
    assert post_compare(
        {"rules": [{"action": "allow", "cidr": "10.0.0.1/8"}], "default_action": "deny"},
        ok,
    ).status_code == 422
    assert post_compare(
        ok,
        {"rules": [{"action": "allow", "cidr": "2001:db8::/32"}], "default_action": "deny"},
    ).status_code == 422
    # 非法 action / default_action
    assert post_compare(
        {"rules": [{"action": "permit", "cidr": "10.0.0.0/8"}], "default_action": "deny"},
        ok,
    ).status_code == 422
    assert post_compare({"rules": [], "default_action": "permit"}, ok).status_code == 422
    # 缺字段
    assert post_compare({"rules": []}, ok).status_code == 422
    assert post_compare({"default_action": "deny"}, ok).status_code == 422
    assert client.post("/compare", json={"left": ok}).status_code == 422
    assert client.post("/compare", json={}).status_code == 422
