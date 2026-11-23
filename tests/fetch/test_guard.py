"""sec-dns-rebind 的红灯测试。

共 15 个测试：前 10 个一一对应题面的 10 个缺陷，后 5 个是正向与回归断言。
测试只使用注入的 resolver，不进行任何真实 DNS、socket 或 HTTP 访问。
"""

from __future__ import annotations

import pytest

from engine.fetch.guard import (
    address_blocked,
    fetch_batch,
    host_allowed,
    parse_target,
    pinned_resolve,
    redirect_allowed,
    resolve_and_check,
    validate_policy,
)

PUBLIC = "8.8.8.8"
PUBLIC_ALT = "1.1.1.1"
PRIVATE = "10.0.0.7"
LOOPBACK = "127.0.0.1"
LINK_LOCAL = "169.254.169.254"


def _resolver(table):
    def resolve(host):
        if host not in table:
            raise AssertionError("unexpected resolver call for " + host)
        return list(table[host])

    return resolve


def _policy(**overrides):
    base = {
        "allow_hosts": ["example.com", "*.example.com"],
        "deny_networks": [],
        "check_resolved_addresses": True,
        "max_redirects": 0,
        "allowed_schemes": ["https"],
        "allowed_ports": [443],
    }
    base.update(overrides)
    return base


def _summary(outcome):
    return (
        tuple((item["url"], item["pinned"]) for item in outcome["ok"]),
        tuple((item["url"], item["reason"]) for item in outcome["rejected"]),
    )


# 缺陷 1：白名单使用后缀比较，evil-example.com 命中 example.com。
def test_host_allowed_rejects_suffix_lookalike():
    assert host_allowed("evil-example.com", ["example.com"]) is False


# 缺陷 2：通配条目错误地匹配裸域本身。
def test_wildcard_entry_does_not_match_bare_domain():
    assert host_allowed("example.com", ["*.example.com"]) is False


# 缺陷 3：只校验域名，不校验解析出的每一个地址。
def test_resolve_and_check_validates_every_resolved_address():
    def resolver(host):
        assert host == "example.com"
        return [PUBLIC, PRIVATE]

    with pytest.raises(ValueError):
        resolve_and_check("example.com", resolver, ["example.com"], [])


# 缺陷 4：私网判定只覆盖十点零段，漏掉回环与链路本地。
def test_loopback_and_link_local_are_blocked():
    assert address_blocked(LOOPBACK) is True
    assert address_blocked(LINK_LOCAL) is True
    assert address_blocked(PUBLIC) is False


# 缺陷 5：解析与连接各做一次，两次解析之间可被重绑定。
def test_pinned_resolve_uses_one_resolution_and_keeps_first_answer():
    calls = []

    def resolver(host):
        calls.append(host)
        return [PUBLIC] if len(calls) == 1 else [PRIVATE]

    result = pinned_resolve(
        "https://example.com/image", resolver, ["example.com"], []
    )
    assert result["addresses"] == (PUBLIC,)
    assert result["pinned"] == PUBLIC
    assert calls == ["example.com"]


# 缺陷 6：重定向不重新校验目标，只沿用旧目标的结论。
def test_redirect_allowed_rechecks_new_target_host():
    assert (
        redirect_allowed(
            "https://example.com/a",
            "https://internal.example.net/admin",
            ["example.com"],
        )
        is False
    )


# 缺陷 7：协议白名单缺失，文件协议也能进入抓取流程。
def test_fetch_batch_rejects_file_scheme():
    outcome = fetch_batch(["file:///etc/passwd"], _resolver({}), _policy())
    assert outcome["ok"] == []
    assert outcome["rejected"] == [
        {"url": "file:///etc/passwd", "reason": "scheme_not_allowed"}
    ]


# 缺陷 8：策略校验不检查是否允许无限重定向。
def test_validate_policy_flags_unbounded_redirects():
    issues = validate_policy(_policy(max_redirects=None))
    assert "unbounded_redirects" in issues


# 缺陷 9：批量校验复用解析缓存，后一个地址命中前一个结果。
def test_fetch_batch_does_not_reuse_resolution_cache():
    first = "https://a.example.com/one"
    second = "https://b.example.com/two"
    resolver = _resolver(
        {"a.example.com": [PUBLIC], "b.example.com": [PRIVATE]}
    )

    outcome = fetch_batch([first, second], resolver, _policy())

    assert [item["url"] for item in outcome["ok"]] == [first]
    assert outcome["rejected"] == [
        {"url": second, "reason": "blocked_address"}
    ]


# 缺陷 10：端口不校验，实际可以连接 443 之外的端口。
def test_pinned_resolve_rejects_non_443_port():
    target = "https://example.com:8443/image"
    parsed = parse_target(target)
    assert parsed["port"] == 8443

    with pytest.raises(ValueError):
        pinned_resolve(
            target, _resolver({"example.com": [PUBLIC]}), ["example.com"], []
        )


# 正向 1：白名单中的域名和合法子域可以通过。
def test_host_allowed_allows_exact_domain():
    allow = ["example.com", "*.images.example.com"]
    assert host_allowed("example.com", allow) is True
    assert host_allowed("cdn.images.example.com", allow) is True


# 正向 2：解析到私网地址的目标被拒绝。
def test_private_address_is_rejected():
    with pytest.raises(ValueError):
        resolve_and_check(
            "example.com",
            _resolver({"example.com": [PRIVATE]}),
            ["example.com"],
            [],
        )


# 正向 3：重定向到回环地址被拒绝，即使白名单显式写了该 IP。
def test_redirect_to_loopback_is_rejected():
    allow = ["example.com", LOOPBACK]
    assert (
        redirect_allowed(
            "https://example.com/a",
            "https://127.0.0.1/admin",
            allow,
        )
        is False
    )


# 正向 4：固定解析结果后，外部 resolver 数据变化不影响已返回地址。
def test_pinned_result_is_stable_after_resolver_data_changes():
    addresses = [PUBLIC]

    def resolver(host):
        return addresses

    result = pinned_resolve(
        "https://example.com/image", resolver, ["example.com"], []
    )
    addresses[0] = PRIVATE

    assert result["addresses"] == (PUBLIC,)
    assert result["pinned"] == PUBLIC


# 正向 5：批量校验与逐个单独校验一致，且两批之间彼此独立。
def test_batch_validation_matches_individual_validation():
    urls = [
        "https://a.example.com/1",
        "https://b.example.com/2",
        "https://c.example.com/3",
    ]
    resolver = _resolver(
        {
            "a.example.com": [PUBLIC],
            "b.example.com": [PRIVATE],
            "c.example.com": [PUBLIC_ALT],
        }
    )
    policy = _policy()

    batch_one = fetch_batch(urls, resolver, policy)
    batch_two = fetch_batch(urls, resolver, policy)

    individual_ok = []
    individual_rejected = []
    for url in urls:
        one = fetch_batch([url], resolver, policy)
        individual_ok.extend(
            (item["url"], item["pinned"]) for item in one["ok"]
        )
        individual_rejected.extend(
            (item["url"], item["reason"]) for item in one["rejected"]
        )

    assert batch_one == batch_two
    assert _summary(batch_one) == (
        tuple(individual_ok),
        tuple(individual_rejected),
    )
