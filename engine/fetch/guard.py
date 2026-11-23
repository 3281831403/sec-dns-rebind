"""图片抓取服务的出站目标校验契约。

本模块是唯一实现文件，以下 8 个公开函数全部是尚未实现的桩。实现时不得进行
真实 DNS、socket、HTTP 或文件访问；所有解析结果必须由调用方注入的 resolver
提供。安全默认值为仅 https、仅 443、逐个地址校验、重定向逐跳复检、容差为 0。
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Mapping, Sequence
from typing import Any
from urllib.parse import urlsplit

Resolver = Callable[[str], Sequence[str]]

__all__ = [
    "parse_target",
    "host_allowed",
    "address_blocked",
    "resolve_and_check",
    "pinned_resolve",
    "redirect_allowed",
    "validate_policy",
    "fetch_batch",
]

_DOMAIN_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


def _normalize_host(host: Any) -> str | None:
    """转小写并去掉一个末尾根点；无法规范化时返回 None。"""
    if not isinstance(host, str):
        return None
    host = host.lower()
    if host.endswith("."):
        host = host[:-1]
    if not host:
        return None
    return host


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _is_valid_domain(host: str) -> bool:
    """域名字面校验：点分隔标签，每标签仅 ASCII 字母数字与连字符。"""
    if not host or host.startswith(".") or host.endswith(".") or ".." in host:
        return False
    if any(ch.isspace() for ch in host):
        return False
    labels = host.split(".")
    if len(host) > 253 or not labels:
        return False
    return all(_DOMAIN_LABEL.fullmatch(label) for label in labels)


def parse_target(url: str) -> dict[str, Any]:
    """解析绝对 URL，返回规范化目标，不做任何解析或网络访问。

    契约：
    - 返回且仅返回 url、scheme、host、port、path 五个键。
    - scheme 转小写；host 转小写并去掉一个末尾根点；不得把 userinfo 当作 host。
    - port 使用显式端口，否则使用协议默认端口：https 为 443，http 为 80，
      其他协议为 None。
    - path 至少为斜杠；file 这类无 authority 的 URL 允许空 host。
    - 缺少协议、格式错误、端口非整数或越界、需要 host 却没有 host 时，
      抛出 ValueError，原因码为 invalid_target。

    该函数只解析语法，不判断协议是否允许、端口是否为 443，也不查询 DNS。
    """
    if not isinstance(url, str) or not url:
        raise ValueError("invalid_target")

    try:
        parts = urlsplit(url)
        explicit_port = parts.port
    except ValueError:
        raise ValueError("invalid_target") from None

    scheme = parts.scheme.lower()
    if not scheme:
        raise ValueError("invalid_target")

    if explicit_port is not None and explicit_port not in range(1, 65536):
        raise ValueError("invalid_target")

    # file 等无 authority 的 URL 允许空 host；带 // 的分层 URL 必须有 host。
    raw_host = parts.hostname
    if raw_host is None:
        if parts.netloc or scheme not in ("file",):
            raise ValueError("invalid_target")
        host = ""
    else:
        host = _normalize_host(raw_host)
        if host is None:
            raise ValueError("invalid_target")

    if explicit_port is not None:
        port: int | None = explicit_port
    elif scheme == "https":
        port = 443
    elif scheme == "http":
        port = 80
    else:
        port = None

    path = parts.path or "/"

    return {
        "url": url,
        "scheme": scheme,
        "host": host,
        "port": port,
        "path": path,
    }


def host_allowed(host: str, allow: Sequence[str]) -> bool:
    """判断 host 是否精确命中域名白名单，返回布尔值。

    匹配规则：
    - 双方先转小写并去掉一个末尾根点。
    - 普通条目只做完整相等比较，绝不使用后缀或子串比较；
      evil-example.com 不得命中 example.com。
    - 以星号加点开头的条目是末段通配，只匹配后缀之前至少还有一个标签的
      主机：星号加点 example.com 匹配 img.example.com 和 a.b.example.com，
      不匹配裸域 example.com，不匹配 badexample.com。
    - IP 字面量不得命中通配条目；只有显式列出的精确 IP 可以命中，
      调用方仍须执行地址校验。
    - 空值、畸形主机或畸形条目一律返回 False，不抛异常。
    """
    target = _normalize_host(host)
    if target is None:
        return False
    target_is_ip = _is_ip_literal(target)

    for entry in allow:
        normalized_entry = _normalize_host(entry)
        if normalized_entry is None:
            continue

        if normalized_entry.startswith("*."):
            # 缺陷 2 修复：通配条目不匹配裸域；IP 字面量不得命中通配。
            if target_is_ip:
                continue
            suffix = normalized_entry[2:]
            if not suffix or not _is_valid_domain(suffix):
                continue
            if not _is_valid_domain(target):
                return False
            if not target.endswith("." + suffix):
                continue
            # 后缀之前必须至少还有一个非空标签（裸域此时 prefix 为空，被拒）。
            prefix = target[: -(len(suffix) + 1)]
            if prefix:
                return True
            continue

        # 缺陷 1 修复：普通条目只做完整相等比较，不做后缀/子串比较。
        if normalized_entry == target:
            return True

    return False


def address_blocked(ip: str) -> bool:
    """判断 IP 是否属于禁止连接的非公网地址。

    私网、回环、链路本地、未指定、组播、保留以及 IPv6 唯一本地地址都必须
    返回 True；不能只覆盖 10.0.0.0/8。实现应失败关闭：解析不了的输入抛出
    ValueError，任何非全局单播地址都视为阻断。容差为 0，不允许把私网地址
    通过映射、缩写或网段近似放行。
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        raise ValueError("invalid_address") from None

    # 缺陷 4 修复：覆盖全部非公网类别，而非仅 10.0.0.0/8。
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_unspecified
        or addr.is_multicast
        or addr.is_reserved
    )


def resolve_and_check(
    host: str,
    resolver: Resolver,
    allow: Sequence[str],
    deny: Sequence[str],
) -> dict[str, Any]:
    """解析 host 一次，并对返回的每个地址做全量校验。

    校验是全有或全无，容差为 0：
    - 调用 resolver 之前，host 必须通过 host_allowed；
    - 每次调用该函数时 resolver 只执行一次，结果不得跨调用缓存；
    - 返回的每个地址都必须是合法 IP，且 address_blocked 为 False；
    - 每个地址都必须不在 deny 的任一网段内，网段包含关系精确判断；
    - 重复地址按首次出现顺序去重；
    - 结果为空或任一地址不合格，整个目标即被拒绝。

    抛出 ValueError，原因码为 host_not_allowed、empty_resolution、
    invalid_address、blocked_address 或 denied_address。
    返回 host 与 addresses 两个键，addresses 为字符串元组。
    """
    if not host_allowed(host, allow):
        raise ValueError("host_not_allowed")

    # 缺陷 5 修复的一部分：每次调用只解析一次，且绝不缓存、绝不复用。
    raw_addresses = resolver(host)

    deny_nets = []
    for network in deny:
        try:
            deny_nets.append(ipaddress.ip_network(network, strict=False))
        except ValueError:
            raise ValueError("denied_address") from None

    unique: list[str] = []
    for raw in raw_addresses:
        if raw in unique:
            continue
        if not isinstance(raw, str):
            raise ValueError("invalid_address")
        try:
            addr = ipaddress.ip_address(raw)
        except ValueError:
            raise ValueError("invalid_address") from None

        # 缺陷 3 修复：对解析出的每一个地址逐一做全量校验，全有或全无。
        if address_blocked(raw):
            raise ValueError("blocked_address")
        if any(
            addr.version == net.version and addr in net for net in deny_nets
        ):
            raise ValueError("denied_address")
        unique.append(raw)

    if not unique:
        raise ValueError("empty_resolution")

    return {"host": host, "addresses": tuple(unique)}


def pinned_resolve(
    url: str,
    resolver: Resolver,
    allow: Sequence[str],
    deny: Sequence[str],
) -> dict[str, Any]:
    """解析一次并固定校验后的地址，供后续连接使用。

    先调用 parse_target 解析 URL。这是连接前的安全门：
    - 只接受 https 和 443；其他协议抛 scheme_not_allowed，其他端口抛
      port_not_allowed；
    - host 必须先通过 host_allowed；
    - 只调用 resolve_and_check 一次，resolver 因而只执行一次；
    - 将地址复制为不可变元组，固定第一个地址为连接目标，之后不得再次解析；
      外部 resolver 数据变化不得改变已返回结果；
    - 本函数不跟随重定向；每一跳都必须用新 URL 重新调用本函数。

    返回 url、scheme、host、port、path、addresses、pinned 七个键；
    addresses 为字符串元组，pinned 为其第一个元素。
    """
    target = parse_target(url)

    # 缺陷 7 修复：只允许 https，file 等协议在协议白名单处被挡下。
    if target["scheme"] != "https":
        raise ValueError("scheme_not_allowed")
    # 缺陷 10 修复：只允许 443，其他显式/默认端口一律拒绝。
    if target["port"] != 443:
        raise ValueError("port_not_allowed")

    checked = resolve_and_check(target["host"], resolver, allow, deny)

    # 复制为不可变元组，切断与 resolver 返回列表的共享，防止外部数据变化。
    addresses = tuple(checked["addresses"])
    return {
        "url": target["url"],
        "scheme": target["scheme"],
        "host": target["host"],
        "port": target["port"],
        "path": target["path"],
        "addresses": addresses,
        "pinned": addresses[0],
    }


def redirect_allowed(old: str, new: str, allow: Sequence[str]) -> bool:
    """判断重定向目标是否可进入下一跳校验，不执行跳转。

    old 与 new 都必须是 443 端口的绝对 https URL，且 host 必须重新通过
    host_allowed；不得因为 old 已通过就放行 new。new 的 host 若为 IP 字面量
    且 address_blocked 判定为禁止地址，即使该字面量出现在 allow 中也必须
    拒绝。

    本函数不做 DNS，因此无法证明域名型 new 最终解析到公网。返回 True 只表示
    可以继续校验，不表示可以复用 old 的固定地址；调用方必须对 new 重新执行
    pinned_resolve。畸形输入返回 False。
    """
    try:
        old_target = parse_target(old)
        new_target = parse_target(new)
    except ValueError:
        return False

    if old_target["scheme"] != "https" or old_target["port"] != 443:
        return False
    if new_target["scheme"] != "https" or new_target["port"] != 443:
        return False

    # 缺陷 6 修复：重定向目标必须独立重新通过白名单，不沿用旧结论。
    if not host_allowed(new_target["host"], allow):
        return False

    # IP 字面量即使显式在白名单中，命中禁止地址也必须拒绝。
    if _is_ip_literal(new_target["host"]) and address_blocked(
        new_target["host"]
    ):
        return False

    return True


def validate_policy(policy: Mapping[str, Any]) -> list[str]:
    """返回策略问题的原因码列表，顺序固定且每项最多一次。

    只接受以下安全配置：
    - check_resolved_addresses 必须为 True；
    - max_redirects 必须是有限非负整数；None、布尔值、缺失或负数都表示
      无限重定向；
    - allowed_schemes 归一化后必须恰好等于仅含 https 的集合。

    依次检查并返回 resolved_addresses_not_checked、unbounded_redirects、
    scheme_not_restricted；合法策略返回空列表。缺键按对应问题处理，
    不抛异常。
    """
    issues: list[str] = []

    if policy.get("check_resolved_addresses") is not True:
        issues.append("resolved_addresses_not_checked")

    # 缺陷 8 修复：把无限/不明确的重定向配置明确判为问题。
    max_redirects = policy.get("max_redirects")
    if (
        max_redirects is None
        or isinstance(max_redirects, bool)
        or not isinstance(max_redirects, int)
        or max_redirects < 0
    ):
        issues.append("unbounded_redirects")

    schemes = policy.get("allowed_schemes")
    normalized = set()
    if isinstance(schemes, Sequence) and not isinstance(schemes, (str, bytes)):
        normalized = {
            item.lower() for item in schemes if isinstance(item, str)
        }
    if normalized != {"https"}:
        issues.append("scheme_not_restricted")

    return issues


def fetch_batch(
    urls: Sequence[str],
    resolver: Resolver,
    policy: Mapping[str, Any],
) -> dict[str, Any]:
    """批量校验 URL，目标之间不共享解析状态。

    对每个 URL 独立执行：
    - 先对整个 policy 调用一次 validate_policy；若有任何问题，所有 URL 都以
      invalid_policy 拒绝，且不调用 resolver；
    - 从 policy 读取 allow_hosts 与 deny_networks；
    - 调用 pinned_resolve，执行 https、443、白名单与逐地址校验；
    - 每个 URL 都单独调用 resolver 一次，重复 URL 也不得复用上次结果；
    - 将 ValueError 的原因码转为该 URL 的拒绝原因。

    返回 ok 与 rejected 两个键。ok 为 pinned 结果列表，rejected 为 url 与
    reason 的字典列表；两个列表各自保持输入顺序，一个 URL 只出现在一边。
    """
    ok: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []

    if validate_policy(policy):
        for url in urls:
            rejected.append({"url": url, "reason": "invalid_policy"})
        return {"ok": ok, "rejected": rejected}

    allow = policy.get("allow_hosts", [])
    deny = policy.get("deny_networks", [])

    for url in urls:
        # 缺陷 9 修复：每个 URL 独立走一遍 pinned_resolve，不维护、不复用
        # 任何跨目标的解析缓存；resolver 因此对每个 URL 都被调用一次。
        try:
            result = pinned_resolve(url, resolver, allow, deny)
        except ValueError as exc:
            rejected.append({"url": url, "reason": exc.args[0]})
        else:
            ok.append(result)

    return {"ok": ok, "rejected": rejected}
