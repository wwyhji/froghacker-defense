"""侦察背调预警 — 攻击前信号检测 (G2 资产级).

攻击者下手前会做背调/侦察: 注册仿冒域名(typosquatting)、查证书透明度、
测绘资产暴露面、搜集人员信息。这些是可提前捕捉的攻击前兆信号。

检测能力:
  1. typosquatting 域名 — 生成目标域名的仿冒变体, DNS 检测哪些已被部署
  2. 证书透明度侦察 — crt.sh 查目标域名的全部证书 (发现异常证书)
  3. 资产暴露面 — 生成 Shodan 搜索 URL (降级)

复用 tools.osint.domain_intel 的 crt.sh 查询能力。

用法:
    from tools.blueteam.recon_warning import recon_warning
    report = recon_warning("example.com")
"""

from __future__ import annotations

import socket
from typing import List, Optional

# 常见仿冒 TLD / 前缀 / 后缀
_ALT_TLDS = ["net", "org", "cn", "co", "info", "xyz", "top", "vip"]
_PREFIXES = ["my", "login", "secure", "www", "mail", "auth", "verify"]
_SUFFIXES = ["-login", "-secure", "-auth", "-verify", "-support"]
# 字符替换表 (0→o, 1→l/i, 3→e, 4→a, 5→s, 8→b)
_REPLACEMENTS = {"o": "0", "l": "1", "i": "1", "e": "3", "a": "4", "s": "5", "b": "8"}


def typosquat_variants(domain: str, max_variants: int = 60) -> List[str]:
    """生成目标域名的常见仿冒变体 (typosquatting)。"""
    if "." in domain:
        name, tld = domain.rsplit(".", 1)
    else:
        name, tld = domain, "com"

    variants = set()

    # 1. 字符替换 (homograph/leetspeak)
    for ch, rep in _REPLACEMENTS.items():
        if ch in name:
            variants.add(name.replace(ch, rep) + "." + tld)

    # 2. 连字符拆分
    for i in range(1, len(name)):
        variants.add(name[:i] + "-" + name[i:] + "." + tld)

    # 3. 常见 TLD 替换
    for alt in _ALT_TLDS:
        if alt != tld:
            variants.add(name + "." + alt)

    # 4. 前缀 / 后缀
    for pre in _PREFIXES:
        variants.add(pre + "-" + name + "." + tld)
    for suf in _SUFFIXES:
        variants.add(name + suf + "." + tld)

    return sorted(variants)[:max_variants]


def check_resolved(domains: List[str], timeout: int = 3) -> List[str]:
    """DNS 检测哪些域名已解析 (说明已被注册/部署)。"""
    resolved = []
    for d in domains:
        try:
            socket.setdefaulttimeout(timeout)
            socket.gethostbyname(d)
            resolved.append(d)
        except (socket.gaierror, socket.timeout, OSError):
            continue
    return resolved


def cert_transparency(domain: str) -> List[dict]:
    """查 crt.sh 证书透明度, 返回该域名的全部证书 common_name。"""
    try:
        from tools.osint.domain_intel import _query_crtsh
        certs = _query_crtsh(domain)
    except Exception:
        return []
    return [c.to_dict() for c in certs if hasattr(c, "to_dict")]


def recon_warning(domain: str) -> dict:
    """综合侦察背调预警。

    Returns:
        {domain, typosquat_variants, suspicious_resolved, certificates,
         shodan_url, risk_hints}
    """
    import urllib.parse

    variants = typosquat_variants(domain)
    resolved = check_resolved(variants)
    certs = cert_transparency(domain)
    shodan_url = f"https://www.shodan.io/search?query={urllib.parse.quote('hostname:' + domain)}"

    # 异常证书: common_name 不是主域名本身 (可能是仿冒/相关基础设施)
    main = domain.lower()
    suspicious_certs = [
        c for c in certs
        if c.get("common_name", "").lower() != main
        and main.split(".")[0] in c.get("common_name", "").lower()
    ]

    risk_hints = []
    if resolved:
        risk_hints.append(f"发现 {len(resolved)} 个仿冒域名已部署 (可能用于钓鱼)")
    if suspicious_certs:
        risk_hints.append(f"发现 {len(suspicious_certs)} 个异常证书 (可能相关基础设施)")

    return {
        "domain": domain,
        "typosquat_variants": len(variants),
        "suspicious_resolved": resolved,
        "certificates_total": len(certs),
        "suspicious_certificates": suspicious_certs[:20],
        "shodan_url": shodan_url,
        "risk_hints": risk_hints,
    }
