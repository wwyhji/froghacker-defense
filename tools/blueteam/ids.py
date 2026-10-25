"""入侵检测 — IDS 规则生成与管理 (Snort/Suricata 兼容格式)。

蛙客不仅会攻，也会守 — 每一道防线都刻着对手的指纹.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class IDSRule:
    """一条 IDS 规则。"""
    action: str = "alert"       # alert / drop / reject
    protocol: str = "tcp"       # tcp / udp / icmp / http
    src_ip: str = "$EXTERNAL_NET"
    src_port: str = "any"
    dst_ip: str = "$HOME_NET"
    dst_port: str = "any"
    msg: str = ""
    sid: int = 0
    content: str = ""           # payload match pattern
    pcre: str = ""              # PCRE regex
    classtype: str = ""
    reference: str = ""
    rev: int = 1

    def to_snort(self) -> str:
        """输出 Snort/Suricata 兼容格式。"""
        parts = [self.action, self.protocol, self.src_ip, self.src_port,
                 "->", self.dst_ip, self.dst_port]
        opts = [f'msg:"{self.msg}"', f'sid:{self.sid}', f'rev:{self.rev}']
        if self.content:
            opts.append(f'content:"{self.content}"')
        if self.pcre:
            opts.append(f'pcre:"{self.pcre}"')
        if self.classtype:
            opts.append(f'classtype:{self.classtype}')
        if self.reference:
            opts.append(f'reference:{self.reference}')
        return " ".join(parts) + " (" + "; ".join(opts) + ";)"


# -- Rule generators ----------------------------------------------------------

# Counter for unique SIDs
_sid_base = 1000000
_sid_counter = 0


def _next_sid() -> int:
    global _sid_counter
    _sid_counter += 1
    return _sid_base + _sid_counter


def generate_ssh_brute_rules(threshold: int = 5, window: int = 60) -> List[IDSRule]:
    """生成 SSH 暴力破解检测规则。"""
    sid = _next_sid()
    return [
        IDSRule(
            action="alert", protocol="tcp", dst_port="22",
            msg="SSH 暴力破解 — 多次认证失败",
            sid=sid,
            content="Failed password",
            pcre=f"/Failed password.*from.*port/",
            classtype="attempted-recon",
            reference="url,attack.mitre.org/techniques/T1110",
        ),
        IDSRule(
            action="drop", protocol="tcp", dst_port="22",
            msg=f"SSH 暴力阻断 — {threshold}+ 次失败在 {window}s 内",
            sid=sid + 1,
            classtype="attempted-recon",
        ),
    ]


def generate_sqli_rules() -> List[IDSRule]:
    """生成 SQL 注入检测规则。"""
    sid = _next_sid()
    return [
        IDSRule(
            action="alert", protocol="http", dst_port="any",
            msg="SQL 注入探测 — UNION SELECT",
            sid=sid,
            content="UNION SELECT",
            pcre=r"/UNION\s+(ALL\s+)?SELECT/i",
            classtype="web-application-attack",
            reference="url,attack.mitre.org/techniques/T1190",
        ),
        IDSRule(
            action="alert", protocol="http", dst_port="any",
            msg="SQL 注入探测 — information_schema",
            sid=sid + 1,
            content="information_schema",
            classtype="web-application-attack",
        ),
        IDSRule(
            action="alert", protocol="http", dst_port="any",
            msg="SQL 注入探测 — OR 1=1",
            sid=sid + 2,
            content="OR 1=1",
            pcre=r"/['\"]\s*OR\s+[\d\w]+=[\d\w]+\s*['\"]/i",
            classtype="web-application-attack",
        ),
    ]


def generate_xss_rules() -> List[IDSRule]:
    """生成 XSS 检测规则。"""
    sid = _next_sid()
    return [
        IDSRule(
            action="alert", protocol="http", dst_port="any",
            msg="XSS 探测 — script tag",
            sid=sid,
            content="<script>alert",
            pcre=r"/<script[^>]*>.*alert\(/i",
            classtype="web-application-attack",
            reference="url,attack.mitre.org/techniques/T1189",
        ),
    ]


def generate_c2_rules(domains: Optional[List[str]] = None) -> List[IDSRule]:
    """生成 C2 通信检测规则。"""
    rules = []
    sid = _next_sid()

    # Generic beaconing detection
    rules.append(IDSRule(
        action="alert", protocol="tcp", dst_port="any",
        msg="疑似 C2 Beaconing — 周期性外连",
        sid=sid,
        pcre=r"/\.php\?[a-zA-Z0-9]{16,}/",
        classtype="trojan-activity",
        reference="url,attack.mitre.org/techniques/T1071",
    ))

    # Domain-specific rules
    if domains:
        for i, domain in enumerate(domains[:10]):
            rules.append(IDSRule(
                action="drop", protocol="tcp", dst_port="any",
                msg=f"C2 阻断 — 已知恶意域名: {domain}",
                sid=sid + i + 1,
                content=domain,
                classtype="trojan-activity",
            ))

    return rules


def generate_port_scan_rules(threshold: int = 20, window: int = 10) -> List[IDSRule]:
    """生成端口扫描检测规则。"""
    sid = _next_sid()
    return [
        IDSRule(
            action="alert", protocol="tcp", dst_port="any",
            msg=f"端口扫描 — {threshold}+ 端口在 {window}s 内",
            sid=sid,
            classtype="attempted-recon",
        ),
    ]


# -- Rule exporter ------------------------------------------------------------

def export_rules(rules: List[IDSRule], path: str = "") -> str:
    """导出规则为 Snort .rules 文件格式。

    Returns:
        文件路径或规则文本（path 为空时）。
    """
    header = (
        "# FrogHacker Blue Team — 自动生成 IDS 规则\n"
        f"# Generated rules: {len(rules)}\n\n"
    )
    body = "\n".join(r.to_snort() for r in rules)

    if path:
        Path(path).write_text(header + body + "\n", encoding="utf-8")
        return path
    return header + body


# -- Preset bundles -----------------------------------------------------------

BUNDLES: Dict[str, str] = {
    "web": "sqli + xss + port_scan",
    "server": "ssh_brute + c2 + port_scan",
    "all": "ssh_brute + sqli + xss + c2 + port_scan",
}


def generate_bundle(bundle_name: str = "web") -> List[IDSRule]:
    """生成预定义规则集合。

    Args:
        bundle_name: web | server | all

    Returns:
        合并后的规则列表
    """
    rules = []
    if bundle_name in ("web", "all"):
        rules.extend(generate_sqli_rules())
        rules.extend(generate_xss_rules())
    if bundle_name in ("server", "all"):
        rules.extend(generate_ssh_brute_rules())
        rules.extend(generate_c2_rules())
    if bundle_name in ("web", "server", "all"):
        rules.extend(generate_port_scan_rules())
    return rules
