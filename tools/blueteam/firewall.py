"""防火墙管理 — iptables/nftables 规则生成与 IP 封禁。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class FirewallRule:
    """一条防火墙规则。"""
    action: str = "DROP"       # ACCEPT / DROP / REJECT
    chain: str = "INPUT"
    protocol: str = "tcp"      # tcp / udp / icmp / all
    src_ip: str = ""           # 空 = any
    dst_port: str = ""          # 空 = any
    comment: str = ""

    def to_iptables(self) -> str:
        """输出 iptables 命令。"""
        parts = ["iptables", "-A", self.chain, "-p", self.protocol]
        if self.src_ip:
            parts.extend(["-s", self.src_ip])
        if self.dst_port:
            parts.extend(["--dport", self.dst_port])
        parts.extend(["-j", self.action])
        if self.comment:
            parts.extend(["-m", "comment", "--comment", self.comment])
        return " ".join(parts)

    def to_nftables(self) -> str:
        """输出 nftables 规则。"""
        match = f"meta protocol {self.protocol}"
        if self.src_ip:
            match += f" ip saddr {self.src_ip}"
        if self.dst_port:
            match += f" {self.protocol} dport {self.dst_port}"
        comment = f' comment "{self.comment}"' if self.comment else ""
        return f"add rule inet filter {self.chain} {match} {self.action}{comment}"


# -- Common rule sets ---------------------------------------------------------

def baseline_rules() -> List[FirewallRule]:
    """生成基线防火墙规则 — 允许 SSH/HTTP/HTTPS/DNS，其余入站 DROP。"""
    return [
        FirewallRule(action="ACCEPT", chain="INPUT", protocol="tcp",
                     dst_port="22", comment="SSH"),
        FirewallRule(action="ACCEPT", chain="INPUT", protocol="tcp",
                     dst_port="80", comment="HTTP"),
        FirewallRule(action="ACCEPT", chain="INPUT", protocol="tcp",
                     dst_port="443", comment="HTTPS"),
        FirewallRule(action="ACCEPT", chain="INPUT", protocol="udp",
                     dst_port="53", comment="DNS"),
        FirewallRule(action="ACCEPT", chain="INPUT", protocol="all",
                     comment="Established connections",
                     ),  # Special: -m conntrack --ctstate ESTABLISHED,RELATED
        FirewallRule(action="DROP", chain="INPUT", protocol="all",
                     comment="Default drop inbound"),
    ]


def block_ip(ip: str, comment: str = "FrogHacker auto-block") -> FirewallRule:
    """生成封禁特定 IP 的规则。"""
    return FirewallRule(
        action="DROP", chain="INPUT", protocol="all",
        src_ip=ip, comment=comment,
    )


def block_ips(ips: List[str], comment: str = "FrogHacker auto-block") -> List[FirewallRule]:
    """批量封禁 IP 列表。"""
    return [block_ip(ip, comment) for ip in ips[:100]]


def block_port(port: int, protocol: str = "tcp",
               comment: str = "FrogHacker block port") -> FirewallRule:
    """封禁特定端口入站流量。"""
    return FirewallRule(
        action="DROP", chain="INPUT", protocol=protocol,
        dst_port=str(port), comment=comment,
    )


def rate_limit(port: int, rate: str = "10/minute", burst: int = 20,
               protocol: str = "tcp", comment: str = "FrogHacker rate-limit") -> str:
    """生成速率限制 iptables 规则。

    注意：返回原生 iptables 命令字符串，因为 Python 封装不支持 --limit。
    """
    return (
        f"iptables -A INPUT -p {protocol} --dport {port} "
        f"-m limit --limit {rate} --limit-burst {burst} "
        f'-m comment --comment "{comment}" -j ACCEPT'
    )


# -- Application --------------------------------------------------------------

def apply_rules(rules: List[FirewallRule], dry_run: bool = True) -> Dict[str, Any]:
    """执行防火墙规则（需要 root 权限）。

    Args:
        rules: 规则列表
        dry_run: True = 仅打印命令不执行

    Returns:
        {"applied": N, "errors": N, "commands": [...]}
    """
    commands = [r.to_iptables() for r in rules]
    applied = 0
    errors = 0

    if dry_run:
        return {"applied": 0, "errors": 0, "commands": commands, "dry_run": True}

    from tools.core.tool_invoker import invoke
    for cmd in commands:
        r = invoke("iptables", cmd.split()[1:], timeout=10)
        if r.ok:
            applied += 1
        else:
            errors += 1

    return {"applied": applied, "errors": errors, "commands": commands}


def list_rules(table: str = "filter") -> str:
    """列出当前防火墙规则。"""
    from tools.core.tool_invoker import invoke
    r = invoke("iptables", ["-L", table, "-n", "--line-numbers"], timeout=10)
    return r.stdout if r.ok else "iptables 未安装或无权限"


def flush_chain(chain: str = "INPUT") -> bool:
    """清空指定链的所有规则（危险操作，需确认）。"""
    from tools.core.tool_invoker import invoke
    return invoke("iptables", ["-F", chain], timeout=10).ok
