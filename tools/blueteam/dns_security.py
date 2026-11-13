"""DNS Security Analysis — DNS 隧道 / DGA / 恶意域名检测.

分析 DNS 查询日志，用香农熵 + 结构特征检测三类威胁：
  - tunnel:       DNS 隧道（数据编码进子域名，标签超长 + 高熵）
  - dga:          域生成算法（僵尸网络 C2，主体高熵随机字符）
  - hex_subdomain: 十六进制编码子域（隧道/恶意特征）

纯 Python 无外部依赖，熵计算不依赖第三方库。

Usage:
    from tools.blueteam.dns_security import DNSAnalyzer
    a = DNSAnalyzer()
    findings = a.analyze([
        {"domain": "a1b2c3d4e5f6.example.com"},
        {"domain": "google.com"},
    ])
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Dict, List


def shannon_entropy(s: str) -> float:
    """香农熵（比特/字符），随机字符串趋向 ~log2(字符集大小)。"""
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


@dataclass
class DNSFinding:
    """一条 DNS 可疑发现。"""
    domain: str
    kind: str    # tunnel / dga / hex_subdomain
    score: float
    detail: str


_HEX_RE = re.compile(r"^[0-9a-f]{10,}$")


class DNSAnalyzer:
    """DNS 查询日志安全分析器。"""

    def analyze(self, queries: List[Dict]) -> List[DNSFinding]:
        """分析 DNS 查询，返回可疑发现列表。"""
        findings: List[DNSFinding] = []
        for q in queries:
            domain = str(q.get("domain") or q.get("qname") or q.get("name") or "")
            domain = domain.rstrip(".").lower()
            if not domain:
                continue

            labels = domain.split(".")
            sld = labels[0] if labels else domain
            longest = max(labels, key=len)

            # 1. DNS 隧道：超长标签 + 高熵（数据编码进子域名）
            if len(longest) > 30:
                ent = shannon_entropy(longest)
                if ent > 3.0:
                    findings.append(DNSFinding(
                        domain, "tunnel", ent,
                        f"标签 {len(longest)} 字符, 熵 {ent:.2f}"))

            # 2. DGA：主体高熵（随机字符）+ 合理长度 + 无连字符
            #    （连字符是「人为构造」特征，DGA 随机生成不含连字符，
            #     排除 microsooft-update 这类 typosquatting 误报）
            ent_sld = shannon_entropy(sld)
            if ent_sld > 3.5 and 10 < len(sld) < 32 and "-" not in sld:
                findings.append(DNSFinding(
                    domain, "dga", ent_sld,
                    f"主体熵 {ent_sld:.2f}, 长度 {len(sld)}"))

            # 3. 十六进制编码子域（隧道/恶意特征）
            if _HEX_RE.match(longest):
                findings.append(DNSFinding(
                    domain, "hex_subdomain", 3.0,
                    f"标签为十六进制编码 ({len(longest)} 字符)"))

        return findings


__all__ = ["DNSAnalyzer", "DNSFinding", "shannon_entropy"]
