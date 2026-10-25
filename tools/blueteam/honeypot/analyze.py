"""蜜罐日志分析 — 攻击日志解析、IOC 提取、攻击模式识别。"""

from __future__ import annotations

import json
import platform
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

IS_WINDOWS = platform.system() == "Windows"


# -- Known attack patterns ----------------------------------------------------

ATTACK_PATTERNS: List[Dict[str, Any]] = [
    {"id": "SSH_BRUTE", "name": "SSH 暴力破解",
     "indicators": ["Failed password", "authentication failure", "invalid user"],
     "severity": "medium", "mitigation": "fail2ban + SSH key-only auth"},
    {"id": "WEB_SCAN", "name": "Web 扫描",
     "indicators": ["/wp-admin", "/.env", "/config.php", "admin/login",
                    "wp-login", "sqlmap", "nikto", "nmap"],
     "severity": "low", "mitigation": "WAF + 速率限制"},
    {"id": "SQL_INJ", "name": "SQL 注入探测",
     "indicators": ["' OR '1'='1", "UNION SELECT", "SLEEP(", "BENCHMARK(",
                    "information_schema", "' OR 1=1--"],
     "severity": "high", "mitigation": "参数化查询 + WAF"},
    {"id": "RCE_SCAN", "name": "命令注入/RCE 探测",
     "indicators": [";id;", "|cat /etc/passwd", "$(whoami)", "`id`",
                    "/bin/bash", "cmd.exe", "powershell", "wget http", "curl http"],
     "severity": "critical", "mitigation": "输入白名单 + 禁用危险函数"},
    {"id": "XSS_SCAN", "name": "XSS 探测",
     "indicators": ["<script>alert", "javascript:", "onerror=", "onload=",
                    "<img src=x", "<svg/onload="],
     "severity": "medium", "mitigation": "CSP header + 输出编码"},
    {"id": "LFI_SCAN", "name": "文件包含/路径穿越",
     "indicators": ["../etc/passwd", "....//", "..%2f..%2f",
                    "php://filter", "file:///", "/proc/self/environ"],
     "severity": "high", "mitigation": "输入校验 + 白名单文件访问"},
    {"id": "CRAWLER", "name": "爬虫/扫描器",
     "indicators": ["Googlebot", "bingbot", "AhrefsBot", "SemrushBot",
                    "nessus", "qualys", "burpsuite", "zgrab", "masscan"],
     "severity": "info", "mitigation": "robots.txt + 速率限制"},
]


# -- Data types ---------------------------------------------------------------

@dataclass
class AttackLog:
    """单条攻击日志。"""
    timestamp: str = ""
    source_ip: str = ""
    source_port: int = 0
    protocol: str = ""
    payload: str = ""
    matched_patterns: List[str] = field(default_factory=list)
    severity: str = "info"

    def to_dict(self) -> dict:
        return {
            "time": self.timestamp, "src": f"{self.source_ip}:{self.source_port}",
            "proto": self.protocol, "payload": self.payload[:200],
            "patterns": self.matched_patterns, "severity": self.severity,
        }


# -- IOC extraction -----------------------------------------------------------

IP_RE = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
HASH_RE = re.compile(r'\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b')
DOMAIN_RE = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+'
                       r'[a-zA-Z]{2,}\b')
URL_RE = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
EMAIL_RE = re.compile(r'\b[\w\.\-+=]+@[\w\.\-]+\.[a-zA-Z]{2,}\b')


def extract_iocs(text: str) -> Dict[str, List[str]]:
    """从文本中提取 IOCs (IP/域名/URL/邮箱/哈希)。

    Returns:
        {"ips": [...], "domains": [...], "urls": [...], "emails": [...], "hashes": [...]}
    """
    return {
        "ips": list(set(IP_RE.findall(text)))[:20],
        "domains": list(set(DOMAIN_RE.findall(text)))[:20],
        "urls": list(set(URL_RE.findall(text)))[:20],
        "emails": list(set(EMAIL_RE.findall(text)))[:10],
        "hashes": list(set(HASH_RE.findall(text)))[:10],
    }


# -- Log parsing --------------------------------------------------------------

def _parse_cowrie_log(log_path: Path) -> List[AttackLog]:
    """解析 Cowrie JSON 日志。"""
    logs = []
    if not log_path.exists():
        return logs

    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            entry = json.loads(line.strip())
        except json.JSONDecodeError:
            continue

        eventid = entry.get("eventid", "")
        src_ip = entry.get("src_ip", "")
        payload = entry.get("input", "") or entry.get("command", "") or str(entry)

        matched = _match_patterns(payload)
        severity = _max_severity(matched)

        logs.append(AttackLog(
            timestamp=entry.get("timestamp", ""),
            source_ip=src_ip, source_port=entry.get("src_port", 0),
            protocol="ssh/telnet", payload=str(payload)[:500],
            matched_patterns=matched, severity=severity,
        ))

    return logs


def _parse_simple_http_log(log_path: Path) -> List[AttackLog]:
    """解析 simple_http JSONL 日志。"""
    logs = []
    if not log_path.exists():
        return logs

    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            entry = json.loads(line.strip())
        except json.JSONDecodeError:
            continue

        payload = f"{entry.get('method', '?')} {entry.get('path', '/')}"
        body = entry.get("body", "")
        if body:
            payload += f" | body: {body[:200]}"

        # Check headers too
        headers_str = json.dumps(entry.get("headers", {}))
        full_payload = f"{payload} {headers_str}"

        matched = _match_patterns(full_payload)
        severity = _max_severity(matched)

        logs.append(AttackLog(
            timestamp=entry.get("time", ""),
            source_ip=entry.get("client", ""), source_port=0,
            protocol="http", payload=full_payload[:500],
            matched_patterns=matched, severity=severity,
        ))

    return logs


def _parse_generic_log(log_path: Path) -> List[AttackLog]:
    """解析通用文本日志（按行）。"""
    logs = []
    if not log_path.exists():
        return logs

    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines()[:1000]:
        line = line.strip()
        if not line or len(line) < 5:
            continue

        # Try to extract IP
        ips = IP_RE.findall(line)
        src_ip = ips[0] if ips else ""

        matched = _match_patterns(line)
        severity = _max_severity(matched)

        if matched:  # Only keep lines with matches
            logs.append(AttackLog(
                timestamp="", source_ip=src_ip, source_port=0,
                protocol="unknown", payload=line[:500],
                matched_patterns=matched, severity=severity,
            ))

    return logs


# -- Pattern matching ---------------------------------------------------------

def _match_patterns(text: str) -> List[str]:
    """匹配已知攻击模式。"""
    text_lower = text.lower()
    matched = []
    for pat in ATTACK_PATTERNS:
        if any(ind.lower() in text_lower for ind in pat["indicators"]):
            matched.append(pat["id"])
    return matched


def _max_severity(matched: List[str]) -> str:
    """从匹配模式中取最高严重级别。"""
    order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    max_sev = "info"
    for pat in ATTACK_PATTERNS:
        if pat["id"] in matched:
            if order.get(pat["severity"], 0) > order.get(max_sev, 0):
                max_sev = pat["severity"]
    return max_sev


# -- Analysis functions -------------------------------------------------------

def analyze_captures(log_dir: str, honeypot_type: str = "") -> Dict[str, Any]:
    """分析蜜罐捕获的日志。

    Returns:
        {
            "total_attacks": N,
            "top_sources": [(ip, count), ...],
            "attack_types": {pattern_id: count, ...},
            "severity_dist": {sev: count, ...},
            "iocs": {...},
            "timeline": [(time, pattern), ...],
        }
    """
    log_path = Path(log_dir)
    all_logs: List[AttackLog] = []

    # Parse logs based on type
    if honeypot_type == "cowrie":
        json_log = log_path / "cowrie.json" if (log_path / "cowrie.json").exists() else log_path
        if json_log.is_file():
            all_logs = _parse_cowrie_log(json_log)
    elif honeypot_type == "simple_http":
        http_log = log_path / f"http_8888.jsonl"
        for f in log_path.glob("http_*.jsonl"):
            all_logs.extend(_parse_simple_http_log(f))
    else:
        # Generic: scan all text files
        # Windows: NTFS reparse points → BSOD risk, use single-level glob
        if IS_WINDOWS:
            for f in sorted(log_path.glob("*")):
                if f.is_file() and f.suffix in (".log", ".txt", ".jsonl", ".json"):
                    all_logs.extend(_parse_generic_log(f))
        else:
            for f in sorted(log_path.rglob("*")):
                if f.is_symlink():
                    continue
                if f.is_file() and f.suffix in (".log", ".txt", ".jsonl", ".json"):
                    all_logs.extend(_parse_generic_log(f))

    if not all_logs:
        return {"total_attacks": 0, "top_sources": [], "attack_types": {},
                "severity_dist": {}, "iocs": {}, "timeline": []}

    # Statistics
    src_counter = Counter(log.source_ip for log in all_logs if log.source_ip)
    pattern_counter = Counter()
    severity_counter = Counter()
    all_iocs: Dict[str, Set[str]] = {"ips": set(), "domains": set(), "urls": set(),
                                       "emails": set(), "hashes": set()}
    timeline = []

    for log in all_logs:
        for pat in log.matched_patterns:
            pattern_counter[pat] += 1
        severity_counter[log.severity] += 1
        iocs = extract_iocs(log.payload)
        for key in all_iocs:
            all_iocs[key].update(iocs.get(key, []))
        if log.matched_patterns:
            timeline.append((log.timestamp or "", log.matched_patterns[0]))

    return {
        "total_attacks": len(all_logs),
        "top_sources": src_counter.most_common(10),
        "attack_types": dict(pattern_counter.most_common()),
        "severity_dist": dict(severity_counter),
        "iocs": {k: list(v)[:20] for k, v in all_iocs.items()},
        "timeline": timeline[:50],
    }
