"""日志分析 — 多源日志解析与异常检测 (auth/syslog/nginx/apache)。"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class LogEntry:
    """标准化日志条目。"""
    timestamp: str = ""
    source: str = ""          # auth.log / syslog / nginx / apache
    host: str = ""
    service: str = ""
    message: str = ""
    severity: str = "info"   # info / warn / critical
    raw: str = ""

    def to_dict(self) -> dict:
        return {
            "time": self.timestamp, "src": self.source,
            "host": self.host, "svc": self.service,
            "msg": self.message[:200], "severity": self.severity,
        }


# -- Parsers ------------------------------------------------------------------

SSH_FAILED_RE = re.compile(
    r'(\w{3}\s+\d+\s+\d+:\d+:\d+).*sshd.*Failed password for (\S+) from (\S+) port (\d+)',
    re.I,
)
SSH_ACCEPTED_RE = re.compile(
    r'(\w{3}\s+\d+\s+\d+:\d+:\d+).*sshd.*Accepted (?:password|publickey) for (\S+) from (\S+)',
    re.I,
)
SUDO_RE = re.compile(
    r'(\w{3}\s+\d+\s+\d+:\d+:\d+).*sudo:\s+(\S+)\s+.*COMMAND=(.+)',
    re.I,
)
FAILED_SU_RE = re.compile(
    r'(\w{3}\s+\d+\s+\d+:\d+:\d+).*su.*FAILED.*(\S+)',
    re.I,
)

NGINX_RE = re.compile(
    r'(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) [^"]*" (\d+) (\d+) "([^"]*)" "([^"]*)"',
)
APACHE_RE = re.compile(
    r'(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) [^"]*" (\d+) (\d+)',
)


def _parse_auth_log(text: str) -> List[LogEntry]:
    """解析 auth.log / secure 日志。"""
    entries = []
    for line in text.splitlines():
        entry = None

        m = SSH_FAILED_RE.search(line)
        if m:
            entry = LogEntry(
                timestamp=m.group(1), source="auth.log", service="sshd",
                message=f"Failed password for {m.group(2)} from {m.group(3)}",
                severity="warn", raw=line,
            )

        m = SSH_ACCEPTED_RE.search(line)
        if m:
            entry = LogEntry(
                timestamp=m.group(1), source="auth.log", service="sshd",
                message=f"Accepted login: {m.group(2)} from {m.group(3)}",
                severity="info", raw=line,
            )

        m = SUDO_RE.search(line)
        if m:
            entry = LogEntry(
                timestamp=m.group(1), source="auth.log", service="sudo",
                message=f"sudo: {m.group(2)} ran {m.group(3)[:100]}",
                severity="warn", raw=line,
            )

        m = FAILED_SU_RE.search(line)
        if m:
            entry = LogEntry(
                timestamp=m.group(1), source="auth.log", service="su",
                message=f"Failed su for {m.group(2)}",
                severity="critical", raw=line,
            )

        if entry:
            entries.append(entry)

    return entries


def _parse_nginx_log(text: str) -> List[LogEntry]:
    """解析 Nginx access.log。"""
    entries = []
    for line in text.splitlines():
        m = NGINX_RE.match(line)
        if not m:
            continue
        ip, ts, method, path, status, size, referer, ua = m.groups()
        status_code = int(status)

        severity = "info"
        if status_code >= 500:
            severity = "critical"
        elif status_code >= 400:
            severity = "warn"
        elif status_code >= 300:
            severity = "info"

        entries.append(LogEntry(
            timestamp=ts, source="nginx", service="http",
            message=f"{method} {path} → {status} ({size}B)",
            severity=severity, raw=line,
        ))

    return entries


def _parse_syslog(text: str) -> List[LogEntry]:
    """解析 syslog — 提取错误和警告。"""
    entries = []
    keywords = ["error", "fail", "critical", "kernel", "oom", "segfault",
                "panic", "denied", "refused", "timeout"]

    for line in text.splitlines():
        line_lower = line.lower()
        if any(kw in line_lower for kw in keywords):
            critical_kws = ("oom", "segfault", "panic", "kernel")
            severity = "critical" if any(k in line_lower for k in critical_kws) else "warn"
            entries.append(LogEntry(
                timestamp="", source="syslog", service="system",
                message=line[:300], severity=severity, raw=line,
            ))

    return entries


# -- Analysis -----------------------------------------------------------------

_engine = None


def _get_detection_engine():
    """延迟加载 DetectionEngine（单例，避免每次分析重复加载规则）。"""
    global _engine
    if _engine is None:
        from tools.blueteam.detection_engine import DetectionEngine
        _engine = DetectionEngine()
    return _engine


def detect_threats(entries: List[LogEntry]) -> List[dict]:
    """把日志条目喂给 DetectionEngine，返回检测到的威胁告警。

    LogEntry → event dict 映射：raw/message 供关键词匹配，service 供协议/类型匹配。
    这是三端共生闭环的最后一环：日志 → 事件 → 74 规则检测 → 告警。
    """
    if not entries:
        return []
    engine = _get_detection_engine()
    events = [
        {
            "raw": (e.raw or e.message),
            "message": e.message,
            "type": e.service,
            "protocol": e.service,
            "source": e.source,
            "host": e.host,
            "severity": e.severity,
        }
        for e in entries
    ]
    return [a.to_dict() for a in engine.scan_events(events)]


def analyze_logs(log_dir: str = "/var/log", files: Optional[List[str]] = None) -> Dict[str, Any]:
    """分析日志目录。

    Args:
        log_dir: 日志目录
        files: 指定文件列表 (空 = 扫描常见日志)

    Returns:
        {
            "total_entries": N,
            "severity_dist": {sev: count, ...},
            "top_sources": [(ip, count), ...],
            "failed_logins": [(user, ip, count), ...],
            "suspicious_ips": [ip, ...],
            "events": [LogEntry, ...],
        }
    """
    log_path = Path(log_dir)
    if not log_path.exists():
        return {"total_entries": 0, "error": f"目录不存在: {log_dir}"}

    target_files = files or ["auth.log", "secure", "syslog",
                              "nginx/access.log", "apache2/access.log"]
    all_entries: List[LogEntry] = []

    for fname in target_files:
        fpath = log_path / fname
        if not fpath.is_file():
            continue

        try:
            text = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        if "auth" in fname or "secure" in fname:
            all_entries.extend(_parse_auth_log(text))
        elif "nginx" in fname:
            all_entries.extend(_parse_nginx_log(text))
        elif "apache" in fname:
            all_entries.extend(_parse_nginx_log(text))  # same format
        elif "syslog" in fname:
            all_entries.extend(_parse_syslog(text))

    if not all_entries:
        return {"total_entries": 0, "severity_dist": {}, "top_sources": [],
                "failed_logins": [], "suspicious_ips": [], "events": []}

    # Aggregations
    severity_dist = Counter(e.severity for e in all_entries)

    # Extract IPs from messages
    ip_re = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
    ip_counter = Counter()
    failed_logins = Counter()
    for e in all_entries:
        ips = ip_re.findall(e.message)
        for ip in ips:
            if not ip.startswith(("127.", "10.", "192.168.", "172.16.")):
                ip_counter[ip] += 1

    # Suspicious: high-frequency IPs
    suspicious = [ip for ip, cnt in ip_counter.most_common(20)
                  if cnt >= 5 and not ip.startswith("0.")]

    # Failed login aggregation
    for e in all_entries:
        if "Failed password" in e.message:
            user_match = re.search(r'for (\S+) from', e.message)
            ip_match = re.search(r'from (\S+)', e.message)
            if user_match and ip_match:
                failed_logins[(user_match.group(1), ip_match.group(1))] += 1

    return {
        "total_entries": len(all_entries),
        "severity_dist": dict(severity_dist),
        "top_sources": ip_counter.most_common(15),
        "failed_logins": [(u, ip, c) for (u, ip), c in failed_logins.most_common(20)],
        "suspicious_ips": suspicious,
        "events": [e.to_dict() for e in all_entries[-50:]],  # most recent 50
        "detected_threats": detect_threats(all_entries),
    }


def parse_line(line: str) -> Optional[LogEntry]:
    """解析单行日志，自动识别格式。"""
    for parser in (_parse_auth_log, _parse_nginx_log, _parse_syslog):
        result = parser(line)
        if result:
            return result[0]
    return None
