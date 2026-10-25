"""威胁狩猎 — 基于 IOC 和 TTP 的主动威胁搜索。"""

from __future__ import annotations

import os
import platform
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

IS_WINDOWS = platform.system() == "Windows"


@dataclass
class HuntResult:
    """威胁狩猎发现。"""
    finding_type: str = ""      # ioc_match / anomaly / persistence / backdoor
    description: str = ""
    evidence: str = ""          # 文件路径或命令输出
    severity: str = "medium"
    confidence: float = 0.5     # 0.0-1.0
    mitre_technique: str = ""

    def to_dict(self) -> dict:
        return {
            "type": self.finding_type, "desc": self.description,
            "evidence": self.evidence[:200], "severity": self.severity,
            "confidence": self.confidence, "mitre": self.mitre_technique,
        }


# -- Persistence checks -------------------------------------------------------

PERSISTENCE_CHECKS: List[Dict[str, Any]] = [
    {"path": "/etc/crontab", "desc": "系统 crontab",
     "mitre": "T1053.003"},
    {"path": "/var/spool/cron/crontabs", "desc": "用户 crontab 目录",
     "mitre": "T1053.003"},
    {"path": "/etc/systemd/system", "desc": "Systemd 服务目录",
     "mitre": "T1543.002"},
    {"path": "/etc/rc.local", "desc": "rc.local 启动脚本",
     "mitre": "T1037"},
    {"path": os.path.expanduser("~/.ssh/authorized_keys"), "desc": "SSH authorized_keys",
     "mitre": "T1098.004"},
    {"path": "/etc/passwd", "desc": "新增用户检查",
     "mitre": "T1136.001"},
    {"path": "/tmp", "desc": "临时目录可疑文件",
     "mitre": "T1204.002"},
]


# -- Hunting functions --------------------------------------------------------

def _check_persistence(root: str = "/") -> List[HuntResult]:
    """检查持久化机制 — crontab/systemd/rc.local/SSH keys。

    Safety: max_depth=3 + skip junctions on Windows to prevent ntfs.sys BSOD.
    """
    results = []
    for check in PERSISTENCE_CHECKS:
        fpath = Path(check["path"])
        if not fpath.exists():
            continue

        # Skip Linux-only paths on Windows — they don't apply and may resolve oddly
        if IS_WINDOWS and not str(fpath).startswith(os.path.expanduser("~")):
            continue

        try:
            if fpath.is_dir():
                # Safety: depth-limited glob, skip junctions/symlinks on Windows
                import time
                if IS_WINDOWS:
                    # On Windows, avoid rglob entirely for system dirs —
                    # NTFS reparse points can cause infinite recursion → BSOD
                    try:
                        files = list(fpath.glob("*"))  # non-recursive, single level
                    except OSError:
                        continue
                else:
                    # Linux/Unix: recursive but depth-limited
                    files = []
                    for p in fpath.rglob("*"):
                        if p.is_symlink():
                            continue
                        # Limit depth to prevent runaway traversal
                        try:
                            rel = p.relative_to(fpath)
                            if len(rel.parts) > 3:
                                continue
                        except ValueError:
                            continue
                        files.append(p)

                # Filter: recently modified (< 7 days)
                recent = [f for f in files if f.is_file()
                          and not f.is_symlink()
                          and time.time() - f.stat().st_mtime < 7 * 86400]
                if recent:
                    results.append(HuntResult(
                        finding_type="persistence",
                        description=f"{check['desc']}: {len(recent)} 个近期修改文件",
                        evidence=str(recent[:5]),
                        severity="high" if len(recent) > 3 else "medium",
                        confidence=0.7,
                        mitre_technique=check["mitre"],
                    ))
            elif fpath.is_file():
                # Check for suspicious entries
                content = fpath.read_text(encoding="utf-8", errors="replace")
                suspicious_keywords = ["nc ", "bash -i", "python -c", "base64 -d",
                                      "curl http", "wget http", "/dev/tcp", "backdoor"]
                hits = [kw for kw in suspicious_keywords if kw in content.lower()]
                if hits:
                    results.append(HuntResult(
                        finding_type="backdoor",
                        description=f"{check['desc']}: 含可疑关键词 {hits}",
                        evidence=str(fpath),
                        severity="critical",
                        confidence=0.9,
                        mitre_technique=check["mitre"],
                    ))
        except (PermissionError, OSError):
            continue

    return results


def _check_network() -> List[HuntResult]:
    """检查异常网络连接。"""
    results = []
    from tools.core.tool_invoker import invoke
    try:
        # List listening ports
        r = invoke("ss", ["-tlnp"], timeout=10)
        suspicious_ports = {4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337,
                           44444, 55555}
        for line in r.stdout.splitlines():
            for port in suspicious_ports:
                if f":{port}" in line:
                    results.append(HuntResult(
                        finding_type="anomaly",
                        description=f"可疑监听端口: {port}",
                        evidence=line.strip(),
                        severity="critical",
                        confidence=0.85,
                        mitre_technique="T1571",
                    ))

        # Check established connections to known-bad ports
        r2 = invoke("ss", ["-tnp"], timeout=10)
        for line in r2.stdout.splitlines():
            if any(port in line for port in [":4444", ":1337", ":31337"]):
                results.append(HuntResult(
                    finding_type="anomaly",
                    description=f"活跃可疑连接",
                    evidence=line.strip(),
                    severity="critical",
                    confidence=0.8,
                    mitre_technique="T1071",
                ))

    except Exception as _e:
        from tools.swallow_trap import record
        record(_e)

    return results


def _check_processes() -> List[HuntResult]:
    """检查可疑进程。"""
    results = []
    suspicious_names = ["shell", "backdoor", "reverse", "bind", "beacon",
                       "mimikatz", "procdump", "lsass_dump", "psexec"]

    try:
        from tools.core.tool_invoker import invoke
        r = invoke("ps", ["aux"], timeout=10)
        for line in r.stdout.splitlines():
            line_lower = line.lower()
            for name in suspicious_names:
                if name in line_lower and "grep" not in line_lower:
                    results.append(HuntResult(
                        finding_type="anomaly",
                        description=f"可疑进程: {name}",
                        evidence=line.strip()[:200],
                        severity="high",
                        confidence=0.6,
                        mitre_technique="T1057",
                    ))
                    break
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return results


def _check_iocs(iocs: Dict[str, List[str]], search_root: str = "/var/log") -> List[HuntResult]:
    """基于 IOC 搜索日志和文件系统。"""
    results = []
    all_indicators = (iocs.get("ips", []) + iocs.get("domains", [])
                      + iocs.get("hashes", []))

    if not all_indicators:
        return results

    log_dir = Path(search_root)
    if not log_dir.exists():
        return results

    # Safety: Windows uses single-level glob to avoid NTFS reparse point BSOD
    log_files = []
    log_iter = log_dir.rglob("*.log") if not IS_WINDOWS else log_dir.glob("*.log")
    for p in log_iter:
        if p.is_symlink():
            continue
        log_files.append(p)
        if len(log_files) >= 10:
            break
    txt_files = []
    txt_iter = log_dir.rglob("*.txt") if not IS_WINDOWS else log_dir.glob("*.txt")
    for p in txt_iter:
        if p.is_symlink():
            continue
        txt_files.append(p)
        if len(txt_files) >= 5:
            break
    for log_file in log_files + txt_files:
        try:
            content = log_file.read_text(encoding="utf-8", errors="replace")
            for ioc in all_indicators[:50]:  # limit to 50 IOCs
                if ioc in content:
                    count = content.count(ioc)
                    results.append(HuntResult(
                        finding_type="ioc_match",
                        description=f"IOC 命中: {ioc} ({count} 次)",
                        evidence=str(log_file),
                        severity="high" if count > 10 else "medium",
                        confidence=0.9,
                        mitre_technique="",
                    ))
        except (PermissionError, OSError, UnicodeDecodeError):
            continue

    return results


# -- Main hunt ----------------------------------------------------------------

def run_hunt(search_root: str = "/",
             iocs: Optional[Dict[str, List[str]]] = None) -> Dict[str, Any]:
    """运行全量威胁狩猎。

    Returns:
        {
            "total_findings": N,
            "findings": [HuntResult, ...],
            "by_type": {type: count, ...},
            "by_severity": {severity: count, ...},
        }
    """
    all_findings: List[HuntResult] = []

    # Persistence checks
    all_findings.extend(_check_persistence(search_root))

    # Network checks
    all_findings.extend(_check_network())

    # Process checks
    all_findings.extend(_check_processes())

    # IOC hunting
    if iocs:
        all_findings.extend(_check_iocs(iocs, f"{search_root}/var/log"))

    # Aggregate
    from collections import Counter
    type_dist = Counter(f.finding_type for f in all_findings)
    severity_dist = Counter(f.severity for f in all_findings)

    return {
        "total_findings": len(all_findings),
        "findings": [f.to_dict() for f in all_findings],
        "by_type": dict(type_dist),
        "by_severity": dict(severity_dist),
    }
