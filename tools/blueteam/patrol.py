"""Blue Team Patrol — automated periodic security scanning.

Patrol runs a configurable loop of security checks on a schedule,
feeding findings into the Hub for Commander review.

Usage:
    python -m tools.blueteam patrol start --interval 300
    python -m tools.blueteam patrol status
    python -m tools.blueteam patrol stop
"""

from __future__ import annotations

from pathlib import Path
import sys as _sys
_TOOLS = str(Path(__file__).resolve().parent.parent)
if _TOOLS not in _sys.path:
    _sys.path.insert(0, _TOOLS)

from tools.core.logger import get_logger
_patrol_log = get_logger("patrol")

import json
import os
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable


@dataclass
class PatrolCheck:
    name: str
    description: str
    severity: str  # critical/high/medium/low/info
    category: str  # network/process/file/config/log
    check_fn_name: str  # name of check function in registry


@dataclass
class PatrolFinding:
    check_name: str
    severity: str
    category: str
    summary: str
    detail: str
    time: str
    remediation: str = ""


@dataclass
class PatrolState:
    running: bool = False
    interval_seconds: int = 300
    last_run: str = ""
    next_run: str = ""
    total_checks: int = 0
    total_findings: int = 0
    checks_passed: int = 0
    checks_failed: int = 0
    current_check: str = ""
    findings: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ── Check Registry ──

class PatrolEngine:
    """Runs patrol checks and reports findings."""

    def __init__(self, hub_url: str = "http://127.0.0.1:8765", state_file: str = ".blueteam_patrol.json"):
        self.hub_url = hub_url
        self.state_file = state_file
        self.state = PatrolState()
        self._checks: list[PatrolCheck] = []
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._register_checks()

    def _register_checks(self):
        """Register all patrol checks."""
        self._checks = [
            PatrolCheck("open_ports", "Scan for unexpected open ports",
                       "medium", "network", "check_open_ports"),
            PatrolCheck("listening_services", "Check for suspicious listening services",
                       "high", "network", "check_listening_services"),
            PatrolCheck("firewall_status", "Verify firewall is active",
                       "critical", "config", "check_firewall"),
            PatrolCheck("disk_space", "Check available disk space",
                       "low", "config", "check_disk_space"),
            PatrolCheck("suspicious_processes", "Scan for suspicious running processes",
                       "high", "process", "check_processes"),
            PatrolCheck("recent_errors", "Check system event log for recent errors",
                       "medium", "log", "check_event_log"),
            PatrolCheck("auth_failures", "Check for repeated authentication failures",
                       "high", "log", "check_auth_failures"),
            PatrolCheck("file_integrity", "Verify critical file hashes",
                       "medium", "file", "check_file_integrity"),
            PatrolCheck("service_health", "Check critical Windows services",
                       "high", "config", "check_services"),
        ]

    # ── Check implementations ──

    def _check_open_ports(self) -> PatrolFinding | None:
        """Check for unexpected listening ports."""
        expected = {22, 80, 443, 3000, 8765, 3389, 445, 135}
        found = set()
        try:
            import socket as s
            for port in [22, 80, 443, 135, 445, 1080, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8765, 9000, 9090, 27017, 3000]:
                sock = s.socket(s.AF_INET, s.SOCK_STREAM)
                sock.settimeout(0.3)
                result = sock.connect_ex(("127.0.0.1", port))
                if result == 0:
                    found.add(port)
                sock.close()
        except Exception as _e:
            from tools.swallow_trap import record
            record(_e)

        unexpected = found - expected
        if unexpected:
            return PatrolFinding(
                "open_ports", "medium", "network",
                f"Unexpected open ports: {sorted(unexpected)}",
                f"Found unexpected listening ports: {sorted(unexpected)}. Expected: {sorted(expected)}.",
                time=datetime.now().isoformat(),
                remediation="Review services on these ports. Disable if not needed.",
            )
        return None

    def _check_listening_services(self) -> PatrolFinding | None:
        """Check for suspicious listening services."""
        suspicious = []
        try:
            result = subprocess.run(
                ["netstat", "-ano"], capture_output=True, text=True, errors="replace", timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )
            lines = result.stdout.split("\n")
            for line in lines:
                if "LISTENING" in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        addr = parts[1] if len(parts) > 1 else ""
                        if ":0.0.0.0:" not in addr and "127.0.0.1" not in addr.lower():
                            pass  # external listening is normal for servers
                        if any(p in addr for p in [":4444", ":1337", ":31337", ":6666", ":9999"]):
                            suspicious.append(addr)
        except Exception as _e:
            from tools.swallow_trap import record
            record(_e)

        if suspicious:
            return PatrolFinding(
                "listening_services", "high", "network",
                f"Suspicious listening ports detected: {suspicious}",
                f"Ports matching known malicious signatures: {suspicious}",
                time=datetime.now().isoformat(),
                remediation="Investigate these services immediately. Check process ownership.",
            )
        return None

    def _check_firewall(self) -> PatrolFinding | None:
        """Verify Windows Firewall is active."""
        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles", "state"],
                capture_output=True, text=True, errors="replace", timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )
            if "OFF" in result.stdout:
                return PatrolFinding(
                    "firewall_status", "critical", "config",
                    "Windows Firewall is OFF",
                    result.stdout.strip(),
                    time=datetime.now().isoformat(),
                    remediation="Enable Windows Firewall immediately: netsh advfirewall set allprofiles state on",
                )
        except Exception as e:
            return PatrolFinding(
                "firewall_status", "critical", "config",
                "Cannot verify firewall status",
                str(e),
                time=datetime.now().isoformat(),
                remediation="Check firewall configuration manually.",
            )
        return None

    def _check_disk_space(self) -> PatrolFinding | None:
        """Check available disk space."""
        try:
            if sys.platform == "win32":
                import ctypes
                free = ctypes.c_ulonglong(0)
                total = ctypes.c_ulonglong(0)
                ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                    "D:\\", ctypes.byref(free), ctypes.byref(total), None
                )
                free_gb = free.value / (1024 ** 3)
                if free_gb < 10:
                    return PatrolFinding(
                        "disk_space", "low", "config",
                        f"Low disk space: {free_gb:.1f} GB free on D:",
                        f"Only {free_gb:.1f} GB available.",
                        time=datetime.now().isoformat(),
                        remediation="Clean up temporary files and old logs.",
                    )
        except Exception as _e:
            from tools.swallow_trap import record
            record(_e)
        return None

    def _check_processes(self) -> PatrolFinding | None:
        """Check for suspicious processes."""
        suspicious_names = ["mimikatz", "psexec", "nc.exe", "ncat", "procdump",
                           "lsass_dump", "hashdump", "crackmapexec", "powersploit"]
        found = []
        try:
            result = subprocess.run(
                ["tasklist", "/fo", "csv"], capture_output=True, text=True, errors="replace", timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )
            for name in suspicious_names:
                if name.lower() in result.stdout.lower():
                    found.append(name)
        except Exception as _e:
            from tools.swallow_trap import record
            record(_e)

        if found:
            return PatrolFinding(
                "suspicious_processes", "high", "process",
                f"Suspicious processes detected: {found}",
                f"Process names matching known attack tools: {found}",
                time=datetime.now().isoformat(),
                remediation="Investigate these processes immediately. Consider containment.",
            )
        return None

    def _check_event_log(self) -> PatrolFinding | None:
        """Check Windows Event Log for recent errors (last hour)."""
        try:
            result = subprocess.run(
                ["wevtutil", "qe", "System", "/c:50", "/rd:true", "/f:text"],
                capture_output=True, text=True, errors="replace", timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )
            error_count = result.stdout.count("Level: 2")  # Error level
            critical_count = result.stdout.count("Level: 1")  # Critical level
            if critical_count > 0 or error_count > 20:
                return PatrolFinding(
                    "recent_errors", "medium", "log",
                    f"System errors: {critical_count} critical, {error_count} error",
                    f"High error rate detected in System log.",
                    time=datetime.now().isoformat(),
                    remediation="Review Event Viewer for details on recent errors.",
                )
        except Exception as _e:
            from tools.swallow_trap import record
            record(_e)
        return None

    def _check_auth_failures(self) -> PatrolFinding | None:
        """Check for brute-force auth attempts."""
        try:
            result = subprocess.run(
                ["wevtutil", "qe", "Security", "/c:100", "/rd:true", "/f:text",
                 "/q:*[System[EventID=4625]]"],  # Failed logon
                capture_output=True, text=True, errors="replace", timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )
            failures = result.stdout.count("EventID: 4625")
            if failures > 10:
                return PatrolFinding(
                    "auth_failures", "high", "log",
                    f"Brute force suspected: {failures} recent auth failures",
                    f"EventID 4625 count: {failures} in recent Security log.",
                    time=datetime.now().isoformat(),
                    remediation="Review source IPs. Consider temporary account lockout.",
                )
        except Exception as _e:
            from tools.swallow_trap import record
            record(_e)
        return None

    def _check_file_integrity(self) -> PatrolFinding | None:
        """Detect tampering of the hosts file (static resolution to external IPs).

        A common MITM / DNS-hijack persistence trick is adding a static
        mapping in /etc/hosts (or the Windows equivalent). Flag any external
        IPv4 static entry as suspicious.
        """
        hosts_paths = ([r"C:\Windows\System32\drivers\etc\hosts"]
                       if sys.platform == "win32" else ["/etc/hosts"])
        try:
            for hp in hosts_paths:
                if not os.path.exists(hp):
                    continue
                with open(hp, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split()
                        if len(parts) < 2:
                            continue
                        ip = parts[0]
                        host = parts[1]
                        # External IPv4 static mapping (non-local) is suspicious
                        if (ip.count(".") == 3
                                and all(p.isdigit() for p in ip.split("."))
                                and not ip.startswith("127.")
                                and ip != "0.0.0.0"):
                            return PatrolFinding(
                                "file_integrity", "medium", "config",
                                f"Suspicious hosts entry: {ip} -> {host}",
                                f"Static host resolution to external IP {ip} in {hp}.",
                                time=datetime.now().isoformat(),
                                remediation="Verify the hosts file has not been tampered.",
                            )
        except Exception as _e:
            from tools.swallow_trap import record
            record(_e)
        return None

    def _check_services(self) -> PatrolFinding | None:
        """Check critical Windows services are running."""
        critical = {"WinDefend": "Windows Defender", "MpsSvc": "Windows Firewall",
                     "wscsvc": "Security Center"}
        stopped = []
        try:
            result = subprocess.run(
                ["sc", "query"], capture_output=True, text=True, errors="replace", timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )
            for svc, name in critical.items():
                if svc in result.stdout:
                    if "STOPPED" in result.stdout[result.stdout.find(svc):result.stdout.find(svc)+500]:
                        stopped.append(name)
        except Exception as _e:
            from tools.swallow_trap import record
            record(_e)

        if stopped:
            return PatrolFinding(
                "service_health", "high", "config",
                f"Critical services stopped: {stopped}",
                f"Security services not running: {stopped}",
                time=datetime.now().isoformat(),
                remediation="Restart services: sc start <service_name>",
            )
        return None

    # ── Run checks ──

    def run_single_check(self, check: PatrolCheck) -> PatrolFinding | None:
        """Execute a single patrol check."""
        fn = getattr(self, f"_{check.check_fn_name}", None)
        if fn is None:
            return None
        try:
            return fn()
        except Exception as e:
            self.state.errors.append(f"{check.name}: {e}")
            return None

    def run_all_checks(self) -> list[PatrolFinding]:
        """Run all registered patrol checks."""
        self.state.total_checks = len(self._checks)
        self.state.checks_passed = 0
        self.state.checks_failed = 0
        findings = []

        for check in self._checks:
            self.state.current_check = check.name
            finding = self.run_single_check(check)
            if finding:
                findings.append(finding)
                self.state.checks_failed += 1
            else:
                self.state.checks_passed += 1

        self.state.last_run = datetime.now().isoformat()
        self.state.total_findings += len(findings)
        self.state.findings = [{
            "check": f.check_name,
            "severity": f.severity,
            "category": f.category,
            "summary": f.summary,
            "detail": f.detail,
            "time": f.time,
            "remediation": f.remediation,
        } for f in findings]

        # Report to Hub if available
        self._report_to_hub(findings)
        self._save_state()
        return findings

    def _report_to_hub(self, findings: list[PatrolFinding]):
        """Post critical/high findings to Hub for Commander review."""
        for f in findings:
            if f.severity in ("critical", "high"):
                try:
                    import urllib.request
                    data = json.dumps({
                        "from": "blueteam-patrol",
                        "type": f"patrol_{f.check_name}",
                        "summary": f.summary,
                        "detail": f.detail,
                    }).encode()
                    req = urllib.request.Request(
                        f"{self.hub_url}/findings",
                        data=data,
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    )
                    urllib.request.urlopen(req, timeout=5)
                except Exception as _e:
                    from tools.swallow_trap import record
                    record(_e)

    def _save_state(self):
        """Persist patrol state to file."""
        try:
            state_dict = {
                "running": self.state.running,
                "interval_seconds": self.state.interval_seconds,
                "last_run": self.state.last_run,
                "next_run": self.state.next_run,
                "total_checks": self.state.total_checks,
                "total_findings": self.state.total_findings,
                "checks_passed": self.state.checks_passed,
                "checks_failed": self.state.checks_failed,
                "findings": self.state.findings[-50:],  # keep last 50
                "current_check": self.state.current_check,
            }
            Path(self.state_file).write_text(json.dumps(state_dict, indent=2))
        except Exception as _e:
            from tools.swallow_trap import record
            record(_e)

    def load_state(self) -> dict:
        """Load persisted patrol state."""
        try:
            return json.loads(Path(self.state_file).read_text())
        except Exception:
            return {}

    def start_loop(self, interval_seconds: int = 300):
        """Start patrol loop in background thread."""
        if self._thread and self._thread.is_alive():
            return False

        self.state.interval_seconds = interval_seconds
        self.state.running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return True

    def stop_loop(self):
        """Stop patrol loop."""
        self._stop_event.set()
        self.state.running = False
        if self._thread:
            self._thread.join(timeout=5)

    def _loop(self):
        """Main patrol loop."""
        while not self._stop_event.is_set():
            self.state.next_run = (
                datetime.now().timestamp() + self.state.interval_seconds
            )
            try:
                self.run_all_checks()
            except Exception as e:
                self.state.errors.append(f"patrol_loop: {e}")

            # Sleep in 1s increments to allow clean shutdown
            for _ in range(self.state.interval_seconds):
                if self._stop_event.is_set():
                    break
                time.sleep(1)

    def status(self) -> dict:
        """Return current patrol status."""
        state = self.load_state()
        return {
            "running": self.state.running,
            "interval_seconds": self.state.interval_seconds,
            "last_run": state.get("last_run", self.state.last_run),
            "total_checks": state.get("total_checks", 0),
            "total_findings": state.get("total_findings", 0),
            "checks_passed": state.get("checks_passed", 0),
            "checks_failed": state.get("checks_failed", 0),
            "current_check": self.state.current_check,
            "recent_findings": state.get("findings", [])[:10],
            "checks": [c.name for c in self._checks],
        }
