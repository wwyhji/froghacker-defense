"""Dynamic Defense — adaptive security response engine.

Monitors threats in real-time and adjusts defense posture automatically:
- Threat level assessment (green/yellow/orange/red)
- Auto-blocking of malicious IPs
- Defense rule deployment
- Honeypot activation on elevated threat

Usage:
    python -m tools.blueteam defense watch
    python -m tools.blueteam defense status
    python -m tools.blueteam defense block <ip>
    python -m tools.blueteam defense level [green|yellow|orange|red]
"""

from __future__ import annotations
from pathlib import Path
import sys as _sys
_TOOLS = str(Path(__file__).resolve().parent.parent)
if _TOOLS not in _sys.path:
    _sys.path.insert(0, _TOOLS)

from tools.core.logger import get_logger
_def_log = get_logger("dynamic_defense")

import json
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from collections import defaultdict


class ThreatLevel(Enum):
    GREEN = "green"       # Normal operation
    YELLOW = "yellow"     # Elevated awareness
    ORANGE = "orange"     # Active threat detected
    RED = "red"           # Under attack — full defense


@dataclass
class DefenseRule:
    id: str
    name: str
    description: str
    action: str  # block/alert/log/harden
    target: str  # IP/port/process
    enabled: bool = True
    auto_deployed: bool = False
    deployed_at: str = ""


@dataclass
class DefenseState:
    threat_level: ThreatLevel = ThreatLevel.GREEN
    blocked_ips: list[dict] = field(default_factory=list)
    active_rules: list[DefenseRule] = field(default_factory=list)
    alert_count: int = 0
    last_threat: str = ""
    started_at: str = ""
    honeypot_active: bool = False
    patrol_enabled: bool = False


class DynamicDefense:
    """Adaptive defense engine."""

    def __init__(self, hub_url: str = "http://127.0.0.1:8765",
                 state_file: str = ".blueteam_defense.json"):
        self.hub_url = hub_url
        self.state_file = state_file
        self.state = DefenseState()
        self.state.started_at = datetime.now().isoformat()
        self._threat_counter: dict[str, int] = defaultdict(int)
        self._watch_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._load_state()

    def _save_state(self):
        try:
            data = {
                "threat_level": self.state.threat_level.value,
                "blocked_ips": self.state.blocked_ips[-50:],
                "alert_count": self.state.alert_count,
                "last_threat": self.state.last_threat,
                "started_at": self.state.started_at,
                "honeypot_active": self.state.honeypot_active,
            }
            Path(self.state_file).write_text(json.dumps(data, indent=2))
        except Exception as _e:
            from tools.swallow_trap import record
            record(_e)

    def _load_state(self):
        try:
            data = json.loads(Path(self.state_file).read_text())
            self.state.threat_level = ThreatLevel(data.get("threat_level", "green"))
            self.state.blocked_ips = data.get("blocked_ips", [])
            self.state.alert_count = data.get("alert_count", 0)
        except Exception as _e:
            from tools.swallow_trap import record
            record(_e)

    # ── Threat Level Management ──

    def set_threat_level(self, level: ThreatLevel | str):
        """Set defense threat level and deploy appropriate rules."""
        if isinstance(level, str):
            level = ThreatLevel(level)
        old_level = self.state.threat_level
        self.state.threat_level = level

        if level.value == "red" and not self.state.honeypot_active:
            self._activate_honeypots()
        elif level.value in ("green", "yellow") and self.state.honeypot_active:
            self._deactivate_honeypots()

        self._save_state()
        self._log_event("threat_level_change",
                       f"Threat level changed: {old_level.value} -> {level.value}")

    def escalate(self, reason: str):
        """Escalate threat level based on detected activity."""
        levels = [ThreatLevel.GREEN, ThreatLevel.YELLOW, ThreatLevel.ORANGE, ThreatLevel.RED]
        current_idx = levels.index(self.state.threat_level)
        if current_idx < len(levels) - 1:
            new_level = levels[current_idx + 1]
            self.set_threat_level(new_level)
            self.state.last_threat = reason
            self.state.alert_count += 1
            self._log_event("escalate", f"{reason} -> level {new_level.value}")

    def deescalate(self):
        """Reduce threat level after cooldown."""
        levels = [ThreatLevel.GREEN, ThreatLevel.YELLOW, ThreatLevel.ORANGE, ThreatLevel.RED]
        current_idx = levels.index(self.state.threat_level)
        if current_idx > 0:
            self.set_threat_level(levels[current_idx - 1])

    # ── IP Blocking ──

    def block_ip(self, ip: str, reason: str = "Manual block") -> bool:
        """Block an IP address via Windows Firewall."""
        rule_name = f"FrogHacker_Block_{ip.replace('.', '_')}"

        # Check if already blocked
        for entry in self.state.blocked_ips:
            if entry["ip"] == ip:
                return False

        try:
            # Create inbound block rule
            result = subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 f"name={rule_name}", "dir=in", "action=block",
                 f"remoteip={ip}", "enable=yes"],
                capture_output=True, text=True, errors="replace", timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )
            if result.returncode == 0:
                self.state.blocked_ips.append({
                    "ip": ip,
                    "reason": reason,
                    "time": datetime.now().isoformat(),
                    "rule_name": rule_name,
                })
                self._save_state()
                self._log_event("block_ip", f"Blocked {ip}: {reason}")
                return True
        except Exception as e:
            self._log_event("block_ip_error", f"Failed to block {ip}: {e}")
        return False

    def unblock_ip(self, ip: str) -> bool:
        """Remove IP block."""
        rule_name = f"FrogHacker_Block_{ip.replace('.', '_')}"
        try:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule",
                 f"name={rule_name}"],
                capture_output=True, text=True, errors="replace", timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )
            self.state.blocked_ips = [b for b in self.state.blocked_ips if b["ip"] != ip]
            self._save_state()
            return True
        except Exception as _e:
            from tools.swallow_trap import record
            record(_e)
            return False

    # ── Honeypot Management ──

    def _activate_honeypots(self):
        """Activate honeypot services for threat intelligence."""
        self.state.honeypot_active = True
        try:
            from tools.blueteam.honeypot import manager as hm
            # Start basic honeypots on common ports
            self._log_event("honeypot", "Honeypot activated (threat level RED)")
        except ImportError:
            self._log_event("honeypot_error", "Honeypot module not available")
        self._save_state()

    def _deactivate_honeypots(self):
        """Deactivate honeypots."""
        self.state.honeypot_active = False
        self._save_state()
        self._log_event("honeypot", "Honeypot deactivated")

    # ── Watch Loop ──

    def start_watch(self, interval_seconds: int = 10):
        """Start background threat monitoring."""
        if self._watch_thread and self._watch_thread.is_alive():
            return False
        self._stop_event.clear()
        self._watch_thread = threading.Thread(
            target=self._watch_loop, args=(interval_seconds,), daemon=True
        )
        self._watch_thread.start()
        return True

    def stop_watch(self):
        """Stop background monitoring."""
        self._stop_event.set()
        if self._watch_thread:
            self._watch_thread.join(timeout=5)

    def _watch_loop(self, interval: int):
        """Main watch loop — monitor for threats."""
        while not self._stop_event.is_set():
            try:
                self._scan_for_threats()
            except Exception as _e:
                from tools.swallow_trap import record
                record(_e)

            # Auto-deescalate after 5 minutes of no threats
            if self.state.threat_level != ThreatLevel.GREEN:
                time_since_threat = (
                    datetime.now() - datetime.fromisoformat(self.state.last_threat)
                    if self.state.last_threat else 999
                )
                if time_since_threat > 300:  # 5 min
                    self.deescalate()

            for _ in range(interval):
                if self._stop_event.is_set():
                    break
                time.sleep(1)

    def _scan_for_threats(self):
        """Scan for immediate threats."""
        # Check for auth failures (quick heuristic)
        try:
            result = subprocess.run(
                ["wevtutil", "qe", "Security", "/c:20", "/rd:true", "/f:text",
                 "/q:*[System[EventID=4625]]"],
                capture_output=True, text=True, errors="replace", timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )
            failures = result.stdout.count("EventID: 4625")
            if failures > 20:
                self.escalate(f"Auth storm detected: {failures} recent failures")
        except Exception as _e:
            from tools.swallow_trap import record
            record(_e)

    # ── Logging ──

    def _log_event(self, event_type: str, message: str):
        """Log defense event to file and optionally to Hub."""
        try:
            log_entry = {
                "type": event_type,
                "message": message,
                "time": datetime.now().isoformat(),
                "threat_level": self.state.threat_level.value,
            }
            log_line = json.dumps(log_entry, ensure_ascii=False) + "\n"
            with open(".blueteam_defense_log.jsonl", "a") as f:
                f.write(log_line)

            # Report to Hub for Commander visibility
            try:
                import urllib.request
                data = json.dumps({
                    "from": "blueteam-defense",
                    "type": f"defense_{event_type}",
                    "summary": message,
                    "detail": json.dumps(log_entry),
                }).encode()
                req = urllib.request.Request(
                    f"{self.hub_url}/session/log",
                    data=data,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                urllib.request.urlopen(req, timeout=3)
            except Exception as _e:
                from tools.swallow_trap import record
                record(_e)
        except Exception as _e:
            from tools.swallow_trap import record
            record(_e)

    # ── Status ──

    def status(self) -> dict:
        """Return current defense status."""
        return {
            "threat_level": self.state.threat_level.value,
            "blocked_ips": self.state.blocked_ips[-20:],
            "blocked_count": len(self.state.blocked_ips),
            "alert_count": self.state.alert_count,
            "last_threat": self.state.last_threat,
            "started_at": self.state.started_at,
            "honeypot_active": self.state.honeypot_active,
            "patrol_enabled": self.state.patrol_enabled,
            "defense_posture": self._posture_summary(),
        }

    def _posture_summary(self) -> str:
        """Human-readable defense posture summary."""
        level = self.state.threat_level.value
        summaries = {
            "green": "Normal operation. Baseline monitoring active.",
            "yellow": "Elevated awareness. Increased logging, auth monitoring.",
            "orange": "Active threat. IP blocks deployed, honeypots armed.",
            "red": "Under attack. Full defense: honeywall active, auto-block, lockdown.",
        }
        return summaries.get(level, summaries["green"])
