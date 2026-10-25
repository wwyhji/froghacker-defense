#!/usr/bin/env python3
"""
Unified logging framework for FrogHacker.
====================

Provides get_logger(name) for module-level structured logging with
dual output: console (human-readable, colored) and file (JSON lines).

Replaces scattered print() calls with consistent, level-controlled output.

Usage:
    from tools.core.logger import get_logger

    logger = get_logger(__name__)
    logger.info("task_started", task_id="T001")
    logger.error("tool_failed", tool="nmap", exit_code=1)
    logger.debug("http_request", url="...", status=200)

Configuration (env vars):
    FH_LOG_LEVEL / LOG_LEVEL  — DEBUG|INFO|WARNING|ERROR|CRITICAL (default: INFO)
    FH_LOG_DIR                — enable JSON file output to this directory
    FH_LOG_JSON=1             — force JSON output (without dir, writes to stderr as JSON)
    FH_LOG_SILENT=1           — suppress console output
"""

from __future__ import annotations

import json
import os
import re
import sys
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

# ── Secret redaction patterns ─────────────────────────────────────────────
# Match common API key/token/password formats
_SECRET_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'sk-[a-zA-Z0-9]{20,}'), 'sk-***'),
    (re.compile(r'sk-ant-[a-zA-Z0-9_\-]{20,}'), 'sk-ant-***'),
    (re.compile(r'AIza[0-9A-Za-z_\-]{25,}'), 'AIza***'),
    (re.compile(r'xox[bpras]-[0-9A-Za-z_\-]{10,}'), 'xox-***'),
    (re.compile(r'(?:api_key|apikey|api-secret|secret_key|password|passwd|token)\s*[:=]\s*[\'"][^\'"]+[\'"]', re.IGNORECASE), lambda m: m.group(0).split(':', 1)[0].split('=', 1)[0] + '="***"'),
    (re.compile(r'(?:AKIA|ASIA)[A-Z0-9]{16,}'), 'AKIA***'),
    (re.compile(r'ghp_[a-zA-Z0-9]{30,}'), 'ghp_***'),
    (re.compile(r'gho_[a-zA-Z0-9]{30,}'), 'gho_***'),
    (re.compile(r'ghu_[a-zA-Z0-9]{30,}'), 'ghu_***'),
    (re.compile(r'ghs_[a-zA-Z0-9]{30,}'), 'ghs_***'),
    (re.compile(r'glpat-[a-zA-Z0-9_\-]{20,}'), 'glpat-***'),
    (re.compile(r'(?:eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,})'), 'JWT***'),
]

# ── Log levels ──────────────────────────────────────────────────────────

CRITICAL = 50
ERROR = 40
WARNING = 30
INFO = 20
DEBUG = 10
NOTSET = 0

_LEVEL_NAMES: Dict[int, str] = {
    CRITICAL: "CRITICAL",
    ERROR: "ERROR",
    WARNING: "WARNING",
    INFO: "INFO",
    DEBUG: "DEBUG",
}

_LEVEL_MAP: Dict[str, int] = {
    "CRITICAL": CRITICAL,
    "ERROR": ERROR,
    "WARNING": WARNING,
    "INFO": INFO,
    "DEBUG": DEBUG,
}

# ANSI colors for console output
_COLORS: Dict[int, str] = {
    CRITICAL: "\033[1;35m",  # bold magenta
    ERROR: "\033[1;31m",     # bold red
    WARNING: "\033[1;33m",   # bold yellow
    INFO: "\033[0;36m",      # cyan
    DEBUG: "\033[0;37m",     # gray
}
_RESET = "\033[0m"

# ── Global state ────────────────────────────────────────────────────────

_global_level: int = INFO
_global_lock = threading.Lock()
_global_log_dir: Optional[Path] = None
_console_enabled: bool = True
_json_to_console: bool = False
_json_to_file: bool = False
_initialized: bool = False


# ── Public config API ───────────────────────────────────────────────────

def set_level(level: int) -> None:
    """Set global log level. Messages below this level are suppressed."""
    global _global_level
    _global_level = level


def get_level() -> int:
    """Get current global log level."""
    return _global_level


def init_from_env() -> None:
    """Configure logging from environment variables. Called automatically on first import.
    Safe to call multiple times — reads env vars fresh each time.

    Env vars:
        FH_LOG_LEVEL / LOG_LEVEL  — "DEBUG"|"INFO"|"WARNING"|"ERROR"|"CRITICAL"
        FH_LOG_DIR                — path to write daily JSON log files
        FH_LOG_JSON=1             — emit JSON to stderr instead of colored text
        FH_LOG_SILENT=1           — suppress all console output
    """
    global _global_level, _global_log_dir, _console_enabled
    global _json_to_console, _json_to_file, _initialized

    # Log level
    level_name = os.environ.get("FH_LOG_LEVEL", os.environ.get("LOG_LEVEL", "INFO"))
    _global_level = _LEVEL_MAP.get(level_name.upper(), INFO)

    # JSON file output
    log_dir = os.environ.get("FH_LOG_DIR", "")
    if log_dir:
        _global_log_dir = Path(log_dir)
        _json_to_file = True

    # JSON to console (machine-readable mode)
    if os.environ.get("FH_LOG_JSON", "") == "1":
        _json_to_console = True

    # Silent mode
    if os.environ.get("FH_LOG_SILENT", "") == "1":
        _console_enabled = False

    _initialized = True


def configure(
    level: int = INFO,
    log_dir: Optional[str] = None,
    json_mode: bool = False,
    silent: bool = False,
) -> None:
    """Programmatic configuration. Safe to call multiple times."""
    global _global_level, _global_log_dir, _json_to_console
    global _json_to_file, _console_enabled, _initialized

    _global_level = level
    _initialized = True

    if log_dir:
        _global_log_dir = Path(log_dir)
        _json_to_file = True

    _json_to_console = json_mode
    _console_enabled = not silent


# ── Logger class ────────────────────────────────────────────────────────

class Logger:
    """Module-level structured logger.

    Supports key=value extras on every call for structured context:
        logger.info("tool_done", tool="nmap", exit_code=0, duration_ms=123)

    Output modes (detected automatically):
        Console:  colored human-readable text to stderr
        JSON:     single-line JSON objects to stderr (FH_LOG_JSON=1)
        File:     JSON objects to daily-rotated file (FH_LOG_DIR set)
    """

    __slots__ = ("name",)

    def __init__(self, name: str) -> None:
        self.name = name

    # ── Public log methods ───────────────────────────────────────────

    def debug(self, msg: str, **kwargs: Any) -> None:
        self._emit(DEBUG, msg, kwargs)

    def info(self, msg: str, **kwargs: Any) -> None:
        self._emit(INFO, msg, kwargs)

    def warning(self, msg: str, **kwargs: Any) -> None:
        self._emit(WARNING, msg, kwargs)

    def error(self, msg: str, **kwargs: Any) -> None:
        self._emit(ERROR, msg, kwargs)

    def critical(self, msg: str, **kwargs: Any) -> None:
        self._emit(CRITICAL, msg, kwargs)

    # ── Convenience: tool lifecycle ──────────────────────────────────

    def tool_start(self, tool: str, **kwargs: Any) -> None:
        """Log tool invocation start."""
        self.info("tool_start", tool=tool, **kwargs)

    def tool_end(self, tool: str, exit_code: int = 0, duration_ms: int = 0, **kwargs: Any) -> None:
        """Log tool invocation result."""
        if exit_code != 0:
            self.error("tool_end", tool=tool, exit_code=exit_code, duration_ms=duration_ms, **kwargs)
        else:
            self.info("tool_end", tool=tool, exit_code=exit_code, duration_ms=duration_ms, **kwargs)

    def agent_event(self, event: str, **kwargs: Any) -> None:
        """Log an agent lifecycle event."""
        self.info(f"agent_{event}", **kwargs)

    # ── Internal ────────────────────────────────────────────────────

    def _emit(self, level: int, msg: str, kwargs: Dict[str, Any]) -> None:
        if level < _global_level:
            return

        # Redact secrets in log output
        kwargs = _redact_kwargs(kwargs)
        msg = _redact_secrets(msg)

        ts = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        level_name = _LEVEL_NAMES.get(level, "?")

        # Console / stderr output
        if _console_enabled:
            if _json_to_console:
                self._write_json_line(sys.stderr, level_name, msg, ts, kwargs)
            else:
                self._write_console(level, level_name, msg, ts, kwargs)

        # File output (JSON only)
        if _json_to_file and _global_log_dir:
            self._write_file_json(level_name, msg, ts, kwargs)

    def _write_console(self, level: int, level_name: str, msg: str, ts: str, kwargs: Dict[str, Any]) -> None:
        color = _COLORS.get(level, "")
        parts = [f"{ts} [{level_name}] {self.name}: {msg}"]
        if kwargs:
            extras = " ".join(f"{k}={v}" for k, v in kwargs.items())
            parts.append(f"  {extras}")
        line = " ".join(parts)
        try:
            print(f"{color}{line}{_RESET}", file=sys.stderr)
        except Exception as _e:
            from tools.swallow_trap import record
            record(_e)

    def _write_json_line(self, stream, level_name: str, msg: str, ts: str, kwargs: Dict[str, Any]) -> None:
        entry: Dict[str, Any] = {
            "ts": ts,
            "level": level_name,
            "logger": self.name,
            "msg": msg,
        }
        entry.update(kwargs)
        try:
            stream.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
            stream.flush()
        except Exception as _e:
            from tools.swallow_trap import record
            record(_e)

    def _write_file_json(self, level_name: str, msg: str, ts: str, kwargs: Dict[str, Any]) -> None:
        assert _global_log_dir is not None
        today = datetime.now().strftime("%Y-%m-%d")
        fpath = _global_log_dir / f"fh_{today}.jsonl"
        with _global_lock:
            try:
                fpath.parent.mkdir(parents=True, exist_ok=True)
                with open(fpath, "a", encoding="utf-8") as f:
                    entry: Dict[str, Any] = {
                        "ts": ts,
                        "level": level_name,
                        "logger": self.name,
                        "msg": msg,
                    }
                    entry.update(kwargs)
                    f.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
            except Exception as _e:
                from tools.swallow_trap import record
                record(_e)


# ── Logger registry ─────────────────────────────────────────────────────

_loggers: Dict[str, Logger] = {}
_logger_lock = threading.Lock()


def get_logger(name: str) -> Logger:
    """Get or create a Logger by name (typically __name__).

    Usage:
        from tools.core.logger import get_logger
        logger = get_logger(__name__)
        logger.info("task_done", count=42)
    """
    with _logger_lock:
        if name not in _loggers:
            _loggers[name] = Logger(name)
        return _loggers[name]


# ── Auto-init on import ─────────────────────────────────────────────────

init_from_env()


# ── Secret redaction ──────────────────────────────────────────────────────

def _redact_secrets(text: str) -> str:
    """Redact known secret patterns from a string. Returns sanitized copy."""
    for pattern, replacement in _SECRET_PATTERNS:
        if callable(replacement):
            text = pattern.sub(replacement, text)
        else:
            text = pattern.sub(replacement, text)
    return text


def _redact_kwargs(kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """Redact sensitive values from log kwargs. Returns sanitized copy."""
    if not kwargs:
        return kwargs
    sensitive_keys = {"api_key", "apikey", "secret", "password", "passwd",
                      "token", "credential", "auth_token", "access_key",
                      "private_key", "signing_key", "encryption_key"}
    result = {}
    for k, v in kwargs.items():
        if isinstance(k, str) and any(sk in k.lower() for sk in sensitive_keys):
            result[k] = "***"
        elif isinstance(v, str):
            result[k] = _redact_secrets(v)
        elif isinstance(v, (int, float, bool, type(None))):
            result[k] = v
        else:
            result[k] = str(v)  # Don't recurse into nested structures
    return result


# ── Audit logger ──────────────────────────────────────────────────────────

_AUDIT_LOGGER = Logger("audit")


def audit(event: str, **kwargs: Any) -> None:
    """Write a security-audit event with mandatory fields.

    Usage:
        from tools.core.logger import audit
        audit("threat_level_change", old="green", new="yellow", reason="auth_storm")
        audit("worker_restart", worker_id=3, reason="crash")
        audit("ip_blocked", ip="10.0.0.5", reason="brute_force_attempt")
    """
    kwargs["_audit"] = True
    _AUDIT_LOGGER.warning(event, **kwargs)
