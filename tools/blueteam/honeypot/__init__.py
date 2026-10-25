"""蜜罐子模块 — 部署、检测、分析、管理。"""

from tools.blueteam.honeypot.deploy import (
    HoneypotConfig, HoneypotInstance, deploy_honeypot, HONEYPOT_TYPES,
)
from tools.blueteam.honeypot.detect import (
    detect_honeypot, is_honeypot, HONEYPOT_SIGNATURES,
)
from tools.blueteam.honeypot.analyze import (
    AttackLog, analyze_captures, extract_iocs, ATTACK_PATTERNS,
)
from tools.blueteam.honeypot.manager import (
    HoneypotManager, list_honeypots, stop_honeypot,
)

__all__ = [
    "HoneypotConfig", "HoneypotInstance", "deploy_honeypot", "HONEYPOT_TYPES",
    "detect_honeypot", "is_honeypot", "HONEYPOT_SIGNATURES",
    "AttackLog", "analyze_captures", "extract_iocs", "ATTACK_PATTERNS",
    "HoneypotManager", "list_honeypots", "stop_honeypot",
]
