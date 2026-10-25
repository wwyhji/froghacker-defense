"""Incident Responder — 告警处置闭环.

把检测告警 + 行为链阶段映射到处置动作(封IP/升级威胁等级/记录案例),
闭合「检测 → 响应 → 案例」的闭环。

决策规则:
  - 行为链到 lateral/c2/exfil/impact → 最高响应(封IP + 威胁等级 red)
  - severity critical → 封IP
  - severity high/medium → 升级威胁等级
  - 其他 → 仅记录

Usage:
    from tools.blueteam.responder import IncidentResponder
    r = IncidentResponder()
    result = r.respond(alert, chain_place="lateral")
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from tools.blueteam.dynamic_defense import DynamicDefense, ThreatLevel


# 行为链高危阶段 → 最高响应
CRITICAL_CHAIN_PLACES = {"lateral", "c2", "exfil", "impact"}

# severity → 默认动作
ACTION_BY_SEVERITY = {
    "critical": "block_ip",
    "high": "escalate",
    "medium": "escalate",
    "low": "log",
    "info": "log",
}


class IncidentResponder:
    """告警处置闭环引擎。"""

    def __init__(self, case_file: str = ".blueteam_cases.jsonl"):
        self.defense = DynamicDefense()
        self.case_file = case_file

    # ── 决策 ────────────────────────────────────────────────────

    def decide(self, alert, chain_place: str = "") -> str:
        """决策:根据告警 severity + 行为链阶段决定处置动作。"""
        sev = self._get(alert, "severity", "")
        if chain_place in CRITICAL_CHAIN_PLACES:
            return "block_and_lockdown"
        return ACTION_BY_SEVERITY.get(sev, "log")

    # ── 执行 ────────────────────────────────────────────────────

    def respond(self, alert, chain_place: str = "") -> Dict:
        """执行处置动作并记录案例。"""
        action = self.decide(alert, chain_place)
        sev = self._get(alert, "severity", "")
        atype = self._get(alert, "attack_type", "")
        src_ip = self._extract_source_ip(alert)

        result = {"action": action, "executed": False, "detail": ""}

        if action == "block_and_lockdown":
            self.defense.set_threat_level(ThreatLevel.RED)
            result["detail"] = "threat_level=red"
            if src_ip:
                ok = self.defense.block_ip(src_ip, reason=f"behavior_chain:{chain_place}")
                result["executed"] = ok
                result["detail"] += f", block_ip={src_ip}:{'ok' if ok else 'failed(need admin)'}"

        elif action == "block_ip":
            if src_ip:
                ok = self.defense.block_ip(src_ip, reason=f"severity:{sev}")
                result["executed"] = ok
                result["detail"] = f"block_ip={src_ip}:{'ok' if ok else 'failed(need admin)'}"

        elif action == "escalate":
            self.defense.escalate(f"{atype} (severity={sev})")
            result["executed"] = True
            result["detail"] = f"escalated to {self.defense.state.threat_level.value}"

        else:
            result["detail"] = "logged only"

        self._record_case(alert, action, result)
        return result

    # ── 案例管理 ────────────────────────────────────────────────

    def _record_case(self, alert, action: str, result: Dict) -> None:
        """记录处置案例。"""
        entry = {
            "time": datetime.now().isoformat(),
            "attack_type": self._get(alert, "attack_type", ""),
            "severity": self._get(alert, "severity", ""),
            "action": action,
            "executed": result["executed"],
            "detail": result["detail"],
        }
        with open(self.case_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def cases(self, n: int = 20) -> List[Dict]:
        """读取最近处置案例。"""
        p = Path(self.case_file)
        if not p.exists():
            return []
        out: List[Dict] = []
        for line in p.read_text(encoding="utf-8").splitlines()[-n:]:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out

    # ── 辅助 ────────────────────────────────────────────────────

    @staticmethod
    def _get(alert, key: str, default=""):
        """兼容 DetectionAlert 对象和 dict。"""
        if isinstance(alert, dict):
            return alert.get(key, default)
        return getattr(alert, key, default)

    def _extract_source_ip(self, alert) -> str:
        """从告警事件里尽力提取源 IP。"""
        event = self._get(alert, "event", {})
        if not isinstance(event, dict):
            event = {}
        for key in ("source_ip", "src_ip", "remote_ip", "remote_addr", "ip", "client"):
            v = event.get(key)
            if not v and isinstance(alert, dict):
                v = alert.get(key)
            if v:
                return str(v).split(":")[0]  # 去掉端口
        return ""


__all__ = ["IncidentResponder", "CRITICAL_CHAIN_PLACES", "ACTION_BY_SEVERITY"]
