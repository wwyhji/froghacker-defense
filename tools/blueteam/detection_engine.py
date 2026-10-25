"""Detection engine — 动态加载所有 defense 检测规则并执行事件检测.

这是三端共生闭环的防御落地：CrossFeed 生成的 detect_*.py 规则不再是死代码，
由 DetectionEngine 统一加载，对事件流做多特征匹配，输出结构化告警。

Usage:
    engine = DetectionEngine()
    alerts = engine.scan({"event_code": "4662", "raw": "DRSUAPI replication"})
    for a in alerts:
        print(a.to_dict())
"""

from __future__ import annotations

import glob
import importlib
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

TOOLS_DIR = Path(__file__).resolve().parent.parent


@dataclass
class DetectionAlert:
    """一条检测告警。"""
    attack_type: str
    domain: str
    severity: str
    action: str
    recommendations: List[str]
    event: dict
    rule_module: str = ""

    def to_dict(self) -> dict:
        return {
            "attack_type": self.attack_type,
            "domain": self.domain,
            "severity": self.severity,
            "action": self.action,
            "recommendations": self.recommendations,
            "event": self.event,
            "rule_module": self.rule_module,
        }


class DetectionEngine:
    """加载所有 defense/detect_*.py 规则，对事件执行检测。"""

    def __init__(self, tools_dir: Optional[Path] = None):
        self.tools_dir = tools_dir or TOOLS_DIR
        # attack_type → {"signature", "detect", "respond", "module"}
        self._rules: Dict[str, Dict[str, Any]] = {}
        self._load_failures: List[str] = []
        self._load_rules()

    # -- 规则发现与加载 -------------------------------------------------------

    def _discover_modules(self) -> List[str]:
        """发现所有 detect 规则文件路径。"""
        pattern = str(self.tools_dir / "*" / "defense" / "detect_*.py")
        return sorted(glob.glob(pattern))

    @staticmethod
    def _module_path(filepath: str, tools_dir: Path) -> str:
        """文件路径 → 模块点号路径 (tools.x.defense.detect_y)。"""
        root = tools_dir.parent
        rel = os.path.relpath(filepath, root)
        rel = rel.removesuffix(".py")
        return rel.replace(os.sep, ".").replace("/", ".")

    def _load_rules(self) -> None:
        """导入所有 detect 模块，收集 SIGNATURE + detect + respond。"""
        for fp in self._discover_modules():
            mod_path = self._module_path(fp, self.tools_dir)
            try:
                mod = importlib.import_module(mod_path)
            except Exception as e:  # 单个规则加载失败不影响整体
                self._load_failures.append(f"{mod_path}: {e}")
                continue

            sig = getattr(mod, "SIGNATURE", None)
            detect_fn = getattr(mod, "detect", None)
            respond_fn = getattr(mod, "respond", None)
            if not sig or not callable(detect_fn):
                self._load_failures.append(f"{mod_path}: missing SIGNATURE/detect")
                continue

            attack_type = sig.get("attack_type") or os.path.basename(fp)[7:-3]
            self._rules[attack_type] = {
                "signature": sig,
                "detect": detect_fn,
                "respond": respond_fn,
                "module": mod_path,
            }

    # -- 检测 ----------------------------------------------------------------

    def scan(self, event: dict) -> List[DetectionAlert]:
        """对单个事件执行所有规则，返回命中的告警列表。"""
        alerts: List[DetectionAlert] = []
        for attack_type, rule in self._rules.items():
            try:
                if not rule["detect"](event):
                    continue
            except Exception:
                continue  # 单规则异常不中断

            sig = rule["signature"]
            resp = {}
            if callable(rule["respond"]):
                try:
                    resp = rule["respond"](event) or {}
                except Exception:
                    resp = {}

            alerts.append(DetectionAlert(
                attack_type=attack_type,
                domain=sig.get("domain", ""),
                severity=resp.get("severity") or sig.get("severity", "medium"),
                action=resp.get("action", "alert"),
                recommendations=resp.get("recommendations", []),
                event=event,
                rule_module=rule["module"],
            ))
        return alerts

    def scan_events(self, events: List[dict]) -> List[DetectionAlert]:
        """批量事件检测，返回所有告警（去重按 attack_type）。"""
        alerts: List[DetectionAlert] = []
        seen: set = set()
        for ev in events:
            for a in self.scan(ev):
                key = (a.attack_type, a.domain)
                if key not in seen:
                    seen.add(key)
                    alerts.append(a)
        return alerts

    # -- 查询 ----------------------------------------------------------------

    def rule_count(self) -> int:
        return len(self._rules)

    def list_domains(self) -> Dict[str, int]:
        """各域加载的规则数量。"""
        counts: Dict[str, int] = {}
        for rule in self._rules.values():
            d = rule["signature"].get("domain", "unknown")
            counts[d] = counts.get(d, 0) + 1
        return dict(sorted(counts.items()))

    def list_rules(self) -> List[Dict[str, Any]]:
        """列出所有已加载规则的元信息。"""
        return [
            {
                "attack_type": atype,
                "domain": r["signature"].get("domain", ""),
                "severity": r["signature"].get("severity", "medium"),
                "description": r["signature"].get("description", ""),
                "module": r["module"],
            }
            for atype, r in sorted(self._rules.items())
        ]

    def load_failures(self) -> List[str]:
        return list(self._load_failures)
