"""AI蓝队 — 防御自动化全管线：先敌发现→蜜罐→监控→检测→响应→加固→报告。

开源版 (defense-oss)：已剥离数学引擎（同调/Petri/因果/FCA，见 NOTICE 专利保留声明）
与知识库飞轮（AlphaLoop/Flywheel），仅保留常规防御能力。详见仓库根 MANIFEST.md。

用法:
    from tools.blueteam import BlueTeamPipeline

    pipeline = BlueTeamPipeline()
    result = pipeline.run("192.168.1.0/24")
    print(result.summary)

    # 或单点检测
    from tools.blueteam import DetectionEngine
    engine = DetectionEngine()
    alerts = engine.scan({"event_code": "4662", "raw": "DRSUAPI replication"})
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

# -- Submodule imports --------------------------------------------------------
from tools.blueteam.honeypot import (
    deploy_honeypot, list_honeypots, stop_honeypot,
    analyze_captures, detect_honeypot, is_honeypot,
    HoneypotConfig, HoneypotInstance, HoneypotManager,
    HONEYPOT_TYPES, HONEYPOT_SIGNATURES,
)
from tools.blueteam.ids import (
    IDSRule, generate_bundle, export_rules, BUNDLES,
)
from tools.blueteam.log_analyzer import analyze_logs, LogEntry
from tools.blueteam.threat_hunt import run_hunt, HuntResult
from tools.blueteam.firewall import (
    FirewallRule, baseline_rules, block_ip, block_ips,
    apply_rules, list_rules,
)
from tools.blueteam.harden import run_audit, HardeningCheck
from tools.blueteam.preemptive import preemptive_scan, AttackerFinding
from tools.blueteam.detection_engine import DetectionEngine, DetectionAlert
from tools.blueteam.dynamic_defense import DynamicDefense, ThreatLevel
from tools.blueteam.responder import IncidentResponder


# -- Pipeline result ----------------------------------------------------------

@dataclass
class BlueTeamResult:
    """蓝队防御管线完整结果。"""
    target: str = ""
    honeypots: List[HoneypotInstance] = field(default_factory=list)
    ids_rules: List[IDSRule] = field(default_factory=list)
    log_analysis: dict = field(default_factory=dict)
    threat_findings: dict = field(default_factory=dict)
    firewall_rules: List[FirewallRule] = field(default_factory=list)
    hardening_audit: dict = field(default_factory=dict)
    preemptive: dict = field(default_factory=dict)
    # Self-heal（开源版未实现，字段保留以兼容旧序列化）
    self_heal_known: int = 0
    self_heal_count: int = 0
    self_heal_events: list = field(default_factory=list)
    stage_errors: list = field(default_factory=list)
    # Meta
    report_path: str = ""
    pipeline_status: str = ""
    started_at: str = ""
    completed_at: str = ""
    error: str = ""

    @property
    def summary(self) -> str:
        parts = [f"防御目标: {self.target}"]
        pre_total = len(self.preemptive.get("findings", []))
        pre_high = sum(
            1 for f in self.preemptive.get("findings", [])
            if f.risk_level in ("critical", "high")
        )
        parts.append(f"  先敌发现: {pre_total} 个薄弱点 (其中高危: {pre_high} 个)")
        parts.append(f"  蜜罐: {len(self.honeypots)} 个部署")
        parts.append(f"  IDS规则: {len(self.ids_rules)} 条")
        log_total = self.log_analysis.get("total_entries", 0)
        parts.append(f"  日志分析: {log_total} 条")
        threat_total = self.threat_findings.get("total_findings", 0)
        parts.append(f"  威胁狩猎: {threat_total} 个发现")
        parts.append(f"  防火墙规则: {len(self.firewall_rules)} 条")
        score = self.hardening_audit.get("score", 0)
        parts.append(f"  加固评分: {score:.0%}")
        if self.self_heal_count:
            parts.append(f"  🩹 自愈: {self.self_heal_count} 个漏洞自动修复 (已知: {self.self_heal_known})")
        parts.append(f"  状态: {self.pipeline_status}")
        return "\n".join(parts)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "honeypots": [h.to_dict() for h in self.honeypots],
            "ids_rule_count": len(self.ids_rules),
            "log_analysis": self.log_analysis,
            "threat_hunt": self.threat_findings,
            "firewall_rule_count": len(self.firewall_rules),
            "hardening_score": self.hardening_audit.get("score", 0),
            "preemptive": {
                "findings": len(self.preemptive.get("findings", [])),
                "risk_distribution": self.preemptive.get("risk_distribution", {}),
                "platform_used": self.preemptive.get("platform_used", ""),
            },
            "pipeline_status": self.pipeline_status,
        }


# -- Pipeline -----------------------------------------------------------------

class BlueTeamPipeline:
    """蓝队防御管线 — deploy → monitor → detect → respond → harden → report。"""

    def __init__(self, log_dir: str = "/var/log",
                 honeypot_log_dir: str = "./honeypot_logs"):
        self.log_dir = log_dir
        self.honeypot_log_dir = honeypot_log_dir

    def run(self, target: str = "localhost",
            deploy_honeypots: bool = True,
            honeypot_types: Optional[List[str]] = None,
            ids_bundle: str = "all",
            hunt_iocs: Optional[Dict[str, List[str]]] = None,
            skip_preemptive: bool = False,
            skip_log_analysis: bool = False,
            skip_threat_hunt: bool = False,
            skip_hardening: bool = False,
            skip_firewall: bool = False,
            skip_report: bool = False,
            ) -> BlueTeamResult:
        """完整防御管线。

        Args:
            target: 防御目标
            deploy_honeypots: 是否部署蜜罐
            honeypot_types: 蜜罐类型列表 (默认: simple_http)
            ids_bundle: IDS 规则包
            hunt_iocs: 威胁狩猎 IOC 字典
        """
        result = BlueTeamResult(
            target=target,
            started_at=datetime.now().isoformat(),
            pipeline_status="running",
        )

        try:
            # Phase 0: Preemptive scan — find weaknesses before the enemy does
            if not skip_preemptive:
                result.preemptive = preemptive_scan(target)

            # Phase 1: Deploy honeypots
            if deploy_honeypots:
                types = honeypot_types or ["simple_http"]
                for hp_type in types:
                    inst = deploy_honeypot(
                        hp_type, name=f"blueteam_{hp_type}",
                        log_dir=self.honeypot_log_dir,
                    )
                    result.honeypots.append(inst)

            # Phase 2: Generate IDS rules
            result.ids_rules = generate_bundle(ids_bundle)

            # Phase 3: Log analysis
            if not skip_log_analysis:
                result.log_analysis = analyze_logs(self.log_dir)

            # Phase 4: Threat hunting
            if not skip_threat_hunt:
                result.threat_findings = run_hunt(
                    search_root="/",
                    iocs=hunt_iocs or {},
                )

            # Phase 5: Firewall hardening
            if not skip_firewall:
                result.firewall_rules = baseline_rules()

            # Phase 6: System hardening audit
            if not skip_hardening:
                result.hardening_audit = run_audit()

            result.pipeline_status = "completed"

        except Exception as e:
            result.pipeline_status = "failed"
            result.error = str(e)

        result.completed_at = datetime.now().isoformat()
        return result


# -- Public API --------------------------------------------------------------

__all__ = [
    "BlueTeamPipeline", "BlueTeamResult",
    # Preemptive
    "AttackerFinding", "preemptive_scan",
    # Honeypot
    "HoneypotConfig", "HoneypotInstance", "HoneypotManager",
    "deploy_honeypot", "list_honeypots", "stop_honeypot",
    "analyze_captures", "detect_honeypot", "is_honeypot",
    "HONEYPOT_TYPES", "HONEYPOT_SIGNATURES",
    # IDS
    "IDSRule", "generate_bundle", "export_rules", "BUNDLES",
    # Log analysis
    "analyze_logs", "LogEntry",
    # Threat hunting
    "run_hunt", "HuntResult",
    # Firewall
    "FirewallRule", "baseline_rules", "block_ip", "block_ips",
    "apply_rules", "list_rules",
    # Hardening
    "run_audit", "HardeningCheck",
    # Detection & response
    "DetectionEngine", "DetectionAlert",
    "DynamicDefense", "ThreatLevel",
    "IncidentResponder",
]
