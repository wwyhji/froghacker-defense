"""defense_benchmark.py — defense 检测规则基准（45 条 detect_*.py）。

把「检测规则 × 事件样本 → 命中/误报矩阵」沉淀成可重复执行的资产：

  1. 正向事件：从每条规则 SIGNATURE.indicators 自动生成（验证 detect 能命中自己的 IOC）
  2. 正常事件：data/defense/benchmark.yaml 手工维护（验证规则不误报）
  3. 输出每条的「正向命中」+「误报的正常事件」，供 pytest 门禁

用法:
    python -m tools.blueteam.defense_benchmark
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


def _default_manifest_path() -> str:
    return str(Path(__file__).resolve().parent.parent.parent / "data" / "defense" / "benchmark.yaml")


def _load_normal_events(manifest_path: str) -> List[dict]:
    import yaml
    with open(manifest_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data.get("normal_events", [])


def _gen_positive_event(sig: dict) -> dict:
    """从 SIGNATURE.indicators 生成一个能命中该规则的事件（自我验证）。"""
    ind = sig.get("indicators", {})
    event: dict = {}
    codes = ind.get("event_codes") or []
    kws = ind.get("keywords") or []
    protos = ind.get("protocols") or []
    fields = ind.get("fields") or {}
    if codes:
        event["event_code"] = codes[0]
    if kws:
        event["raw"] = kws[0]
    if protos:
        event["protocol"] = protos[0]
    for k, v in fields.items():
        event[k] = v
    return event


@dataclass
class RuleResult:
    """单条规则的正向命中 + 防误报结果。"""
    attack_type: str = ""
    domain: str = ""
    positive_hit: bool = False            # 正向事件是否命中
    false_positive_on: List[str] = field(default_factory=list)  # 误报的正常事件名

    @property
    def passed(self) -> bool:
        return self.positive_hit and not self.false_positive_on

    def to_dict(self) -> dict:
        return {
            "attack_type": self.attack_type,
            "domain": self.domain,
            "positive_hit": self.positive_hit,
            "false_positive_on": self.false_positive_on,
            "passed": self.passed,
        }


@dataclass
class DefenseBenchmarkReport:
    """defense 检测规则基准总报告。"""
    rules: List[RuleResult] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(r.passed for r in self.rules)

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "rules": [r.to_dict() for r in self.rules],
        }

    def render(self) -> str:
        lines = [f"defense 检测规则基准 — {len(self.rules)} 条规则"]
        lines.append("")
        lines.append("rule".ljust(34) + "domain".ljust(12) + "正向" + "误报")
        lines.append("-" * 70)
        for r in self.rules:
            fp = ",".join(r.false_positive_on) if r.false_positive_on else "-"
            pos = "命中" if r.positive_hit else "漏报"
            lines.append(
                r.attack_type.ljust(34) + r.domain.ljust(12) + pos + fp
            )
        n_pass = sum(1 for r in self.rules if r.passed)
        n_fp = sum(len(r.false_positive_on) for r in self.rules)
        n_miss = sum(1 for r in self.rules if not r.positive_hit)
        lines.append("")
        lines.append(f"结果: {n_pass}/{len(self.rules)} 通过 | 漏报 {n_miss} | 误报 {n_fp}")
        return "\n".join(lines)


def run_benchmark(manifest_path: str = "") -> DefenseBenchmarkReport:
    """跑基准：加载规则 → 正向自检 + 正常事件防误报。"""
    from tools.blueteam.detection_engine import DetectionEngine

    if not manifest_path:
        manifest_path = _default_manifest_path()

    engine = DetectionEngine()
    normal_events = _load_normal_events(manifest_path)

    report = DefenseBenchmarkReport()
    for attack_type, rule in sorted(engine._rules.items()):
        sig = rule["signature"]
        detect_fn = rule["detect"]
        domain = sig.get("domain", "unknown")

        # 正向：从 SIGNATURE 生成的事件应命中
        pos_event = _gen_positive_event(sig)
        try:
            positive_hit = bool(detect_fn(pos_event))
        except Exception:
            positive_hit = False

        # 防误报：正常事件不应命中
        fp = []
        for ne in normal_events:
            try:
                if detect_fn(ne["event"]):
                    fp.append(ne["name"])
            except Exception:
                continue

        report.rules.append(RuleResult(
            attack_type=attack_type,
            domain=domain,
            positive_hit=positive_hit,
            false_positive_on=fp,
        ))

    return report


def main() -> int:
    import argparse

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    ap = argparse.ArgumentParser(description="defense 检测规则基准")
    ap.add_argument("--manifest", default="", help="清单路径（默认 data/defense/benchmark.yaml）")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    args = ap.parse_args()

    report = run_benchmark(args.manifest)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    else:
        print(report.render())
    return 0 if report.passed else 1


if __name__ == "__main__":
    sys.exit(main())
