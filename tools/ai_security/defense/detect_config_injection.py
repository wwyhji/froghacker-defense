"""Detect config-surface de-alignment injection on DSH-style AI agent harnesses.

Scans a harness config dir for IoCs left by prompt/persona injection tools:
  - injector manifest (.dsh-rp-injector/manifest.json)
  - backup residue (*.bak-*)
  - disabled harness identity injection (cordis.patch.yml)
  - flipped personaEnabled (settings.yaml)
  - injected tokens leaking into AGENTS.md

Usage:
    python -m tools.ai_security.defense.detect_config_injection [target_dir ...]
    (no args -> auto-discover common DSH locations)

Domain: ai_security / config_injection
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

SCAN_RULES = [
    {
        "name": "injector_manifest",
        "severity": "critical",
        "kind": "file",
        "path": ".dsh-rp-injector/manifest.json",
        "desc": "DSH 注入工具 manifest 存在，说明该工具已在本机执行",
    },
    {
        "name": "backup_residue",
        "severity": "medium",
        "kind": "glob",
        "pattern": "*.bak-*",
        "desc": "存在 .bak-时间戳 备份残留，配置/技能曾被批量改写",
    },
    {
        "name": "harness_identity_disabled",
        "severity": "critical",
        "kind": "content",
        "pattern": "cordis.patch.yml",
        "regex": r"includeHarnessIdentity\s*:\s*false|includeRuntimeContext\s*:\s*false",
        "desc": "harness 强制注入开关被关闭（去对齐）",
    },
    {
        "name": "persona_enabled_flip",
        "severity": "high",
        "kind": "content",
        "pattern": "settings.yaml",
        "regex": r"personaEnabled\s*:\s*true",
        "desc": "settings.yaml 中 personaEnabled 被置 true（插件人设注入开关被打开）",
    },
    {
        "name": "agents_injected_token",
        "severity": "high",
        "kind": "content",
        "pattern": "AGENTS.md",
        "regex": r"includeHarnessIdentity",
        "desc": "全局提示词出现 includeHarnessIdentity，注入内容已渗入提示词",
    },
]


def scan_dir(dsh_home: str) -> list[dict]:
    """Scan one harness config dir and return a list of findings."""
    root = Path(dsh_home)
    if not root.is_dir():
        return []
    findings = []
    for rule in SCAN_RULES:
        kind = rule["kind"]
        if kind == "file":
            if (root / rule["path"]).exists():
                findings.append(_finding(rule, str(root / rule["path"])))
        elif kind == "glob":
            for hit in root.glob(rule["pattern"]):
                findings.append(_finding(rule, str(hit)))
        elif kind == "content":
            for path in root.glob(rule["pattern"]):
                try:
                    text = path.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                if re.search(rule["regex"], text):
                    findings.append(_finding(rule, str(path)))
    return findings


def _finding(rule: dict, path: str) -> dict:
    return {
        "rule": rule["name"],
        "severity": rule["severity"],
        "path": path,
        "desc": rule["desc"],
    }


def find_default_homes() -> list[str]:
    """Auto-discover common DSH harness config locations."""
    homes: list[str] = []
    env_home = os.environ.get("DSH_HOME")
    if env_home:
        homes.append(env_home)
    home = os.path.expanduser("~")
    homes.append(os.path.join(home, ".dsh"))
    starter_base = os.path.join(
        os.environ.get("LOCALAPPDATA", home),
        "Programs",
        "deepseek-harness-starter",
    )
    homes.append(os.path.join(starter_base, "dsh-home"))
    return list(dict.fromkeys(homes))  # dedup, keep order


def main(argv: list[str]) -> int:
    targets = argv[1:] if len(argv) > 1 else find_default_homes()
    total = 0
    critical = 0
    for t in targets:
        findings = scan_dir(t)
        if not findings:
            print(f"[clean] {t}")
            continue
        print(f"[{len(findings)} finding(s)] {t}")
        for f in findings:
            total += 1
            if f["severity"] == "critical":
                critical += 1
            print(f"  [{f['severity']}] {f['rule']} — {f['desc']}")
            print(f"      {f['path']}")
    print()
    print(f"共 {total} 项，其中 critical {critical} 项")
    return 1 if critical else 0


SIGNATURE = {
    "attack_type": "config_injection",
    "mitre_tactic": "TA0003",
    "domain": "ai_security",
    "severity": "high",
    "description": "配置面去对齐注入：DSH harness 配置被改写（注入工具 manifest / personaEnabled 翻转 / includeHarnessIdentity 关闭）",
    "indicators": {
        "keywords": [
            ".dsh-rp-injector", "cordis.patch.yml", "personaEnabled",
            "includeHarnessIdentity", "config_injection",
        ],
        "fields": {},
    },
}


def detect(event: dict) -> bool:
    """检测事件是否命中配置注入特征。"""
    if not isinstance(event, dict):
        return False
    text = " ".join(str(v).lower() for v in event.values())
    return any(k.lower() in text for k in SIGNATURE["indicators"]["keywords"])


def respond(event: dict) -> dict:
    """告警 + 处置建议。"""
    return {
        "action": "alert",
        "severity": SIGNATURE["severity"],
        "attack_type": SIGNATURE["attack_type"],
        "recommendations": [
            "检查 ~/.dsh 等 harness 配置目录是否有 .dsh-rp-injector/manifest.json",
            "审计 settings.yaml 的 personaEnabled 与 cordis.patch.yml 的 includeHarnessIdentity",
            "回滚 *.bak-* 备份，恢复被改写的 AGENTS.md / 技能文件",
        ],
        "event": event,
    }


if __name__ == "__main__":
    sys.exit(main(sys.argv))
