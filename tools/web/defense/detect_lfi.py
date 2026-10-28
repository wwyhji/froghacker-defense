"""路径遍历 / 本地文件包含 (LFI) 检测

Source: forensics server_logs._ATTACK_PATTERNS 反向注入 (web 域缺口补全)
Domain: web / web_lfi
"""
from __future__ import annotations

import re

SIGNATURE = {
    "attack_type": "web_lfi",
    "mitre_tactic": "TA0001",
    "domain": "web",
    "severity": "high",
    "description": "路径遍历/本地文件包含 (LFI): ../ %2e%2e %252e ..%2f 等编码变体",
    "indicators": {
        "event_codes": [],
        "keywords": ["../", "%2e%2e", "%252e", "..%2f"],
        "protocols": ["http", "https"],
        "fields": {},
    },
}

_LFI = re.compile(r"\.\./|%2e%2e|%252e|\.\.%2f")


def detect(event: dict) -> bool:
    """检测 HTTP 请求路径/原始日志中的路径遍历特征。"""
    if not isinstance(event, dict):
        return False
    text = " ".join(str(v).lower() for v in event.values())
    return bool(_LFI.search(text))


def respond(event: dict) -> dict:
    """告警 + 处置建议。"""
    return {
        "action": "alert",
        "severity": SIGNATURE["severity"],
        "attack_type": SIGNATURE["attack_type"],
        "recommendations": [
            "阻断含路径遍历特征的请求，确认 WAF 覆盖 ../ 与 %2e%2e 等编码变体",
            "审计 /etc/passwd、/etc/shadow 等敏感文件是否已泄露",
            "修复应用层路径拼接，统一路径规范化 + 白名单校验",
        ],
        "event": event,
    }
