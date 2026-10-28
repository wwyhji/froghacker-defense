"""二次编码绕过检测

Source: forensics server_logs._ATTACK_PATTERNS 反向注入 (web 域缺口补全)
Domain: web / web_double_encoding
"""
from __future__ import annotations

import re

SIGNATURE = {
    "attack_type": "web_double_encoding",
    "mitre_tactic": "TA0005",
    "domain": "web",
    "severity": "medium",
    "description": "二次编码绕过 WAF: %252f %255c %253f %252e 等双重 URL 编码",
    "indicators": {
        "event_codes": [],
        "keywords": ["%252f", "%255c", "%253f", "%252e"],
        "protocols": ["http", "https"],
        "fields": {},
    },
}

_DOUBLE = re.compile(r"%25(2f|5c|3f|2e)")


def detect(event: dict) -> bool:
    """检测 HTTP 请求路径/原始日志中的二次编码绕过特征。"""
    if not isinstance(event, dict):
        return False
    text = " ".join(str(v).lower() for v in event.values())
    return bool(_DOUBLE.search(text))


def respond(event: dict) -> dict:
    """告警 + 处置建议。"""
    return {
        "action": "alert",
        "severity": SIGNATURE["severity"],
        "attack_type": SIGNATURE["attack_type"],
        "recommendations": [
            "二次编码常伴随 LFI/SQLi，需结合同请求其它特征综合研判",
            "WAF 规则需覆盖多次解码场景，解码后再匹配攻击特征",
        ],
        "event": event,
    }
