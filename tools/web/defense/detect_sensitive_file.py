"""敏感文件访问检测

Source: forensics server_logs._ATTACK_PATTERNS 反向注入 (web 域缺口补全)
Domain: web / web_sensitive_file
"""
from __future__ import annotations

import re

SIGNATURE = {
    "attack_type": "web_sensitive_file",
    "mitre_tactic": "TA0006",
    "domain": "web",
    "severity": "high",
    "description": "敏感文件访问: /etc/passwd /etc/shadow wp-config .htaccess .env",
    "indicators": {
        "event_codes": [],
        "keywords": ["/etc/passwd", "/etc/shadow", "wp-config", ".htaccess"],
        "protocols": ["http", "https"],
        "fields": {},
    },
}

_SENSITIVE = re.compile(r"/etc/(passwd|shadow|hosts)|wp-config|\.htaccess|\benv\b")


def detect(event: dict) -> bool:
    """检测 HTTP 请求路径/原始日志中的敏感文件访问。"""
    if not isinstance(event, dict):
        return False
    text = " ".join(str(v).lower() for v in event.values())
    return bool(_SENSITIVE.search(text))


def respond(event: dict) -> dict:
    """告警 + 处置建议。"""
    return {
        "action": "alert",
        "severity": SIGNATURE["severity"],
        "attack_type": SIGNATURE["attack_type"],
        "recommendations": [
            "确认敏感文件是否已通过应用/中间件泄露，立即轮换泄露凭据",
            "检查应用是否错误暴露配置文件 (.env/wp-config/.htaccess)",
            "审计访问来源 IP 与后续横向行为",
        ],
        "event": event,
    }
