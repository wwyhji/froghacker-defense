"""Webshell 远程代码执行检测

Source: forensics server_logs._ATTACK_PATTERNS 反向注入 (web 域缺口补全)
Domain: web / web_webshell
"""
from __future__ import annotations

import re

SIGNATURE = {
    "attack_type": "web_webshell",
    "mitre_tactic": "TA0002",
    "domain": "web",
    "severity": "critical",
    "description": "Webshell/RCE: eval( system( exec( shell_exec passthru cmd.exe",
    "indicators": {
        "event_codes": [],
        "keywords": ["system(", "eval(", "exec(", "shell_exec", "passthru"],
        "protocols": ["http", "https"],
        "fields": {},
    },
}

_WEBSHELL = re.compile(r"eval\(|system\(|exec\(|shell_exec|passthru|cmd\.exe")


def detect(event: dict) -> bool:
    """检测 HTTP 请求路径/原始日志中的 RCE/webshell 特征。"""
    if not isinstance(event, dict):
        return False
    text = " ".join(str(v).lower() for v in event.values())
    return bool(_WEBSHELL.search(text))


def respond(event: dict) -> dict:
    """告警 + 处置建议。"""
    return {
        "action": "alert",
        "severity": SIGNATURE["severity"],
        "attack_type": SIGNATURE["attack_type"],
        "recommendations": [
            "立即隔离受影响主机，检查是否已写入 webshell 文件",
            "从访问日志回溯完整攻击链，定位 webshell 落盘路径",
            "封禁来源 IP，审计同时间段其它请求",
        ],
        "event": event,
    }
