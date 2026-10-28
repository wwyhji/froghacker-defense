"""SQL 注入检测

Source: forensics server_logs._ATTACK_PATTERNS 反向注入 (web 域缺口补全)
Domain: web / web_sqli
"""
from __future__ import annotations

import re

SIGNATURE = {
    "attack_type": "web_sqli",
    "mitre_tactic": "TA0001",
    "domain": "web",
    "severity": "high",
    "description": "SQL 注入: union select / sleep( / or 1=1 / '--",
    "indicators": {
        "event_codes": [],
        "keywords": ["union select", "sleep(", "1=1", "'--"],
        "protocols": ["http", "https"],
        "fields": {},
    },
}

_SQLI = re.compile(r"union\s+select|sleep\(|\bor\s+1=1|'--")


def detect(event: dict) -> bool:
    """检测 HTTP 请求路径/原始日志中的 SQL 注入特征。"""
    if not isinstance(event, dict):
        return False
    text = " ".join(str(v).lower() for v in event.values())
    return bool(_SQLI.search(text))


def respond(event: dict) -> dict:
    """告警 + 处置建议。"""
    return {
        "action": "alert",
        "severity": SIGNATURE["severity"],
        "attack_type": SIGNATURE["attack_type"],
        "recommendations": [
            "确认注入点是否成功利用，检查数据库是否被拖库",
            "封禁来源 IP，审计同时间段 SQL 注入探测",
            "修复参数化查询，禁用字符串拼接 SQL",
        ],
        "event": event,
    }
