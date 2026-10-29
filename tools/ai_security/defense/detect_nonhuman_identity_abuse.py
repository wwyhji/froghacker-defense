"""非人类身份滥用：机器身份 / 服务账户 / API 密钥越权或泄露

Domain: ai_security / nonhuman_identity_abuse
OWASP: ASI03 Identity Abuse
"""

from __future__ import annotations

# Detection signature — 真实 IOC
SIGNATURE = {
    "attack_type": "nonhuman_identity_abuse",
    "mitre_tactic": "TA0004",
    "domain": "ai_security",
    "severity": "high",
    "description": "机器身份 / 服务账户 / API 密钥被越权使用或泄露（非人类身份治理缺失）",
    "owasp": "ASI03",
    "indicators": {
        "event_codes": [],
        "keywords": [
            'machine identity', 'service account abuse', 'api key exfiltration',
            'non-human identity', 'workload identity', 'stolen token',
            'agent identity theft', 'impersonate agent', 'credential stuffing agent',
            'unauthorized service account',
        ],
        "protocols": [],
        "fields": {},
    },
}


def detect(event: dict) -> bool:
    """检测事件是否命中本攻击特征。"""
    if not isinstance(event, dict):
        return False
    ind = SIGNATURE["indicators"]

    text = " ".join(str(v).lower() for v in event.values())
    soft = any(k.lower() in text for k in ind.get("keywords", []))
    if not soft:
        proto = str(event.get("protocol") or event.get("type") or "").lower()
        soft = bool(proto and ind.get("protocols") and proto in ind["protocols"])
    if not soft:
        soft = any(str(event.get(k)) == str(v) for k, v in ind.get("fields", {}).items())

    code = str(event.get("event_code") or event.get("event_id") or event.get("code") or "")
    code_hit = bool(code and ind.get("event_codes") and code in ind["event_codes"])

    has_soft = bool(ind.get("keywords") or ind.get("protocols") or ind.get("fields"))
    has_code = bool(ind.get("event_codes"))
    if has_soft and has_code:
        if code:
            return soft and code_hit
        return soft
    if has_soft:
        return soft
    return code_hit


def respond(event: dict) -> dict:
    """告警 + 处置建议。"""
    return {
        "action": "alert",
        "severity": SIGNATURE["severity"],
        "attack_type": SIGNATURE["attack_type"],
        "recommendations": ['为非人类身份建立独立 IAM 与最短有效期令牌', '审计机器身份的异常调用模式', '密钥泄露即轮换并溯源'],
        "event": event,
    }
