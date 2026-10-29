"""敏感信息泄露：LLM 输出泄露密钥 / PII / 凭证

Domain: ai_security / sensitive_info_disclosure
OWASP: LLM02:2025 Sensitive Information Disclosure
"""

from __future__ import annotations

# Detection signature — 真实 IOC
SIGNATURE = {
    "attack_type": "sensitive_info_disclosure",
    "mitre_tactic": "TA0010",
    "domain": "ai_security",
    "severity": "high",
    "description": "LLM 输出泄露 API 密钥 / 令牌 / PII / 凭证等敏感信息",
    "owasp": "LLM02:2025",
    "indicators": {
        "event_codes": [],
        "keywords": [
            'api key', 'secret key', 'access token', 'refresh token', 'password',
            'private key', 'client secret', 'connection string', 'credit card',
            'social security', 'credential leak', 'pii disclosure', 'sensitive data',
            'akia', 'ghp_', 'sk-', 'bearer token',
        ],
        "protocols": [],
        "fields": {},
    },
}


def detect(event: dict) -> bool:
    """检测事件是否命中本攻击特征。

    事件码是弱特征，关键词/协议/字段是强特征。两者都有时需同时命中才告警。
    """
    if not isinstance(event, dict):
        return False
    ind = SIGNATURE["indicators"]

    # 强特征：关键词 / 协议 / 字段
    text = " ".join(str(v).lower() for v in event.values())
    soft = any(k.lower() in text for k in ind.get("keywords", []))
    if not soft:
        proto = str(event.get("protocol") or event.get("type") or "").lower()
        soft = bool(proto and ind.get("protocols") and proto in ind["protocols"])
    if not soft:
        soft = any(str(event.get(k)) == str(v) for k, v in ind.get("fields", {}).items())

    # 弱特征：事件码
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
        "recommendations": ['对模型输出做敏感信息脱敏/过滤', '启用输出侧 DLP 扫描', '密钥轮换并撤销量产令牌'],
        "event": event,
    }
