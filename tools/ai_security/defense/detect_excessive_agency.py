"""过度代理：Agent 工具权限过大、缺失人工审批 / 最小权限

Domain: ai_security / excessive_agency
OWASP: LLM06:2025 Excessive Agency
"""

from __future__ import annotations

# Detection signature — 真实 IOC
SIGNATURE = {
    "attack_type": "excessive_agency",
    "mitre_tactic": "TA0004",
    "domain": "ai_security",
    "severity": "high",
    "description": "AI Agent 被授予过大工具权限，高风险操作缺乏人工审批",
    "owasp": "LLM06:2025",
    "indicators": {
        "event_codes": [],
        "keywords": [
            'sudo', 'auto-approve', 'no human approval', 'unrestricted tool',
            'elevated permission', 'full access', 'root access', 'disable approval',
            'bypass approval', 'autonomous deploy', 'auto execute',
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
        "recommendations": ['工具权限按最小权限收敛', '高风险操作强制人工审批（human-on-the-loop）', '限制单次调用可访问的资源范围'],
        "event": event,
    }
