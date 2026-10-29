"""不安全代理间通信：多 Agent / A2A 消息投毒与劫持

Domain: ai_security / inter_agent_comm
OWASP: ASI07 Insecure Inter-Agent Communication
"""

from __future__ import annotations

# Detection signature — 真实 IOC
SIGNATURE = {
    "attack_type": "inter_agent_comm",
    "mitre_tactic": "TA0008",
    "domain": "ai_security",
    "severity": "high",
    "description": "多 Agent 系统间（A2A）消息被投毒 / 劫持，跨代理传播恶意指令",
    "owasp": "ASI07",
    "indicators": {
        "event_codes": [],
        "keywords": [
            'inter-agent', 'a2a protocol', 'agent message injection', 'cross-agent injection',
            'multi-agent poisoning', 'untrusted agent message', 'agent relay attack',
            'swarm message injection', 'agent-to-agent hijack', 'malicious agent broadcast',
        ],
        "protocols": ['a2a'],
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
        "recommendations": ['代理间消息做签名与来源认证', '跨代理指令做隔离与校验', '限制代理间信任传播边界'],
        "event": event,
    }
