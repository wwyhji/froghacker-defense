"""记忆投毒：RAG 检索 / Agent 记忆 / 上下文投毒

Domain: ai_security / agent_memory_poisoning
OWASP: ASI06 Memory Poisoning
"""

from __future__ import annotations

# Detection signature — 真实 IOC
SIGNATURE = {
    "attack_type": "agent_memory_poisoning",
    "mitre_tactic": "TA0001",
    "domain": "ai_security",
    "severity": "high",
    "description": "攻击者向 RAG 知识库 / Agent 长期记忆 / 向量库注入恶意内容",
    "owasp": "ASI06",
    "indicators": {
        "event_codes": [],
        "keywords": [
            'memory poisoning', 'rag poisoning', 'retrieval injection', 'context poisoning',
            'vector store injection', 'poisoned context', 'memory injection',
            'knowledge base poisoning', 'embedding poisoning', 'retrieval augmented injection',
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
        "recommendations": ['对写入记忆/RAG 的内容做来源校验与清洗', '记忆与指令上下文隔离', '检索结果按可信度过滤'],
        "event": event,
    }
