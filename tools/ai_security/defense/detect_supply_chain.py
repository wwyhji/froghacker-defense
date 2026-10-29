"""供应链攻击：恶意模型 / 数据集 / 插件 / 依赖投毒

Domain: ai_security / supply_chain
OWASP: LLM03:2025 Supply Chain
"""

from __future__ import annotations

# Detection signature — 真实 IOC
SIGNATURE = {
    "attack_type": "supply_chain",
    "mitre_tactic": "TA0001",
    "domain": "ai_security",
    "severity": "high",
    "description": "恶意模型 / 数据集 / 插件 / 依赖供应链投毒（后门 / 篡改 / 仿冒）",
    "owasp": "LLM03:2025",
    "indicators": {
        "event_codes": [],
        "keywords": [
            'malicious model', 'backdoored model', 'poisoned dataset', 'malicious plugin',
            'typosquat', 'untrusted package', 'model tampering', 'dataset poisoning',
            'supply chain compromise', 'fake package', 'dependency confusion',
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
        "recommendations": ['校验模型/数据集来源与签名', '生成 AI-BOM 追踪依赖', '隔离并下架受污染组件'],
        "event": event,
    }
