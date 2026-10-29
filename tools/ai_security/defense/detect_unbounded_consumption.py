"""无界消耗：资源耗尽 / 成本放大（Denial of Wallet）攻击 LLM 服务

Domain: ai_security / unbounded_consumption
OWASP: LLM10:2025 Unbounded Consumption
"""

from __future__ import annotations

# Detection signature — 真实 IOC
SIGNATURE = {
    "attack_type": "unbounded_consumption",
    "mitre_tactic": "TA0040",
    "domain": "ai_security",
    "severity": "medium",
    "description": "诱导 LLM 无界推理 / 资源耗尽 / 成本放大，造成 DoS 或经济损失",
    "owasp": "LLM10:2025",
    "indicators": {
        "event_codes": [],
        "keywords": [
            'repeat this forever', 'infinite loop', 'token bomb', 'denial of wallet',
            'excessive tokens', 'recursive expansion', 'generate endlessly',
            'amplify cost', 'unbounded generation', 'max tokens exhaust',
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
        "recommendations": ['按用户/组织/全局设置速率与 token 预算', '检测发散式重复输出并熔断', '对高消耗请求做成本配额'],
        "event": event,
    }
