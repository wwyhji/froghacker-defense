"""不当输出处理：LLM 输出未净化，导致下游 XSS / SQLi / 命令注入 / SSRF

Domain: ai_security / improper_output_handling
OWASP: LLM05:2025 Improper Output Handling
"""

from __future__ import annotations

# Detection signature — 真实 IOC
SIGNATURE = {
    "attack_type": "improper_output_handling",
    "mitre_tactic": "TA0002",
    "domain": "ai_security",
    "severity": "high",
    "description": "LLM 输出携带可执行/注入载荷未净化，直接进入下游解释器",
    "owasp": "LLM05:2025",
    "indicators": {
        "event_codes": [],
        "keywords": [
            '<script>', 'javascript:', 'onerror=', 'onload=', 'union select', '1=1',
            '; rm -rf', '; cat /etc/passwd', 'ssrf', 'redirect:', 'file://',
            'eval(', 'exec(', 'os.system', 'base64_decode',
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
        "recommendations": ['对 LLM 输出做上下文感知的编码/净化', '下游解释器与模型输出隔离', '输出按用途做 schema 校验'],
        "event": event,
    }
