"""MCP 工具滥用：工具参数污染 / 命令注入 / 工具链操纵

Domain: ai_security / mcp_tool_misuse
OWASP: ASI02 Tool Misuse and Exploitation
"""

from __future__ import annotations

# Detection signature — 真实 IOC
SIGNATURE = {
    "attack_type": "mcp_tool_misuse",
    "mitre_tactic": "TA0002",
    "domain": "ai_security",
    "severity": "critical",
    "description": "AI Agent 滥用 MCP 工具：参数污染 / 命令注入 / 工具链操纵 / 越权调用",
    "owasp": "ASI02",
    "indicators": {
        "event_codes": [],
        "keywords": [
            'mcp', 'tool injection', 'parameter pollution', 'command injection via tool',
            'tool chaining', 'exfil via tool', 'mcp command injection', 'tool call injection',
            'malicious tool input', 'tool output injection', 'mcp server exploit',
        ],
        "protocols": ['mcp'],
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
        "recommendations": ['对 MCP 工具调用做参数 schema 校验', '隔离工具输出与指令上下文', '限制工具权限并审计调用链'],
        "event": event,
    }
