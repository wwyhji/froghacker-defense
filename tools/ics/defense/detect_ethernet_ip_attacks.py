"""EtherNet/IP 攻击：CIP 协议命令注入或未授权读写

Source: CrossFeed defense rule (filled)
Domain: ics / ethernet_ip_attacks
"""

from __future__ import annotations

# Detection signature — 真实 IOC
SIGNATURE = {
    "attack_type": "ethernet_ip_attacks",
    "mitre_tactic": "TA0040",
    "domain": "ics",
    "severity": "high",
    "description": "EtherNet/IP 攻击：CIP 协议命令注入或未授权读写",
    "indicators": {
        "event_codes": [],
        "keywords": ['ethernet/ip', 'cip', 'command injection', 'unauthorized write'],
        "protocols": ['ethernet/ip', 'cip'],
        "fields": {},
    },
}


def detect(event: dict) -> bool:
    """检测事件是否命中本攻击特征。

    事件码是弱特征 (如 4624 登录、4662 目录访问，过于宽泛)，关键词/协议/字段是
    强特征。两者都有时需同时命中才告警，避免正常事件误报。
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
        # 事件提供事件码 → 需 AND 防误报；未提供（普通日志）→ 强特征命中即可
        if code:
            return soft and code_hit
        return soft
    if has_soft:
        return soft                # 只有强特征：命中即告警
    return code_hit                # 只有事件码：命中即告警


def respond(event: dict) -> dict:
    """告警 + 处置建议。"""
    return {
        "action": "alert",
        "severity": SIGNATURE["severity"],
        "attack_type": SIGNATURE["attack_type"],
        "recommendations": ['检测 CIP 未授权命令', '部署 EtherNet/IP 深度包检测', '网络分段'],
        "event": event,
    }
