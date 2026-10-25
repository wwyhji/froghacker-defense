"""Kerberoasting：高频 TGS-REQ 请求，常用 RC4 加密拉取服务票据

Source: CrossFeed defense rule (filled)
Domain: ad_attack / ad_kerberos
"""

from __future__ import annotations

# Detection signature — 真实 IOC
SIGNATURE = {
    "attack_type": "ad_kerberos",
    "mitre_tactic": "TA0006",
    "domain": "ad_attack",
    "severity": "high",
    "description": "Kerberoasting：高频 TGS-REQ 请求，常用 RC4 加密拉取服务票据",
    "indicators": {
        "event_codes": ['4769'],
        "keywords": ['TGS-REQ', 'kerberoast', 'service ticket', 'rc4-hmac'],
        "protocols": [],
        "fields": {'encryption_type': '0x17'},
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
        "recommendations": ['审计高频 4769 事件的服务账户', '为服务账户设置高强度密码并定期轮换', '监控 RC4 加密类型的票据请求'],
        "event": event,
    }
