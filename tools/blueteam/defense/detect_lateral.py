"""横向移动检测 (Remote Services / PsExec / WMI / Pass-the-Hash)

Source: blueteam coverage blindspot fill (TA0008 lateral)
Domain: blueteam / lateral_movement
"""

from __future__ import annotations

# Detection signature — 真实 IOC
SIGNATURE = {
    "attack_type": "lateral_movement",
    "mitre_tactic": "TA0008",
    "domain": "blueteam",
    "severity": "critical",
    "description": "横向移动：远程服务创建 (PsExec/WMI)、显式凭证登录、Pass-the-Hash 凭证重用",
    "indicators": {
        "event_codes": ['7045', '4697', '4648'],
        "keywords": [
            'psexec', 'wmiexec', 'smbexec', 'atexec', 'dcomexec', 'mmcexec',
            'impacket', 'crackmapexec', 'winexe', 'schtasks /create',
            'pass the hash', 'pass-the-hash', 'ntlm hash',
        ],
        "protocols": ['smb', 'rpc', 'winrm'],
        "fields": {},
    },
}


def detect(event: dict) -> bool:
    """检测事件是否命中横向移动特征。

    事件码是弱特征 (如 7045 服务安装、4624 登录，过于宽泛)，关键词/协议是
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
        "recommendations": [
            '隔离触发横向移动的源主机，重置被重用凭证',
            '审计 7045/4697 新建服务，确认非计划内远程执行',
            '启用 SMB 签名与 LAPS，禁用 NTLM 回退，限制 PsExec/WMI 来源',
        ],
        "event": event,
    }
