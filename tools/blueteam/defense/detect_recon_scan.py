"""网络侦察检测 (端口扫描 / SYN·TCP 扫描 / 子域·DNS 枚举)

Source: blueteam coverage blindspot fill (TA0043 recon)
Domain: blueteam / recon_scan
"""

from __future__ import annotations

# Detection signature — 真实 IOC
SIGNATURE = {
    "attack_type": "recon_scan",
    "mitre_tactic": "TA0043",
    "domain": "blueteam",
    "severity": "medium",
    "description": "网络侦察：端口扫描 (nmap/masscan/rustscan)、SYN/TCP 扫描、子域与 DNS 枚举 (amass/sublist3r/dnsrecon)",
    "indicators": {
        "event_codes": [],
        "keywords": [
            'nmap', 'masscan', 'rustscan',
            'sublist3r', 'dnsrecon', 'dnsenum', 'theharvester', 'dnscan',
            'amass enum',
            'syn scan', 'port scan', 'port scanning', 'tcp connect scan',
            'top-ports',
        ],
        "protocols": [],
        "fields": {},
    },
}


def detect(event: dict) -> bool:
    """检测事件是否命中网络侦察特征。

    侦察是网络层行为，无 Windows 事件码可依，仅凭强特征 (关键词) 命中即告警。
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

    return soft


def respond(event: dict) -> dict:
    """告警 + 处置建议。"""
    return {
        "action": "alert",
        "severity": SIGNATURE["severity"],
        "attack_type": SIGNATURE["attack_type"],
        "recommendations": [
            '定位扫描源 IP，结合威胁情报研判是否已知恶意基础设施',
            '审计防火墙/IDS 日志，确认扫描范围与目标端口',
            '评估被扫描资产的暴露面，收紧非必要端口与服务访问控制',
        ],
        "event": event,
    }
