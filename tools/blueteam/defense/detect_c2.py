"""命令控制通道检测 (Cobalt Strike / Meterpreter / DNS 隧道 / PowerShell 回连)

Source: blueteam coverage blindspot fill (TA0011 c2)
Domain: blueteam / c2_channel
"""

from __future__ import annotations

# Detection signature — 真实 IOC
SIGNATURE = {
    "attack_type": "c2_channel",
    "mitre_tactic": "TA0011",
    "domain": "blueteam",
    "severity": "critical",
    "description": "命令控制通道：Cobalt Strike/Meterpreter beacon、DNS 隧道、PowerShell 编码回连",
    "indicators": {
        "event_codes": [],
        "keywords": [
            'cobalt strike', 'cobaltstrike', 'meterpreter', 'reverse_tcp',
            'reverse_http', 'reverse_https', 'dnscat2', 'iodine',
            'dns tunneling', 'powershell -enc', 'powershell -encodedcommand',
            'encodedcommand', 'empire', 'sliver', 'covenant', 'beacon',
        ],
        "protocols": [],  # http/dns/https 是正常协议，不能作为 C2 独立判据（防误报）
        "fields": {},
    },
}


def detect(event: dict) -> bool:
    """检测事件是否命中 C2 通道特征。

    C2 是网络层行为，无 Windows 事件码可依，仅凭强特征 (关键词/协议) 命中即告警。
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

    # C2 无事件码，仅强特征命中即告警
    return soft


def respond(event: dict) -> dict:
    """告警 + 处置建议。"""
    return {
        "action": "alert",
        "severity": SIGNATURE["severity"],
        "attack_type": SIGNATURE["attack_type"],
        "recommendations": [
            '立即阻断出站连接，定位 beacon 宿主进程并转储内存取证',
            '审计异常 DNS 查询 (高熵域名/超长子域)，启用 DNS 解析日志',
            '禁用 PowerShell 无限制执行策略，监控 encodedcommand 回连',
        ],
        "event": event,
    }
