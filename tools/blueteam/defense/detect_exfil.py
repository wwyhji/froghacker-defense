"""数据渗出检测 (压缩打包外传 / rclone·Mega 云同步 / curl·nc 上传)

Source: blueteam coverage blindspot fill (TA0010 exfil)
Domain: blueteam / data_exfiltration
"""

from __future__ import annotations

# Detection signature — 真实 IOC
SIGNATURE = {
    "attack_type": "data_exfiltration",
    "mitre_tactic": "TA0010",
    "domain": "blueteam",
    "severity": "critical",
    "description": "数据渗出：压缩打包后外传、rclone/Megasync 云同步、curl/nc 上传、DNS/HTTP 隧道外带",
    "indicators": {
        "event_codes": ['4663'],
        "keywords": [
            'rclone', 'megasync', '7z a', '7za a', 'winrar a',
            'curl -t', 'nc -e', 'file.io', 'transfer.sh', 'sendspace',
            'exfiltrat', 'tar czf', 'split -b',
        ],
        "protocols": [],  # ftp/smtp/dns 是常见协议，不能作为数据渗出独立判据（防误报）
        "fields": {},
    },
}


def detect(event: dict) -> bool:
    """检测事件是否命中数据渗出特征。

    事件码 4663 (对象访问) 是弱特征，压缩/上传工具关键词是强特征。
    两者都有时需同时命中才告警，避免正常文件读取误报。
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
            '阻断外传通道，核查近期敏感文件访问 (4663) 记录',
            '审查出站流量异常 (体积/时段/目标)，启用 DLP 与出站代理',
            '检查压缩工具与云同步客户端是否为非授权安装',
        ],
        "event": event,
    }
