"""数据收集暂存检测 (文件集中复制 / 剪贴板捕获 / 键盘记录)

Source: blueteam coverage blindspot fill (TA0009 collect)
Domain: blueteam / data_staging
"""

from __future__ import annotations

# Detection signature — 真实 IOC
SIGNATURE = {
    "attack_type": "data_staging",
    "mitre_tactic": "TA0009",
    "domain": "blueteam",
    "severity": "medium",
    "description": "数据收集暂存：文件集中复制 (xcopy/robocopy)、剪贴板捕获 (GetClipboardData)、键盘记录 (keylogger/SetWindowsHookEx)",
    "indicators": {
        "event_codes": ['4663'],
        "keywords": [
            'xcopy /s', 'robocopy /s', 'robocopy /e', 'dir /s /b',
            'keylogger', 'getasynckeystate', 'setwindowshookex',
            'getclipboarddata', 'setclipboarddata', 'readclipboard',
            'get-clipboard', 'set-clipboard',
            'data staging', 'staged data',
        ],
        "protocols": [],
        "fields": {},
    },
}


def detect(event: dict) -> bool:
    """检测事件是否命中数据收集暂存特征。

    事件码 4663 (对象访问/文件读取) 是弱特征，集中复制/剪贴板/键盘记录
    关键词是强特征。两者都有时需同时命中才告警，避免正常文件读取误报。
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
            '隔离触发数据收集的主机，核查被复制/暂存文件的敏感级别',
            '审计剪贴板与键盘记录 API 调用进程，定位注入/钩子来源',
            '检查集中复制目标目录，确认是否为攻击者暂存点 (staging)',
        ],
        "event": event,
    }
