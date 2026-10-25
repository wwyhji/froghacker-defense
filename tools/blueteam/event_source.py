"""Windows 事件日志结构化拉取源 — 替代 wevtutil subprocess 轮询.

用 win32evtlog.EvtQuery 进程内查询,结构化 XML 解析(而非 wevtutil 文本 grep),
支持 XPath 精确过滤。

权限:非管理员可读 System/Application;Security(4624/4625 登录事件)需管理员。
注:此 pywin32 版本无 EvtSubscribe(回调推送),当前为增量拉取;真推送需 ctypes
调 EvtSubscribe 或安装完整 pywin32。

Usage:
    from tools.blueteam.event_source import EventLogSource
    src = EventLogSource(["System", "Application"])
    events = src.poll(limit=50)   # [{event_id, level, provider, time, ...}]
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Dict, List, Optional

try:
    import win32evtlog
    _HAS_WIN32EVTLOG = True
except ImportError:
    _HAS_WIN32EVTLOG = False

_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

# 默认查询:错误级及以上(Level <= 3)
DEFAULT_QUERY = "*[System[(Level<=3)]]"

# Sysmon 事件日志通道(需管理员读;含进程创建 ID1/网络连接 ID3/驱动加载 ID6 等 EDR 级事件)
# 安装: sysmon64.exe -accepteula -i tools/blueteam/sysmon-config.xml
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"

# 级别映射:1=critical, 2=error, 3=warning, 4=info
LEVEL_NAMES = {"1": "critical", "2": "error", "3": "warning", "4": "info"}


class EventLogSource:
    """Windows 事件日志结构化拉取源。"""

    def __init__(self, channels: Optional[List[str]] = None,
                 query: str = DEFAULT_QUERY):
        self.channels = channels or ["System", "Application"]
        self.query = query

    def poll(self, limit: int = 50) -> List[Dict]:
        """拉取一批结构化事件(跨所有通道)。"""
        events: List[Dict] = []
        for ch in self.channels:
            events.extend(self._poll_channel(ch, limit))
        return events

    # ── 拉取 ────────────────────────────────────────────────────

    def _poll_channel(self, channel: str, limit: int) -> List[Dict]:
        if not _HAS_WIN32EVTLOG:
            return []
        try:
            q = win32evtlog.EvtQuery(
                channel, win32evtlog.EvtQueryForwardDirection, self.query,
            )
        except Exception:
            return []  # 无权限(如 Security)或通道不存在

        try:
            handles = win32evtlog.EvtNext(q, limit)
        except Exception:
            self._close(q)
            return []

        out: List[Dict] = []
        for h in handles:
            try:
                xml = win32evtlog.EvtRender(h, win32evtlog.EvtRenderEventXml)
                parsed = self._parse_xml(xml)
                if parsed:
                    out.append(parsed)
            except Exception:
                continue
        self._close(q)
        return out

    # ── 解析 ────────────────────────────────────────────────────

    def _parse_xml(self, xml: str) -> Optional[Dict]:
        """事件 XML → dict。"""
        try:
            root = ET.fromstring(xml)
        except ET.ParseError:
            return None

        sys_el = root.find(f"{_NS}System")
        if sys_el is None:
            return None

        event_id = sys_el.findtext(f"{_NS}EventID", "")
        level = sys_el.findtext(f"{_NS}Level", "")
        time = sys_el.findtext(f"{_NS}TimeCreated", "")

        provider_el = sys_el.find(f"{_NS}Provider")
        provider = provider_el.get("Name", "") if provider_el is not None else ""

        channel_el = sys_el.find(f"{_NS}Channel")
        channel = channel_el.text if channel_el is not None else ""

        # EventData: Data 子元素,取非空文本
        data_items: List[str] = []
        for data in root.iter(f"{_NS}Data"):
            txt = (data.text or "").strip()
            if txt and txt != "-":
                data_items.append(txt)

        return {
            "event_id": event_id,
            "level": level,
            "level_name": LEVEL_NAMES.get(level, "info"),
            "provider": provider,
            "channel": channel,
            "time": time,
            "data": data_items,
        }

    # ── 辅助 ────────────────────────────────────────────────────

    @staticmethod
    def _close(handle) -> None:
        """关闭查询 handle(兼容不同 pywin32 版本)。"""
        for closer in (getattr(win32evtlog, "EvtClose", None),
                       getattr(handle, "Close", None),
                       getattr(handle, "close", None)):
            if closer:
                try:
                    closer(handle)
                    return
                except Exception:
                    continue


__all__ = ["EventLogSource", "DEFAULT_QUERY", "SYSMON_CHANNEL"]
