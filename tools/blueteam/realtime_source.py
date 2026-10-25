"""Real-time event subscription via EvtSubscribe — 真事件驱动.

用 ctypes 直接调 Win32 wevtapi.EvtSubscribe(SignalEvent 模式),实现
内核事件推送 → 信号 → 回调的真事件驱动,替代轮询。

注:pywin32 的 EvtSubscribe 返回的 handle 无法被其 EvtNext 消费(封装 bug),
故用 ctypes 直接调 Win32 API。

Usage:
    from tools.blueteam.realtime_source import RealtimeEventSource
    src = RealtimeEventSource("System", query="*[System[(Level<=3)]]")
    src.run(callback, stop_event)   # 阻塞,事件到来时调 callback
"""

from __future__ import annotations

import ctypes
import threading
import xml.etree.ElementTree as ET
from ctypes import wintypes
from typing import Callable, Dict, Optional

wevtapi = ctypes.WinDLL("wevtapi")
kernel32 = ctypes.WinDLL("kernel32")

# ── Win32 函数签名 ─────────────────────────────────────────────

# EvtSubscribe: 订阅事件(SignalEvent 模式,Callback=NULL)
wevtapi.EvtSubscribe.restype = wintypes.HANDLE
wevtapi.EvtSubscribe.argtypes = [
    wintypes.HANDLE,       # Session (NULL = local)
    wintypes.HANDLE,       # SignalEvent (事件信号句柄)
    wintypes.LPCWSTR,      # ChannelPath
    wintypes.LPCWSTR,      # Query (XPath)
    wintypes.HANDLE,       # Bookmark (NULL)
    ctypes.c_void_p,       # Context (NULL)
    ctypes.c_void_p,       # Callback (NULL = signal mode)
    wintypes.DWORD,        # Flags
]

# EvtNext: 拉取事件(阻塞等待 Timeout 毫秒)
wevtapi.EvtNext.restype = wintypes.BOOL
wevtapi.EvtNext.argtypes = [
    wintypes.HANDLE,                          # ResultSet (subscription handle)
    wintypes.DWORD,                           # EventArraySize
    ctypes.POINTER(wintypes.HANDLE),          # EventArray
    wintypes.DWORD,                           # Timeout (ms)
    wintypes.DWORD,                           # Flags (0)
    ctypes.POINTER(wintypes.DWORD),           # Returned count
]

# EvtRender: 渲染事件(EvtRenderEventXml=1)
wevtapi.EvtRender.restype = wintypes.BOOL
wevtapi.EvtRender.argtypes = [
    wintypes.HANDLE,                          # Context (NULL = default)
    wintypes.HANDLE,                          # Fragment (event handle)
    wintypes.DWORD,                           # Flags (1 = XML)
    wintypes.DWORD,                           # BufferSize
    ctypes.c_void_p,                          # Buffer
    ctypes.POINTER(wintypes.DWORD),           # BufferUsed
    ctypes.POINTER(wintypes.DWORD),           # PropertyCount
]

# EvtClose
wevtapi.EvtClose.restype = wintypes.BOOL
wevtapi.EvtClose.argtypes = [wintypes.HANDLE]

# Flags
EVT_SUBSCRIBE_TO_FUTURE = 1
EVT_RENDER_EVENT_XML = 1

_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


class RealtimeEventSource:
    """真事件驱动的 Windows 事件日志订阅源。"""

    def __init__(self, channel: str, query: str = "*"):
        self.channel = channel
        self.query = query
        self._subscription: Optional[int] = None
        self._signal: Optional[int] = None

    # ── 事件循环 ────────────────────────────────────────────────

    def run(self, callback: Callable[[Dict], None],
            stop_event: Optional[threading.Event] = None) -> int:
        """阻塞运行事件循环,事件到来时调 callback(带 parsed dict)。

        Returns:
            处理的事件总数(停止后)。
        """
        stop = stop_event or threading.Event()
        self._signal = int(kernel32.CreateEventW(None, False, False, None))
        self._subscription = int(wevtapi.EvtSubscribe(
            None, wintypes.HANDLE(self._signal), self.channel, self.query,
            None, None, None, EVT_SUBSCRIBE_TO_FUTURE,
        ))
        if not self._subscription:
            self.close()
            return 0

        total = 0
        try:
            while not stop.is_set():
                # 阻塞等待信号(1 秒超时以检查停止标志)
                wait = kernel32.WaitForSingleObject(
                    wintypes.HANDLE(self._signal), 1000,
                )
                if wait == 0xFFFFFFFF:  # WAIT_FAILED
                    break
                if wait != 0:  # WAIT_TIMEOUT,无事件
                    continue
                # 信号触发 → 拉取并渲染所有待处理事件
                total += self._drain(callback)
        finally:
            self.close()
        return total

    def _drain(self, callback: Callable[[Dict], None]) -> int:
        """拉取并渲染当前待处理的事件。"""
        count = 0
        while True:
            evt = wintypes.HANDLE()
            returned = wintypes.DWORD()
            ok = wevtapi.EvtNext(
                wintypes.HANDLE(self._subscription), 1,
                ctypes.byref(evt), 0, 0, ctypes.byref(returned),
            )
            if not ok or returned.value == 0 or not evt:
                break  # 无更多待处理事件
            try:
                xml = self._render_xml(int(evt))
                parsed = self._parse_xml(xml)
                if parsed:
                    callback(parsed)
                    count += 1
            finally:
                wevtapi.EvtClose(evt)
        return count

    # ── 渲染 ────────────────────────────────────────────────────

    def _render_xml(self, event_handle: int) -> str:
        """EvtRender 渲染事件为 XML(两次调用:查大小 → 渲染)。"""
        used = wintypes.DWORD()
        wevtapi.EvtRender(None, wintypes.HANDLE(event_handle),
                          EVT_RENDER_EVENT_XML, 0, None,
                          ctypes.byref(used), None)
        if used.value == 0:
            return ""
        buf = ctypes.create_unicode_buffer(used.value // 2 + 1)
        wevtapi.EvtRender(None, wintypes.HANDLE(event_handle),
                          EVT_RENDER_EVENT_XML, used.value, buf,
                          ctypes.byref(used), None)
        return buf.value

    # ── 解析 ────────────────────────────────────────────────────

    def _parse_xml(self, xml: str) -> Optional[Dict]:
        try:
            root = ET.fromstring(xml)
        except ET.ParseError:
            return None
        sys_el = root.find(f"{_NS}System")
        if sys_el is None:
            return None
        event_id = sys_el.findtext(f"{_NS}EventID", "")
        level = sys_el.findtext(f"{_NS}Level", "")
        provider_el = sys_el.find(f"{_NS}Provider")
        provider = provider_el.get("Name", "") if provider_el is not None else ""
        time = sys_el.findtext(f"{_NS}TimeCreated", "")
        data_items = [d.text or "" for d in root.iter(f"{_NS}Data") if d.text]
        return {
            "event_id": event_id,
            "level": level,
            "provider": provider,
            "time": time,
            "channel": self.channel,
            "data": data_items,
        }

    # ── 清理 ────────────────────────────────────────────────────

    def close(self) -> None:
        if self._subscription:
            wevtapi.EvtClose(wintypes.HANDLE(self._subscription))
            self._subscription = None
        if self._signal:
            kernel32.CloseHandle(wintypes.HANDLE(self._signal))
            self._signal = None


__all__ = ["RealtimeEventSource"]
