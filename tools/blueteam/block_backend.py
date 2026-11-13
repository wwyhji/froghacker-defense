"""Block Backend — 封 IP 后端抽象.

把「封 IP」从 dynamic_defense 抽离，支持多后端切换，是「封 IP 扩展到
网络级设备」的接口层：
  - WindowsFirewallBackend: netsh advfirewall（默认，本机防火墙，需管理员）
  - NullBackend:             不真封 IP，仅记录（测试/非 Windows/演练）
  - 未来可加:                网络设备 API / EDR / 云安全组 / 代理

Usage:
    from tools.blueteam.block_backend import WindowsFirewallBackend
    from tools.blueteam.dynamic_defense import DynamicDefense
    d = DynamicDefense(block_backend=WindowsFirewallBackend())
"""

from __future__ import annotations

import subprocess
import sys
from abc import ABC, abstractmethod
from typing import List


class BlockBackend(ABC):
    """封 IP 后端抽象接口。"""

    @abstractmethod
    def block(self, ip: str, reason: str = "") -> bool:
        """封禁 IP，返回是否成功。"""

    @abstractmethod
    def unblock(self, ip: str) -> bool:
        """解封 IP，返回是否成功。"""

    @abstractmethod
    def list_blocked(self) -> List[str]:
        """列出已封禁的 IP。"""


class WindowsFirewallBackend(BlockBackend):
    """Windows 防火墙后端 — netsh advfirewall（需管理员权限）。"""

    def __init__(self):
        self._blocked: set = set()

    def _rule_name(self, ip: str) -> str:
        return f"FrogHacker_Block_{ip.replace('.', '_')}"

    def block(self, ip: str, reason: str = "") -> bool:
        if ip in self._blocked:
            return False
        try:
            r = subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 f"name={self._rule_name(ip)}", "dir=in", "action=block",
                 f"remoteip={ip}", "enable=yes"],
                capture_output=True, text=True, errors="replace", timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )
            if r.returncode == 0:
                self._blocked.add(ip)
                return True
        except Exception:
            pass
        return False

    def unblock(self, ip: str) -> bool:
        try:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule",
                 f"name={self._rule_name(ip)}"],
                capture_output=True, text=True, errors="replace", timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )
            self._blocked.discard(ip)
            return True
        except Exception:
            return False

    def list_blocked(self) -> List[str]:
        return sorted(self._blocked)


class NullBackend(BlockBackend):
    """空后端 — 不真封 IP，仅记录（用于测试/非 Windows/演练）。"""

    def __init__(self):
        self._blocked: set = set()

    def block(self, ip: str, reason: str = "") -> bool:
        self._blocked.add(ip)
        return True

    def unblock(self, ip: str) -> bool:
        self._blocked.discard(ip)
        return True

    def list_blocked(self) -> List[str]:
        return sorted(self._blocked)


__all__ = ["BlockBackend", "WindowsFirewallBackend", "NullBackend"]
