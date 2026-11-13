"""tool_invoker.py — 精简版外部工具调用器（defense-oss 剥离版）.

主仓库版依赖 OperationQueue gating + Hub 日志 + 平台架构，此处剥离为
纯 subprocess 封装，提供 `invoke(tool, args, timeout)` → `ToolResult`，
供蜜罐部署/威胁狩猎/加固/防火墙调用外部工具（nmap/docker/sqlmap 等）。

Usage:
    from tools.core.tool_invoker import invoke
    r = invoke("nmap", ["-sV", "target"], timeout=30)
    if r.ok:
        print(r.stdout)
"""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class ToolResult:
    """工具调用结果。"""
    ok: bool = False
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    elapsed_ms: float = 0.0
    timed_out: bool = False


def invoke(tool: str, args: Optional[List[str]] = None, *,
           timeout: Optional[int] = None, cwd: Optional[str] = None,
           env: Optional[Dict[str, str]] = None, capture: bool = True,
           **kwargs) -> ToolResult:
    """调用外部工具，返回 ToolResult。

    timeout 超时或工具未找到时返回 returncode=-1（timed_out=True 区分超时）。
    """
    cmd = [tool] + (args or [])
    start = time.time()
    try:
        proc = subprocess.run(
            cmd, capture_output=capture, text=True, errors="replace",
            timeout=timeout, cwd=cwd, env=env,
            creationflags=(subprocess.CREATE_NO_WINDOW
                           if hasattr(subprocess, "CREATE_NO_WINDOW") else 0),
        )
        return ToolResult(
            ok=proc.returncode == 0,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            returncode=proc.returncode,
            elapsed_ms=(time.time() - start) * 1000,
        )
    except subprocess.TimeoutExpired:
        return ToolResult(
            ok=False, stdout="", stderr="timeout",
            returncode=-1, elapsed_ms=(time.time() - start) * 1000, timed_out=True,
        )
    except FileNotFoundError:
        return ToolResult(
            ok=False, stdout="", stderr=f"tool not found: {tool}",
            returncode=-1, elapsed_ms=(time.time() - start) * 1000,
        )


__all__ = ["ToolResult", "invoke"]
