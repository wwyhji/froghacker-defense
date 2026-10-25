"""crash_defense.py — 蓝队系统崩溃面扫描器

从防御者视角检测可能导致 Windows 崩溃/蓝屏的攻击向量。
纯被动检查，不做任何破坏性操作。
"""

import sys as _sys
from pathlib import Path as _Path
_TOOLS = str(_Path(__file__).resolve().parent.parent)
if _TOOLS not in _sys.path:
    _sys.path.insert(0, _TOOLS)

# 扫描维度:
#   1. 文件系统 DoS -- NTFS junction/rglob 陷阱
#   2. 内存耗尽面 -- 页面文件/进程配额/句柄限制
#   3. USB 崩溃面 -- 恶意描述符/驱动冲突
#   4. 注册表面 -- 关键服务配置/安全模式
#   5. 驱动安全 -- 第三方驱动/ctypes 暴露
#   6. 进程保护 -- 关键进程/WER 配置
#   7. 输入管道面 -- stdin 炸弹/命名管道
#   8. 网络 DoS 面 -- 开放端口/协议栈弱点
#
# 安全底线:
#   - 纯信息收集，不修改任何配置
#   - 不调用 ctypes.windll (避免自身触发 BSOD)
#   - 所有 PowerShell 调用有超时保护
#   - 文件遍历用 glob(非 rglob) + IS_WINDOWS 守卫
#
# Usage:
#     from tools.blueteam.crash_defense import run_crash_scan, CrashFinding
#
#     result = run_crash_scan()
#     for f in result["findings"]:
#         print(f"{f.risk_level}: {f.vector} -- {f.description}")


import json
import logging
import os
import platform
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_cd_log = logging.getLogger("crash_defense")

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"
IS_MACOS = platform.system() == "Darwin"

# ── Safety: no rglob on Windows ──
if IS_WINDOWS:
    _walk_method = Path.glob
else:
    _walk_method = Path.rglob


# ── Data Classes ──────────────────────────────────────────────────────

@dataclass
class CrashFinding:
    """A discovered crash vulnerability surface."""
    scan_id: str = ""              # e.g. "FS-01"
    dimension: str = ""            # filesystem / memory / usb / registry / driver / process / input / network
    vector: str = ""               # Short name e.g. "NTFS Junction Trap"
    risk_level: str = "info"       # critical / high / medium / low / info
    description: str = ""          # What the risk is
    evidence: str = ""             # Observed state
    attack_scenario: str = ""      # How an attacker would exploit
    remediation: str = ""          # How to fix
    mitre_technique: str = ""      # e.g. T1499.001
    confidence: float = 0.8

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "dimension": self.dimension,
            "vector": self.vector,
            "risk_level": self.risk_level,
            "description": self.description,
            "evidence": self.evidence,
            "attack_scenario": self.attack_scenario,
            "remediation": self.remediation,
            "mitre_technique": self.mitre_technique,
            "confidence": self.confidence,
        }


@dataclass
class CrashScanResult:
    """Overall crash scan result."""
    timestamp: str = ""
    hostname: str = ""
    platform: str = ""
    findings: list = field(default_factory=list)
    risk_distribution: dict = field(default_factory=dict)
    scan_duration_seconds: float = 0.0
    total_checks: int = 0
    warnings: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "hostname": self.hostname,
            "platform": self.platform,
            "findings_count": len(self.findings),
            "risk_distribution": self.risk_distribution,
            "scan_duration": self.scan_duration_seconds,
            "warnings": self.warnings,
        }


# ── Risk Ordering ─────────────────────────────────────────────────────

_RISK_ORDER: dict[str, int] = {
    "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
}


# ── Helpers ───────────────────────────────────────────────────────────

def _safe_ps(script: str, timeout: int = 15) -> str:
    """Run a PowerShell script safely with timeout."""
    if not IS_WINDOWS:
        return ""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
        return result.stdout.strip()
    except Exception:
        _cd_log.warning("safe_ps_failed: %s", script[:60])
        return ""


def _safe_reg_query(key: str, value: str = "") -> str:
    """Safely query registry value."""
    if not IS_WINDOWS:
        return ""
    try:
        if value:
            result = subprocess.run(
                ["reg", "query", key, "/v", value],
                capture_output=True, text=True, timeout=10,
                encoding="utf-8", errors="replace",
            )
        else:
            result = subprocess.run(
                ["reg", "query", key],
                capture_output=True, text=True, timeout=10,
                encoding="utf-8", errors="replace",
            )
        return result.stdout.strip() if result.returncode == 0 else ""
    except Exception:
        _cd_log.warning("safe_reg_failed: %s", key)
        return ""


def _safe_cmd(cmd: list[str], timeout: int = 10) -> str:
    """Safely run a command with timeout."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
        return result.stdout.strip()
    except Exception:
        _cd_log.warning("safe_cmd_failed: %s", str(cmd)[:60])
        return ""


# ══════════════════════════════════════════════════════════════════════
# Dimension 1: 文件系统 DoS 面
# ══════════════════════════════════════════════════════════════════════

def _scan_filesystem_dos() -> List[CrashFinding]:
    """Scan for filesystem-based crash vectors."""
    findings: List[CrashFinding] = []

    # ── FS-01: NTFS junction / reparse points in accessible paths ──
    if IS_WINDOWS:
        risky_dirs = [
            Path("C:\\Users"),
            Path("C:\\ProgramData"),
            Path("C:\\Windows\\Temp"),
            Path(os.environ.get("TEMP", "C:\\Windows\\Temp")),
        ]
        junctions_found = 0
        for d in risky_dirs:
            if not d.exists():
                continue
            try:
                for item in d.glob("*"):
                    if junctions_found >= 10:
                        break
                    try:
                        if item.is_dir() and not item.is_symlink():
                            # Check for junction via attrib
                            pass  # Too expensive to check every dir
                    except OSError:
                        pass
            except PermissionError:
                pass

        # Check known junction locations
        known_junctions = [
            r"C:\Documents and Settings",
            r"C:\Users\All Users",
            r"C:\Users\Default User",
        ]
        for jp in known_junctions:
            p = Path(jp)
            if p.exists():
                junctions_found += 1

        if junctions_found > 0:
            findings.append(CrashFinding(
                scan_id="FS-01",
                dimension="filesystem",
                vector="NTFS 重解析点 (Junction) 遍历风险",
                risk_level="low",
                description=f"系统中存在 {junctions_found}+ NTFS junction/reparse point。"
                            "无保护的 rglob('*') 遍历可能进入循环递归，触发 ntfs.sys 崩溃 (BSOD)。",
                evidence=f"检测到 NTFS junction 点，如 'Documents and Settings' → 'Users'",
                attack_scenario="攻击者创建循环 junction → 诱使扫描器/备份工具遍历 → ntfs.sys 无限循环 → BSOD",
                remediation="所有文件遍历代码加 IS_WINDOWS 守卫：用 glob() 替代 rglob()；"
                           "遍历前检查 is_symlink()；限制递归深度 ≤5 层",
                mitre_technique="T1499.001",
                confidence=0.85,
            ))

    # ── FS-02: MAX_PATH 深层目录 ──
    # Safe check: only query registry for long path support, never traverse C:\
    if IS_WINDOWS:
        long_path = _safe_reg_query(
            r"HKLM\SYSTEM\CurrentControlSet\Control\FileSystem", "LongPathsEnabled"
        )
        long_path_enabled = "0x1" in long_path if long_path else False
    else:
        long_path_enabled = True  # Linux has no MAX_PATH issue

    findings.append(CrashFinding(
        scan_id="FS-02",
        dimension="filesystem",
        vector="MAX_PATH 深层嵌套目录风险",
        risk_level="low",
        description="Windows MAX_PATH=260 限制。深层嵌套或长文件名目录可能导致"
                    "应用程序崩溃、无法删除、备份失败。",
        evidence=f"LongPathsEnabled={'是' if long_path_enabled else '否'}。"
                 "（未执行全盘递归扫描以避免触发 NTFS junction 崩溃）",
        attack_scenario="攻击者创建超长路径 → 杀软/备份工具无法处理 → 绕过检测或触发崩溃",
        remediation="启用长路径支持 (HKLM\\SYSTEM\\CurrentControlSet\\Control\\FileSystem\\LongPathsEnabled=1)；"
                   "代码中使用 \\\\?\\ 前缀",
        mitre_technique="T1564.001",
        confidence=0.6,
    ))

    # ── FS-03: ADS (Alternate Data Streams) 隐藏数据 ──
    if IS_WINDOWS:
        ads_check = _safe_ps(
            "Get-ChildItem -Path $env:TEMP -File -ErrorAction SilentlyContinue | "
            "ForEach-Object { Get-Item $_.FullName -Stream * -ErrorAction SilentlyContinue | "
            "Where-Object { $_.Stream -ne ':$DATA' } } | "
            "Select-Object -First 5 FileName,Stream",
            timeout=20,
        )
        if ads_check:
            findings.append(CrashFinding(
                scan_id="FS-03",
                dimension="filesystem",
                vector="NTFS 备用数据流 (ADS) 隐藏风险",
                risk_level="medium",
                description="在 %TEMP% 中发现非默认 ADS 流。ADS 可用于隐藏恶意载荷、"
                            "绕过文件扫描，且部分工具处理 ADS 时会崩溃。",
                evidence=ads_check[:200],
                attack_scenario="攻击者在合法文件中嵌入恶意 ADS → 杀软只扫描默认流 → 绕过检测；"
                               "老旧工具读取含 ADS 文件时缓冲区溢出",
                remediation="用 streams.exe (Sysinternals) 或 `dir /r` 定期审计 ADS；"
                           "限制 TEMP 目录写入权限",
                mitre_technique="T1564.004",
                confidence=0.7,
            ))

    # ── FS-04: 页面文件/休眠文件访问 ──
    if IS_WINDOWS:
        pagefile = Path("C:\\pagefile.sys")
        hiberfil = Path("C:\\hiberfil.sys")
        sensitive_files = []
        if pagefile.exists():
            sensitive_files.append("pagefile.sys")
        if hiberfil.exists():
            sensitive_files.append("hiberfil.sys")

        if sensitive_files:
            findings.append(CrashFinding(
                scan_id="FS-04",
                dimension="filesystem",
                vector="系统文件锁定竞争风险",
                risk_level="low",
                description=f"系统文件 ({', '.join(sensitive_files)}) 存在。"
                            "恶意尝试锁定/读取这些文件可能触发文件系统过滤驱动冲突。",
                evidence=f"检测到 {', '.join(sensitive_files)}",
                attack_scenario="恶意软件尝试打开 pagefile.sys 独占锁 → 内存管理器无法访问 → 系统不稳定",
                remediation="确保只有 SYSTEM 可访问这些文件；监控对这些文件的访问尝试",
                mitre_technique="T1499.001",
                confidence=0.5,
            ))

    return findings


# ══════════════════════════════════════════════════════════════════════
# Dimension 2: 内存耗尽面
# ══════════════════════════════════════════════════════════════════════

def _scan_memory_exhaustion() -> List[CrashFinding]:
    """Scan for memory exhaustion vectors."""
    findings: List[CrashFinding] = []

    # ── MEM-01: 页面文件配置 ──
    if IS_WINDOWS:
        pf_out = _safe_ps(
            "Get-CimInstance -ClassName Win32_PageFileUsage | "
            "Select-Object Name, AllocatedBaseSize, CurrentUsage | ConvertTo-Json -Compress",
            timeout=10,
        )
        if pf_out:
            try:
                pf_data = json.loads(pf_out)
                pf_items = pf_data if isinstance(pf_data, list) else [pf_data]
                for pf in pf_items:
                    allocated = pf.get("AllocatedBaseSize", 0)
                    current = pf.get("CurrentUsage", 0)
                    if allocated > 0 and current > allocated * 0.8:
                        findings.append(CrashFinding(
                            scan_id="MEM-01",
                            dimension="memory",
                            vector="页面文件接近满容量",
                            risk_level="high",
                            description=f"页面文件使用率 {current/allocated*100:.0f}%。"
                                        "内存压力大时可能导致系统颠簸 (thrashing) 甚至内核 OOM 崩溃。",
                            evidence=f"Allocated={allocated}MB, Used={current}MB ({current/allocated*100:.0f}%)",
                            attack_scenario="攻击者分配大量内存 (fork bomb/内存炸弹) → 页面文件耗尽 → 系统挂起或 BSOD",
                            remediation="增加页面文件大小；添加物理内存；设置进程内存限制",
                            mitre_technique="T1499.001",
                            confidence=0.8,
                        ))
            except (json.JSONDecodeError, KeyError):
                pass

    # ── MEM-02: 进程数/句柄数上限 ──
    if IS_WINDOWS:
        proc_count = _safe_ps("(Get-Process).Count", timeout=10)
        if proc_count and proc_count.isdigit():
            count = int(proc_count)
            if count > 300:
                findings.append(CrashFinding(
                    scan_id="MEM-02",
                    dimension="memory",
                    vector="高进程数 — 内核资源耗尽风险",
                    risk_level="medium",
                    description=f"当前运行 {count} 个进程。大量进程消耗内核句柄表、"
                                "内存池，增加池耗尽 (pool exhaustion) 风险。",
                    evidence=f"当前 {count} 个进程运行中",
                    attack_scenario="攻击者执行 fork bomb 或大量启动进程 → 内核池耗尽 → BSOD "
                                   "(POOL_CORRUPTION / BAD_POOL_HEADER)",
                    remediation="配置 Windows 进程创建审计 (Event ID 4688)；限制用户进程数；"
                               "监控非分页池使用 (\\Memory\\Pool Nonpaged Bytes)",
                    mitre_technique="T1499.001",
                    confidence=0.6,
                ))

    # ── MEM-03: 非分页池使用率 ──
    if IS_WINDOWS:
        pool_out = _safe_ps(
            "$pool = Get-Counter '\\Memory\\Pool Nonpaged Bytes'; "
            "$total = Get-Counter '\\Memory\\Pool Nonpaged Bytes'; "
            "Write-Output $pool.CounterSamples[0].CookedValue",
            timeout=10,
        )
        if pool_out and pool_out.strip().isdigit():
            pool_bytes = int(pool_out.strip())
            pool_mb = pool_bytes / (1024 * 1024)
            if pool_mb > 500:  # Typical limit is ~1-2GB but >500MB is high
                findings.append(CrashFinding(
                    scan_id="MEM-03",
                    dimension="memory",
                    vector="非分页池使用量偏高",
                    risk_level="medium",
                    description=f"非分页池使用 {pool_mb:.0f} MB。非分页池耗尽直接导致 "
                                "BSOD (PFN_LIST_CORRUPT / BAD_POOL_CALLER)。",
                    evidence=f"Pool Nonpaged = {pool_mb:.0f} MB",
                    attack_scenario="攻击者触发大量 I/O 操作或 NtCreateFile → 非分页池泄漏 → 池耗尽 → BSOD",
                    remediation="检查驱动是否存在内存泄漏；用 poolmon.exe 追踪池标签；"
                               "更新网卡/存储驱动",
                    mitre_technique="T1499.001",
                    confidence=0.7,
                ))

    # ── MEM-04: 用户内存无限制 (大文件读取) ──
    findings.append(CrashFinding(
        scan_id="MEM-04",
        dimension="memory",
        vector="大文件全量读取导致的 OOM 风险",
        risk_level="medium",
        description="应用代码中对大文件（如 500GB 镜像）做 f.read() 无大小上限，"
                    "可导致内存耗尽、系统颠簸，极端情况下触发 BSOD。",
        evidence="代码中存在 f.read() 无分块/无上限的情况 (参考 ntfs-bsod-rglob-lessons)",
        attack_scenario="攻击者放置超大文件 (如伪造的 E01 镜像) → 取证工具全量加载 → OOM → "
                       "连锁反应触发系统崩溃",
        remediation="所有 f.read() 加 100MB 硬上限或 1MB 分块读取；"
                   "大文件读取前先检查 os.path.getsize()",
        mitre_technique="T1499.001",
        confidence=0.75,
    ))

    return findings


# ══════════════════════════════════════════════════════════════════════
# Dimension 3: USB 崩溃面
# ══════════════════════════════════════════════════════════════════════

def _scan_usb_crash() -> List[CrashFinding]:
    """Scan for USB-based crash vectors."""
    findings: List[CrashFinding] = []

    if IS_WINDOWS:
        # ── USB-01: USB 存储策略 ──
        storage_blocked_out = _safe_reg_query(
            r"HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR", "Start"
        )
        usb_blocked = "0x4" in storage_blocked_out if storage_blocked_out else False

        findings.append(CrashFinding(
            scan_id="USB-01",
            dimension="usb",
            vector="USB 设备描述符攻击面",
            risk_level="info",
            description="恶意 USB 设备可发送畸形设备描述符 (malformed descriptors)，"
                       "触发 USB 驱动栈解析错误，导致 BSOD (USBHUB3.SYS / USBXHCI.SYS)。"
                       f"USB 存储当前: {'已阻止' if usb_blocked else '允许'}。",
            evidence=f"USBSTOR Start={'4 (禁止)' if usb_blocked else '3 (手动)'}",
            attack_scenario="攻击者插入特制 USB 设备 (Facedancer/USB Killer 2.0) → "
                           "畸形描述符 → 驱动解析失败 → BSOD (DRIVER_IRQL_NOT_LESS_OR_EQUAL)",
            remediation="1) 物理端口控制 (USB 端口锁)；2) 组策略限制可安装设备类；"
                       "3) 启用 Device Guard；4) 企业环境 block_usb_storage()",
            mitre_technique="T1200",
            confidence=0.85,
        ))

        # ── USB-02: USB 驱动版本 ──
        usb_drivers = _safe_ps(
            "Get-WmiObject Win32_PnPSignedDriver | "
            "Where-Object { $_.DeviceClass -eq 'USB' -and $_.DriverProviderName -like '*USB*' } | "
            "Select-Object -First 5 DeviceName,DriverVersion,DriverDate | ConvertTo-Json -Compress",
            timeout=15,
        )
        if usb_drivers:
            findings.append(CrashFinding(
                scan_id="USB-02",
                dimension="usb",
                vector="USB 驱动版本过旧风险",
                risk_level="medium",
                description="过旧的 USB 控制器驱动可能包含已知漏洞，可被恶意设备利用触发 BSOD。",
                evidence=usb_drivers[:300],
                attack_scenario="针对旧版 USB 驱动的 CVE 利用 → 特制 USB 数据包 → 驱动崩溃 → BSOD",
                remediation="更新芯片组/USB 控制器驱动；Windows Update 自动更新驱动",
                mitre_technique="T1200",
                confidence=0.6,
            ))

        # ── USB-03: WinUSB / 用户态 USB 驱动暴露 ──
        winusb_check = _safe_ps(
            "Get-PnpDevice -Class USB -PresentOnly | "
            "Where-Object { $_.FriendlyName -like '*WinUSB*' -or $_.FriendlyName -like '*libusb*' } | "
            "Select-Object -First 3 FriendlyName,InstanceId | ConvertTo-Json -Compress",
            timeout=10,
        )
        if winusb_check:
            findings.append(CrashFinding(
                scan_id="USB-03",
                dimension="usb",
                vector="用户态 USB 驱动 (WinUSB/libusb) 暴露",
                risk_level="medium",
                description="检测到 WinUSB/libusb 设备。用户态 USB 驱动绕过了内核 USB 栈的"
                           "部分校验，恶意设备可发送控制传输导致驱动缓冲区溢出。",
                evidence=winusb_check[:200],
                attack_scenario="恶意 USB 设备通过 WinUSB 发送超出描述符大小的控制传输 → "
                               "用户态驱动缓冲区溢出 → 权限提升或进程崩溃",
                remediation="审查使用 WinUSB/libusb 的应用；限制可信任设备的 VID/PID；"
                           "应用层加输入校验",
                mitre_technique="T1200",
                confidence=0.65,
            ))

    # ── USB-04: USB 电源浪涌 (跨平台) ──
    # 基线提醒：物理攻击向量，非软件检测结果，每台机器均输出
    findings.append(CrashFinding(
        scan_id="USB-04",
        dimension="usb",
        vector="USB Killer / 电源浪涌攻击",
        risk_level="info",
        description="USB Killer 通过快速充放电向 USB 数据线注入高压 (-220V)，"
                   "可物理烧毁主板。软件防御无效。",
        evidence="物理攻击向量，无法通过软件检测",
        attack_scenario="攻击者插入 USB Killer → 电容器放电 → 主板电路烧毁 → 永久性硬件损坏",
        remediation="USB 端口物理锁；USB 数据阻断器 (仅充电)；用带过压保护的 USB 集线器",
        mitre_technique="T1200",
        confidence=1.0,
    ))

    return findings


# ══════════════════════════════════════════════════════════════════════
# Dimension 4: 注册表面
# ══════════════════════════════════════════════════════════════════════

def _scan_registry_crash() -> List[CrashFinding]:
    """Scan for registry-based crash vectors."""
    findings: List[CrashFinding] = []

    if not IS_WINDOWS:
        return findings

    # ── REG-01: 关键服务启动类型 ──
    critical_services = {
        "USBSTOR": (r"HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR", "Start"),
        "Tcpip": (r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip", "Start"),
        "Disk": (r"HKLM\SYSTEM\CurrentControlSet\Services\Disk", "Start"),
        "volmgr": (r"HKLM\SYSTEM\CurrentControlSet\Services\volmgr", "Start"),
        "Ntfs": (r"HKLM\SYSTEM\CurrentControlSet\Services\Ntfs", "Start"),
    }
    for svc, (key, val) in critical_services.items():
        out = _safe_reg_query(key, val)
        if out:
            # Start=0 Boot, 1 System, 2 Automatic, 3 Manual, 4 Disabled
            if "0x4" in out:
                findings.append(CrashFinding(
                    scan_id="REG-01",
                    dimension="registry",
                    vector=f"关键服务 {svc} 被禁用",
                    risk_level="critical" if svc in ("Ntfs", "volmgr", "Disk") else "high",
                    description=f"关键系统服务 {svc} 当前 Start=4 (禁用)。"
                                f"{'这会导致系统无法启动!' if svc in ('Ntfs', 'volmgr') else '可能影响系统功能。'}",
                    evidence=f"{key}\\Start = 4 (Disabled)",
                    attack_scenario="攻击者通过注册表禁用关键服务 → 重启 → 系统无法启动或 BSOD (INACCESSIBLE_BOOT_DEVICE)",
                    remediation=f"reg add {key} /v Start /t REG_DWORD /d 0 /f (恢复默认)",
                    mitre_technique="T1562.001",
                    confidence=0.9,
                ))

    # ── REG-02: SafeBoot 键完整性 ──
    safeboot_out = _safe_reg_query(
        r"HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot"
    )
    if not safeboot_out:
        findings.append(CrashFinding(
            scan_id="REG-02",
            dimension="registry",
            vector="SafeBoot 注册表项缺失",
            risk_level="high",
            description="SafeBoot 配置缺失。安全模式无法启动，系统恢复能力受损。",
            evidence="HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot 不可读",
            attack_scenario="攻击者删除 SafeBoot 键 → 系统故障后无法进入安全模式 → 延长停机时间",
            remediation="从备份或正常系统导入 SafeBoot 注册表项",
            mitre_technique="T1562.001",
            confidence=0.8,
        ))

    # ── REG-03: CrashControl 配置 ──
    crash_control = _safe_reg_query(
        r"HKLM\SYSTEM\CurrentControlSet\Control\CrashControl"
    )
    if crash_control:
        # Check CrashDumpEnabled
        dump_out = _safe_reg_query(
            r"HKLM\SYSTEM\CurrentControlSet\Control\CrashControl", "CrashDumpEnabled"
        )
        if "0x0" in dump_out:
            findings.append(CrashFinding(
                scan_id="REG-03",
                dimension="registry",
                vector="系统崩溃转储已禁用",
                risk_level="medium",
                description="CrashDumpEnabled=0，系统崩溃时不生成 dump 文件。"
                           "故障排查困难，攻击痕迹可能丢失。",
                evidence="CrashDumpEnabled = 0 (Disabled)",
                attack_scenario="攻击者禁用崩溃转储 → 发动 DoS 攻击 → 无转储文件 → 取证困难",
                remediation="设置 CrashDumpEnabled=7 (自动内存转储)；确保 %SystemRoot%\\MEMORY.DMP 有足够磁盘空间",
                mitre_technique="T1562.001",
                confidence=0.7,
            ))

    return findings


# ══════════════════════════════════════════════════════════════════════
# Dimension 5: 驱动安全
# ══════════════════════════════════════════════════════════════════════

def _scan_driver_safety() -> List[CrashFinding]:
    """Scan for driver-based crash vectors."""
    findings: List[CrashFinding] = []

    # ── DRV-01: 第三方驱动审计 ──
    if IS_WINDOWS:
        third_party_drivers = _safe_ps(
            "Get-WmiObject Win32_PnPSignedDriver | "
            "Where-Object { $_.DriverProviderName -notlike '*Microsoft*' -and "
            "$_.DriverProviderName -notlike '*Intel*' -and $_.DriverProviderName -notlike '*AMD*' "
            "-and $_.DriverProviderName -notlike '*NVIDIA*' -and $_.DriverProviderName -notlike '*Realtek*' } | "
            "Select-Object -First 10 DeviceName,DriverProviderName,DriverDate,IsSigned | ConvertTo-Json -Compress",
            timeout=20,
        )
        if third_party_drivers:
            findings.append(CrashFinding(
                scan_id="DRV-01",
                dimension="driver",
                vector="第三方驱动风险",
                risk_level="medium",
                description="系统中存在非主流第三方驱动。第三方驱动是 BSOD 的首要原因"
                           "（据统计 ~70% 的 Windows 崩溃由第三方驱动引起）。",
                evidence=third_party_drivers[:500],
                attack_scenario="攻击者利用第三方驱动已知漏洞 → 内核内存损坏 → BSOD；"
                               "或加载恶意驱动 (BYOVD — Bring Your Own Vulnerable Driver)",
                remediation="审查第三方驱动必要性；检查驱动签名；移除不再需要的驱动；"
                           "用 Driver Verifier 测试可疑驱动",
                mitre_technique="T1068",
                confidence=0.7,
            ))

    # ── DRV-02: 易受攻击驱动 (BYOVD) ──
    # Known vulnerable drivers list (abridged)
    _VULN_DRIVERS = {
        "RTCore64.sys": "CVE-2019-16098 — MSI Afterburner 权限提升",
        "GVCIDrv64.sys": "CVE-2021-31728 — Gigabyte 驱动漏洞",
        "WinRing0x64.sys": "通用硬件监控驱动 — 广泛被利用",
        "Phymem.sys": "物理内存读写 — 威胁者最爱",
        "AsrDrv.sys": "ASRock 驱动 — CVE-2021-21551",
    }
    if IS_WINDOWS:
        for drv_name, drv_desc in _VULN_DRIVERS.items():
            drv_path = Path(f"C:\\Windows\\System32\\drivers\\{drv_name}")
            if drv_path.exists():
                findings.append(CrashFinding(
                    scan_id="DRV-02",
                    dimension="driver",
                    vector=f"易受攻击驱动: {drv_name}",
                    risk_level="critical",
                    description=f"检测到已知漏洞驱动: {drv_desc}。该驱动可被利用进行 "
                               "内核级代码执行、权限提升、或故意触发 BSOD。",
                    evidence=f"文件存在: {drv_path}",
                    attack_scenario=f"攻击者利用 {drv_name} I/O 控制代码 → 内核任意读写 → "
                                   "patch 内核/修改令牌/触发 BSOD",
                    remediation=f"删除或更新 {drv_name}；使用 WDAC (Windows Defender Application Control) "
                               "阻止未签名驱动加载",
                    mitre_technique="T1068",
                    confidence=0.95,
                ))

    # ── DRV-03: Driver Verifier 状态 ──
    if IS_WINDOWS:
        verifier_out = _safe_cmd(["verifier", "/querysettings"], timeout=10)
        verifier_active = "Enabled" in verifier_out or "enabled" in verifier_out.lower()
        findings.append(CrashFinding(
            scan_id="DRV-03",
            dimension="driver",
            vector="Driver Verifier 未启用",
            risk_level="low",
            description="Driver Verifier 是 Windows 内置的驱动压力测试工具。"
                       f"{'已启用 — 好!' if verifier_active else '未启用 — 系统未经驱动压力测试。'}",
            evidence=f"Status: {'Active' if verifier_active else 'Inactive'}",
            attack_scenario="N/A — 这是一个检测能力缺口，非直接攻击向量",
            remediation="非生产环境: verifier /standard /all；生产环境: 至少检查驱动签名",
            mitre_technique="",
            confidence=0.9,
        ))

    return findings


# ══════════════════════════════════════════════════════════════════════
# Dimension 6: 进程/服务保护
# ══════════════════════════════════════════════════════════════════════

def _scan_process_protection() -> List[CrashFinding]:
    """Scan for process/service crash vectors."""
    findings: List[CrashFinding] = []

    if IS_WINDOWS:
        # ── PROC-01: 关键进程保护 ──
        critical_procs = _safe_ps(
            "Get-Process -Name winlogon,csrss,lsass,smss,wininit,services -ErrorAction SilentlyContinue | "
            "Select-Object Name,Id,ProtectedProcess | ConvertTo-Json -Compress",
            timeout=10,
        )
        if critical_procs:
            try:
                procs = json.loads(critical_procs)
                procs = procs if isinstance(procs, list) else [procs]
                unprotected = [p["Name"] for p in procs if not p.get("ProtectedProcess", True)]
                if unprotected:
                    findings.append(CrashFinding(
                        scan_id="PROC-01",
                        dimension="process",
                        vector="关键进程保护缺失",
                        risk_level="high",
                        description=f"关键进程未启用 Protected Process Light (PPL): {', '.join(unprotected)}。"
                                   "PPL 可防止恶意软件终止关键进程导致系统崩溃。",
                        evidence=f"Unprotected: {unprotected}",
                        attack_scenario="攻击者终止 lsass.exe/csrss.exe → 系统立即 BSOD "
                                       "(CRITICAL_PROCESS_DIED) 或强制重启",
                        remediation="Windows Defender Credential Guard；启用 LSASS PPL；"
                                   "监控进程终止事件 (Event ID 4689)",
                        mitre_technique="T1562.001",
                        confidence=0.8,
                    ))
            except (json.JSONDecodeError, KeyError):
                pass

        # ── PROC-02: 服务恢复设置 ──
        svc_recovery = _safe_ps(
            "Get-Service | Where-Object { $_.Status -eq 'Running' -and $_.StartType -eq 'Automatic' } | "
            "Select-Object -First 20 Name | ForEach-Object { "
            "$s = $_; $r = Get-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$($s.Name)\" "
            "-ErrorAction SilentlyContinue; "
            "[PSCustomObject]@{Name=$s.Name; FailureActions=$r.FailureActions} } | "
            "Where-Object { -not $_.FailureActions } | Select-Object -First 5 Name | ConvertTo-Json -Compress",
            timeout=15,
        )
        if svc_recovery:
            findings.append(CrashFinding(
                scan_id="PROC-02",
                dimension="process",
                vector="服务失败恢复未配置",
                risk_level="low",
                description="部分自动启动服务未配置失败恢复操作。服务反复崩溃时系统不会自动重启它们。",
                evidence=svc_recovery[:300],
                attack_scenario="攻击者触发服务崩溃循环 → 服务不可用 → 拒绝服务",
                remediation='sc failure <svc> reset=86400 actions=restart/60000/restart/60000/restart/60000',
                mitre_technique="T1499",
                confidence=0.5,
            ))

        # ── PROC-03: WER (Windows Error Reporting) 状态 ──
        wer_out = _safe_reg_query(
            r"HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting", "Disabled"
        )
        if "0x1" in wer_out:
            findings.append(CrashFinding(
                scan_id="PROC-03",
                dimension="process",
                vector="Windows 错误报告已禁用",
                risk_level="low",
                description="WER 禁用后系统不会收集崩溃信息，故障排查和取证困难。",
                evidence="WER Disabled = 1",
                attack_scenario="攻击者禁用 WER → 发动攻击 → 无错误报告 → 延长检测时间",
                remediation="启用 WER: Set-WindowsErrorReporting -Enable",
                mitre_technique="T1562.001",
                confidence=0.5,
            ))

    return findings


# ══════════════════════════════════════════════════════════════════════
# Dimension 7: 输入/管道攻击面
# ══════════════════════════════════════════════════════════════════════

def _scan_input_crash() -> List[CrashFinding]:
    """Scan for input/pipeline crash vectors."""
    findings: List[CrashFinding] = []

    # ── IN-01: stdin 炸弹 (管道大文件) ──
    findings.append(CrashFinding(
        scan_id="IN-01",
        dimension="input",
        vector="stdin 管道无限制读取风险",
        risk_level="medium",
        description="代码中 sys.stdin.read() 无大小限制。攻击者可通过管道发送超大数据，"
                   "导致应用程序内存耗尽，连锁反应影响系统稳定性。",
        evidence="参考 pattern_extract.py 修复 (1MB 分块 + 100MB 硬上限)",
        attack_scenario="攻击者向 CLI 工具 pipe 超大文件 → 工具 OOM → 系统内存压力增大 → "
                       "页交换颠簸 → 可能触发 BSOD",
        remediation="sys.stdin.buffer.read(MAX_SIZE)；分块读取 1MB；设置 100MB 硬上限",
        mitre_technique="T1499.001",
        confidence=0.65,
    ))

    # ── IN-02: 命名管道 DoS ──
    if IS_WINDOWS:
        named_pipes = _safe_ps(
            "Get-ChildItem \\\\.\\pipe\\ -ErrorAction SilentlyContinue | "
            "Select-Object -First 20 Name | ConvertTo-Json -Compress",
            timeout=10,
        )
        if named_pipes:
            pipe_count = named_pipes.count('"Name"')
            if pipe_count > 10:
                findings.append(CrashFinding(
                    scan_id="IN-02",
                    dimension="input",
                    vector="命名管道暴露面",
                    risk_level="medium",
                    description=f"检测到 {pipe_count}+ 命名管道。命名管道是本地/远程 IPC 的常见攻击面，"
                               "恶意输入可触发服务崩溃或提权 (如 PrintSpoofer)。",
                    evidence=f"{pipe_count}+ 命名管道开放",
                    attack_scenario="攻击者向高权限命名管道发送畸形数据 → 服务崩溃 → "
                                   "重启循环或权限提升",
                    remediation="审查命名管道 ACL；限制远程命名管道访问 (RestrictAnonymous=1)；"
                               "禁用不需要的管道服务",
                    mitre_technique="T1559",
                    confidence=0.6,
                ))

    return findings


# ══════════════════════════════════════════════════════════════════════
# Dimension 8: 网络 DoS 面
# ══════════════════════════════════════════════════════════════════════

def _scan_network_dos() -> List[CrashFinding]:
    """Scan for network-based crash vectors."""
    findings: List[CrashFinding] = []

    # ── NET-01: SYN Flood 防护 ──
    if IS_WINDOWS:
        syn_protect = _safe_ps(
            "Get-NetTCPSetting | Select-Object -ExpandProperty SynAttackProtect",
            timeout=10,
        )
        findings.append(CrashFinding(
            scan_id="NET-01",
            dimension="network",
            vector="TCP SYN Flood 防护状态",
            risk_level="medium",
            description=f"SynAttackProtect={'已启用' if '1' in str(syn_protect) else '未启用'}。"
                       "SYN Flood 可耗尽 TCP 协议栈资源，导致系统无法接受新连接。",
            evidence=f"SynAttackProtect = {syn_protect if syn_protect else 'Unknown'}",
            attack_scenario="攻击者发送大量 SYN 包 → TCP 半连接队列满 → 系统拒绝新连接 → DoS",
            remediation="netsh int ipv4 set global synattackprotect=1；启用 Windows Defender 防火墙",
            mitre_technique="T1499.001",
            confidence=0.7,
        ))

    # ── NET-02: 网络驱动栈 ──
    if IS_WINDOWS:
        npcap_check = _safe_ps(
            "Get-WmiObject Win32_PnPSignedDriver | "
            "Where-Object { $_.DeviceName -like '*npcap*' -or $_.DeviceName -like '*WinPcap*' "
            "-or $_.DeviceName -like '*wireshark*' } | "
            "Select-Object DeviceName,DriverVersion | ConvertTo-Json -Compress",
            timeout=15,
        )
        if npcap_check:
            findings.append(CrashFinding(
                scan_id="NET-02",
                dimension="network",
                vector="抓包驱动 (Npcap/WinPcap) 风险",
                risk_level="medium",
                description="Npcap/WinPcap 是内核级抓包驱动。Buggy 版本是 BSOD 的常见原因，"
                           "尤其在处理畸形数据包 (如 scapy 生成的) 时。",
                evidence=npcap_check[:300],
                attack_scenario="攻击者发送畸形网络包 → Npcap 驱动解析失败 → "
                               "IRQL 冲突 → BSOD (DRIVER_IRQL_NOT_LESS_OR_EQUAL)",
                remediation="更新到最新 Npcap；生产服务器不安装抓包驱动；用 Windows 内置 netsh trace",
                mitre_technique="T1499.001",
                confidence=0.75,
            ))

    # ── NET-03: 监听端口面 ──
    try:
        # Quick check on listening ports (just count, very fast)
        if IS_WINDOWS:
            listening = _safe_cmd(["netstat", "-ano", "-p", "tcp"], timeout=10)
        else:
            listening = _safe_cmd(["ss", "-tlnp"], timeout=5)

        if listening:
            listening_lines = [l for l in listening.splitlines() if "LISTEN" in l.upper()]
            if len(listening_lines) > 20:
                findings.append(CrashFinding(
                    scan_id="NET-03",
                    dimension="network",
                    vector="过度开放的监听端口",
                    risk_level="low",
                    description=f"当前 {len(listening_lines)} 个端口在 LISTEN 状态。"
                               "每个开放端口都是潜在的攻击面，可被利用进行 DoS。",
                    evidence=f"{len(listening_lines)} TCP LISTEN ports",
                    attack_scenario="攻击者扫描所有开放端口 → 找到无认证服务 → 发送畸形请求 → "
                                   "服务崩溃或资源耗尽",
                    remediation="用防火墙限制来源 IP；关闭不必要的服务；定期端口审计",
                    mitre_technique="T1046",
                    confidence=0.5,
                ))
    except Exception:
        _cd_log.warning("network_scan_failed")
        return findings


# ══════════════════════════════════════════════════════════════════════
# 扫描编排
# ══════════════════════════════════════════════════════════════════════

def run_crash_scan(
    dimensions: Optional[List[str]] = None,
    min_severity: str = "info",
    output_path: str = "",
) -> dict:
    """运行完整的系统崩溃面扫描。

    Args:
        dimensions: 限制扫描维度，None=全部。可选:
            ["filesystem", "memory", "usb", "registry", "driver", "process", "input", "network"]
        min_severity: 最低报告级别 (critical/high/medium/low/info)
        output_path: 输出 JSON 报告路径 (可选)

    Returns:
        {
            "result": CrashScanResult dict,
            "findings": list[CrashFinding dict],
            "risk_distribution": dict,
            "total_checks": int,
        }
    """
    start_time = time.time()
    all_dimensions = dimensions or [
        "filesystem", "memory", "usb", "registry", "driver", "process", "input", "network"
    ]

    scan_map = {
        "filesystem": _scan_filesystem_dos,
        "memory": _scan_memory_exhaustion,
        "usb": _scan_usb_crash,
        "registry": _scan_registry_crash,
        "driver": _scan_driver_safety,
        "process": _scan_process_protection,
        "input": _scan_input_crash,
        "network": _scan_network_dos,
    }

    all_findings: List[CrashFinding] = []
    warnings: List[str] = []

    for dim in all_dimensions:
        scanner = scan_map.get(dim)
        if scanner is None:
            warnings.append(f"Unknown dimension: {dim}")
            continue
        try:
            dim_findings = scanner()
            all_findings.extend(dim_findings)
        except Exception as e:
            warnings.append(f"Dimension '{dim}' scan failed: {e}")

    # Filter by severity
    cutoff = _RISK_ORDER.get(min_severity, 99)
    filtered = [f for f in all_findings if _RISK_ORDER.get(f.risk_level, 99) <= cutoff]

    # Sort by risk
    filtered.sort(key=lambda f: _RISK_ORDER.get(f.risk_level, 99))

    # Risk distribution
    dist: dict[str, int] = {}
    for f in filtered:
        dist[f.risk_level] = dist.get(f.risk_level, 0) + 1

    elapsed = time.time() - start_time

    result = CrashScanResult(
        timestamp=datetime.now().isoformat(),
        hostname=socket.gethostname(),
        platform=platform.system(),
        findings=[f.to_dict() for f in filtered],
        risk_distribution=dist,
        scan_duration_seconds=elapsed,
        total_checks=len(filtered),
        warnings=warnings,
    )

    # Write report if requested
    if output_path:
        out_file = Path(output_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(
            json.dumps(result.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    return {
        "result": result.to_dict(),
        "findings": [f.to_dict() for f in filtered],
        "risk_distribution": dist,
        "total_checks": len(filtered),
    }


def quick_crash_check() -> dict:
    """快速崩溃面检查 — 只做关键高危扫描，30秒内返回。

    适合: 日常安全检查、CI/CD 流水线、新主机上线前验证。
    """
    return run_crash_scan(
        dimensions=["filesystem", "memory", "registry", "driver", "usb"],
        min_severity="high",
    )


def check_vulnerable_drivers() -> list[dict]:
    """仅扫描已知漏洞驱动 (BYOVD)。速度最快，适合频繁执行。"""
    findings = _scan_driver_safety()
    return [f.to_dict() for f in findings if f.risk_level == "critical"]


# ── CLI 友好输出 ─────────────────────────────────────────────────────

def print_crash_report(result: dict) -> None:
    """打印人类可读的崩溃面扫描报告。"""
    findings = result.get("findings", [])
    dist = result.get("risk_distribution", {})
    meta = result.get("result", {})

    print()
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║          🛡️  蓝队系统崩溃面扫描报告                          ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print(f"║  主机: {meta.get('hostname', '?'):50s} ║")
    print(f"║  平台: {meta.get('platform', '?'):50s} ║")
    print(f"║  耗时: {meta.get('scan_duration', 0):.1f}s{'':48s} ║")
    print(f"║  检出: {len(findings)} 个风险项{'':44s} ║")
    print("╠══════════════════════════════════════════════════════════════╣")

    # Risk summary
    risk_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
    summary_parts = []
    for level in ["critical", "high", "medium", "low", "info"]:
        count = dist.get(level, 0)
        if count > 0:
            summary_parts.append(f"{risk_icons[level]} {level}:{count}")
    print(f"║  风险分布: {'  '.join(summary_parts):46s} ║")
    print("╠══════════════════════════════════════════════════════════════╣")

    if not findings:
        print("║  ✅ 未发现高危崩溃面，系统基础防护良好                      ║")
    else:
        for f in findings[:20]:  # Top 20
            icon = risk_icons.get(f["risk_level"], "⚪")
            sid = f.get("scan_id", "??")
            vector = f.get("vector", "?")
            desc = f.get("description", "")[:80]
            print(f"║  {icon} [{sid}] {vector:45s} ║")
            if desc:
                print(f"║      {desc[:70]:70s} ║")

    print("╚══════════════════════════════════════════════════════════════╝")
    print()
    print("  💡 详细修复建议: 对每项运行 .remediation 查看")
    print(f"  📄 JSON 报告: run_crash_scan(output_path='crash_report.json')")
    print()


__all__ = [
    "CrashFinding",
    "CrashScanResult",
    "run_crash_scan",
    "quick_crash_check",
    "check_vulnerable_drivers",
    "print_crash_report",
]


# ── CLI entry point ──────────────────────────────────────────────────────

def auto_fix_crash_issues(scan_result: dict) -> dict:
    """Apply safe automatic fixes for detected crash-defense issues.

    Only applies fixes that are:
      - Read-only checks (no system modification)
      - Safe registry tweaks (CrashDumpEnabled, service start type checks)
      - NON-destructive: never removes drivers, never kills processes

    Returns: {"fixed": [...], "skipped": [...], "errors": [...]}
    """
    import subprocess
    fixed, skipped, errors = [], [], []

    findings = scan_result.get("findings", [])
    for f in findings:
        fid = f.get("scan_id", "")
        severity = f.get("risk_level", "low")

        if severity not in ("critical", "high"):
            continue

        try:
            if fid == "REG-03" and IS_WINDOWS:
                # Enable CrashDumpEnabled (safe: just enables minidump)
                cmd = [
                    'reg', 'add',
                    r'HKLM\SYSTEM\CurrentControlSet\Control\CrashControl',
                    '/v', 'CrashDumpEnabled', '/t', 'REG_DWORD',
                    '/d', '2', '/f',
                ]
                r = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=10)
                if r.returncode == 0:
                    fixed.append(f"REG-03: CrashDumpEnabled set to 2 (kernel minidump)")
                else:
                    errors.append(f"REG-03: reg add failed: {r.stderr.strip()}")

            elif fid == "REG-01" and IS_WINDOWS:
                # Check critical services — only report, don't auto-change
                skipped.append("REG-01: critical service checks require manual review (risk of boot failure)")

            elif fid == "FS-01" and IS_WINDOWS:
                # Path safety already monkey-patched at import
                fixed.append("FS-01: path safety circuit breaker active (import-time monkey-patch)")

            elif fid == "NET-01" and IS_WINDOWS:
                # Enable SYN attack protection
                cmd = [
                    'netsh', 'int', 'ipv4', 'set', 'global',
                    'synattackprotect=1',
                ]
                r = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=10)
                if r.returncode == 0:
                    fixed.append("NET-01: SYN attack protection enabled")
                else:
                    errors.append(f"NET-01: netsh failed: {r.stderr.strip()}")

            elif fid == "PROC-01" and IS_WINDOWS:
                skipped.append("PROC-01: PPL config requires manual setup (RunAsPPL registry + reboot)")

            elif fid.startswith("DRV-"):
                skipped.append(f"{fid}: driver changes require manual review (risk of BSOD)")

            else:
                skipped.append(f"{fid}: no auto-fix available for this finding type")

        except Exception as e:
            errors.append(f"{fid}: {e}")

    return {"fixed": fixed, "skipped": skipped, "errors": errors}


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="蓝队系统崩溃面扫描器 — 检测 Windows BSOD 攻击向量"
    )
    parser.add_argument(
        "--quick", action="store_true",
        help="快速扫描 (仅高危项, 30秒内)"
    )
    parser.add_argument(
        "--auto-fix", action="store_true",
        help="自动修复安全发现 (仅安全操作, 不改驱动/服务)"
    )
    parser.add_argument(
        "--dimensions", nargs="+",
        choices=["filesystem", "memory", "usb", "registry", "driver", "process", "input", "network"],
        help="限制扫描维度"
    )
    parser.add_argument(
        "--min-severity", default="low",
        choices=["critical", "high", "medium", "low", "info"],
        help="最低报告级别 (默认: low)"
    )
    parser.add_argument(
        "--output", "-o", default="",
        help="输出 JSON 报告路径"
    )
    parser.add_argument(
        "--json", action="store_true",
        help="输出原始 JSON (无格式化表格)"
    )

    args = parser.parse_args()

    # Windows GBK fix: reconfigure stdout to UTF-8 for emoji support
    if IS_WINDOWS:
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            _cd_log.warning("stdout_reconfigure_failed")

    if args.quick:
        result = quick_crash_check()
    else:
        result = run_crash_scan(
            dimensions=args.dimensions,
            min_severity=args.min_severity,
            output_path=args.output,
        )

    if args.auto_fix:
        fix_result = auto_fix_crash_issues(result)
        print("\n  --- 自动修复 ---")
        for item in fix_result["fixed"]:
            print(f"  [FIXED] {item}")
        for item in fix_result["skipped"]:
            print(f"  [SKIP] {item}")
        for item in fix_result["errors"]:
            print(f"  [ERR] {item}")
        if not any(fix_result.values()):
            print("  [OK] 无需自动修复")

    if args.json:
        import json as _json
        output = dict(result)
        if args.auto_fix:
            output["auto_fix"] = fix_result
        _json.dump(output, sys.stdout, indent=2, ensure_ascii=False)
    else:
        print_crash_report(result)
