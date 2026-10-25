"""系统加固 — 安全配置审计与自动化加固建议。"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class HardeningCheck:
    """单条加固检查结果。"""
    check_id: str = ""
    name: str = ""
    status: str = ""            # pass / fail / warn / skip
    current_value: str = ""
    recommended: str = ""
    command: str = ""           # 修复命令
    severity: str = "medium"    # low / medium / high / critical

    def to_dict(self) -> dict:
        return {
            "id": self.check_id, "name": self.name,
            "status": self.status, "current": self.current_value,
            "recommend": self.recommended, "fix_cmd": self.command,
            "severity": self.severity,
        }


# -- Check functions ----------------------------------------------------------

def _check_ssh_config() -> List[HardeningCheck]:
    """审计 SSH 配置。"""
    checks = []
    sshd_config = Path("/etc/ssh/sshd_config")
    if not sshd_config.exists():
        return [HardeningCheck(check_id="SSH-01", name="SSH 配置",
                               status="skip", current_value="sshd_config 不存在")]

    try:
        content = sshd_config.read_text()
        lines_lower = content.lower()

        # PermitRootLogin
        if "permitrootlogin yes" in lines_lower and "permitrootlogin no" not in lines_lower:
            checks.append(HardeningCheck(
                check_id="SSH-01", name="禁止 root SSH 登录",
                status="fail", current_value="PermitRootLogin yes",
                recommended="PermitRootLogin no",
                command="sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config",
                severity="high",
            ))
        else:
            checks.append(HardeningCheck(
                check_id="SSH-01", name="禁止 root SSH 登录",
                status="pass", current_value="PermitRootLogin no",
                severity="high",
            ))

        # PasswordAuthentication
        if "passwordauthentication yes" in lines_lower and "passwordauthentication no" not in lines_lower:
            checks.append(HardeningCheck(
                check_id="SSH-02", name="禁用 SSH 密码登录",
                status="fail", current_value="PasswordAuthentication yes",
                recommended="PasswordAuthentication no",
                command="sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config",
                severity="high",
            ))
        else:
            checks.append(HardeningCheck(
                check_id="SSH-02", name="禁用 SSH 密码登录",
                status="pass", current_value="PasswordAuthentication no",
                severity="high",
            ))

        # X11Forwarding
        if "x11forwarding yes" in lines_lower:
            checks.append(HardeningCheck(
                check_id="SSH-03", name="禁用 X11 转发",
                status="fail", current_value="X11Forwarding yes",
                recommended="X11Forwarding no",
                command="sed -i 's/X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config",
                severity="low",
            ))
        else:
            checks.append(HardeningCheck(
                check_id="SSH-03", name="禁用 X11 转发",
                status="pass", severity="low",
            ))

    except Exception as _e:
        from tools.swallow_trap import record
        record(_e)

    return checks


def _check_file_permissions() -> List[HardeningCheck]:
    """审计关键文件权限。"""
    checks = []
    critical_files = [
        ("/etc/shadow", "0o400", "high"),
        ("/etc/passwd", "0o644", "medium"),
        ("/etc/gshadow", "0o400", "high"),
    ]

    for fpath_str, expected_perm, sev in critical_files:
        fpath = Path(fpath_str)
        if not fpath.exists():
            checks.append(HardeningCheck(
                check_id=f"PERM-{fpath.name}", name=f"{fpath} 权限",
                status="skip", current_value="文件不存在", severity=sev,
            ))
            continue

        try:
            mode = fpath.stat().st_mode & 0o777
            if oct(mode) != expected_perm:
                checks.append(HardeningCheck(
                    check_id=f"PERM-{fpath.name}", name=f"{fpath} 权限",
                    status="fail",
                    current_value=oct(mode),
                    recommended=expected_perm,
                    command=f"chmod {expected_perm[2:]} {fpath_str}",
                    severity=sev,
                ))
            else:
                checks.append(HardeningCheck(
                    check_id=f"PERM-{fpath.name}", name=f"{fpath} 权限",
                    status="pass", current_value=oct(mode), severity=sev,
                ))
        except Exception:
            checks.append(HardeningCheck(
                check_id=f"PERM-{fpath.name}", name=f"{fpath} 权限",
                status="warn", current_value="无法读取", severity=sev,
            ))

    return checks


def _check_kernel_params() -> List[HardeningCheck]:
    """审计内核安全参数。"""
    checks = []
    params = {
        "net.ipv4.ip_forward": ("0", "禁用 IP 转发", "medium"),
        "net.ipv4.conf.all.send_redirects": ("0", "禁用 ICMP 重定向", "medium"),
        "net.ipv4.conf.all.accept_source_route": ("0", "禁用源路由", "medium"),
        "net.ipv4.tcp_syncookies": ("1", "启用 SYN Cookie", "medium"),
        "net.ipv4.conf.all.rp_filter": ("1", "启用反向路径过滤", "low"),
        "kernel.randomize_va_space": ("2", "完全 ASLR", "high"),
        "fs.suid_dumpable": ("0", "禁用 SUID core dump", "medium"),
    }

    for param, (expected, desc, sev) in params.items():
        from tools.core.tool_invoker import invoke
        r = invoke("sysctl", ["-n", param], timeout=5)
        if r.ok:
            current = r.stdout.strip()
            if current == expected:
                checks.append(HardeningCheck(
                    check_id=f"KERN-{param.split('.')[-1]}",
                    name=desc, status="pass", current_value=current, severity=sev,
                ))
            else:
                checks.append(HardeningCheck(
                    check_id=f"KERN-{param.split('.')[-1]}",
                    name=desc, status="fail",
                    current_value=current, recommended=expected,
                    command=f"sysctl -w {param}={expected}",
                    severity=sev,
                ))
        else:
            checks.append(HardeningCheck(
                check_id=f"KERN-{param.split('.')[-1]}",
                name=desc, status="skip", current_value="sysctl 不可用",
                severity=sev,
            ))

    return checks


def _check_services() -> List[HardeningCheck]:
    """审计不必要的服务。"""
    checks = []
    dangerous_services = [
        ("telnet", "Telnet 服务", "high"),
        ("rsh", "RSH 服务", "high"),
        ("ftp", "FTP 服务 (建议用 SFTP)", "medium"),
        ("nfs-server", "NFS 服务", "medium"),
        ("smbd", "Samba 服务", "low"),
        ("avahi-daemon", "Avahi/Bonjour (mDNS)", "low"),
    ]

    from tools.core.tool_invoker import invoke
    for svc_name, desc, sev in dangerous_services:
        r = invoke("systemctl", ["is-active", svc_name], timeout=5)
        if r.ok and "active" in r.stdout:
            checks.append(HardeningCheck(
                check_id=f"SVC-{svc_name}",
                name=f"禁用 {desc}",
                status="fail",
                current_value="正在运行",
                recommended="停止并禁用",
                command=f"systemctl stop {svc_name} && systemctl disable {svc_name}",
                severity=sev,
            ))
        else:
            checks.append(HardeningCheck(
                check_id=f"SVC-{svc_name}",
                name=f"{desc} 已禁用",
                status="pass", current_value="未运行",
                severity=sev,
            ))

    return checks


# -- Main audit ---------------------------------------------------------------

def run_audit() -> Dict[str, Any]:
    """运行全量安全加固审计。

    Returns:
        {
            "total_checks": N,
            "pass": N, "fail": N, "warn": N, "skip": N,
            "score": 0.0-1.0,  # 通过率
            "checks": [HardeningCheck, ...],
            "fix_commands": [...],  # 所有 fail 项的修复命令
        }
    """
    all_checks: List[HardeningCheck] = []
    all_checks.extend(_check_ssh_config())
    all_checks.extend(_check_file_permissions())
    all_checks.extend(_check_kernel_params())
    all_checks.extend(_check_services())

    pass_count = sum(1 for c in all_checks if c.status == "pass")
    fail_count = sum(1 for c in all_checks if c.status == "fail")
    warn_count = sum(1 for c in all_checks if c.status == "warn")
    skip_count = sum(1 for c in all_checks if c.status == "skip")

    total_evaluated = pass_count + fail_count + warn_count  # exclude skip
    score = pass_count / max(total_evaluated, 1)

    fix_commands = [c.command for c in all_checks if c.status == "fail" and c.command]

    return {
        "total_checks": len(all_checks),
        "pass": pass_count, "fail": fail_count, "warn": warn_count, "skip": skip_count,
        "score": round(score, 2),
        "checks": [c.to_dict() for c in all_checks],
        "fix_commands": fix_commands,
    }
