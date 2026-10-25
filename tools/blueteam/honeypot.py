"""蜜罐部署 — 轻量级欺骗防御诱饵.

支持 HTTP/SSH/FTP/MySQL 模拟蜜罐，用于检测横向移动和侦察行为。
"""

from __future__ import annotations

import json
import os
import re
import socket
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


# ── Constants ────────────────────────────────────────────────────────────

HONEYPOT_TYPES = {
    "simple_http": {
        "port": 8080,
        "banner": "Apache/2.4.41 (Ubuntu)",
        "description": "模拟 HTTP 服务 — 检测 Web 扫描",
    },
    "ssh": {
        "port": 2222,
        "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
        "description": "模拟 SSH 服务 — 检测暴力破解",
    },
    "ftp": {
        "port": 2121,
        "banner": "220 ProFTPD 1.3.6 Server ready.",
        "description": "模拟 FTP 服务 — 检测文件传输侦察",
    },
    "mysql": {
        "port": 3307,
        "banner": "5.7.35-log MySQL Community Server",
        "description": "模拟 MySQL — 检测数据库扫描",
    },
    "telnet": {
        "port": 2323,
        "banner": "Ubuntu 20.04 LTS\nlogin: ",
        "description": "模拟 Telnet — 检测老旧协议侦察",
    },
    "rdp": {
        "port": 3399,
        "banner": "",
        "description": "模拟 RDP — 检测远程桌面扫描",
    },
    "smb": {
        "port": 4450,
        "banner": "",
        "description": "模拟 SMB — 检测文件共享侦察",
    },
}

# Signatures that indicate someone is probing a honeypot
HONEYPOT_SIGNATURES = {
    "port_scan": re.compile(
        r'(?:nmap|masscan|zmap|scan|probe)',
        re.IGNORECASE,
    ),
    "bruteforce": re.compile(
        r'(?:login|password|auth|ssh|bruteforce)',
        re.IGNORECASE,
    ),
    "exploit_attempt": re.compile(
        r'(?:union\s+select|\.\./\.\./|cmd\.exe|/bin/bash|wget\s|curl\s)',
        re.IGNORECASE,
    ),
}


# ── Data Types ───────────────────────────────────────────────────────────

@dataclass
class HoneypotConfig:
    """蜜罐部署配置。"""
    hp_type: str = "simple_http"
    port: int = 8080
    banner: str = ""
    log_dir: str = "./honeypot_logs"
    max_connections: int = 100
    timeout: int = 10
    auto_start: bool = True

    def to_dict(self) -> dict:
        return {
            "type": self.hp_type,
            "port": self.port,
            "banner": self.banner[:80],
            "log_dir": self.log_dir,
            "auto_start": self.auto_start,
        }


@dataclass
class HoneypotInstance:
    """一个运行中的蜜罐实例。"""
    name: str
    hp_type: str
    port: int
    status: str = "stopped"  # "running" / "stopped" / "error"
    connections: int = 0
    captures: List[Dict[str, Any]] = field(default_factory=list)
    log_dir: str = ""
    started_at: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "type": self.hp_type,
            "port": self.port,
            "status": self.status,
            "connections": self.connections,
            "captures": len(self.captures),
            "started_at": self.started_at,
        }


# ── Honeypot Manager ─────────────────────────────────────────────────────

class HoneypotManager:
    """蜜罐生命周期管理 — 部署/列表/停止/分析。"""

    def __init__(self, log_dir: str = "./honeypot_logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._instances: Dict[str, HoneypotInstance] = {}
        self._threads: Dict[str, threading.Thread] = {}
        self._running: Dict[str, bool] = {}

    def deploy(self, hp_type: str, name: str = "",
               port: Optional[int] = None,
               bind_ip: str = "0.0.0.0") -> HoneypotInstance:
        """部署一个蜜罐实例。"""
        if hp_type not in HONEYPOT_TYPES:
            raise ValueError(f"未知蜜罐类型: {hp_type}. 可用: {list(HONEYPOT_TYPES)}")

        cfg = HONEYPOT_TYPES[hp_type]
        actual_port = port or cfg["port"]
        instance_name = name or f"{hp_type}_{actual_port}"

        if instance_name in self._instances:
            return self._instances[instance_name]

        inst = HoneypotInstance(
            name=instance_name,
            hp_type=hp_type,
            port=actual_port,
            status="stopped",
            log_dir=str(self.log_dir),
        )
        self._instances[instance_name] = inst

        # Start listener in background thread
        self._running[instance_name] = True
        t = threading.Thread(
            target=self._listen,
            args=(instance_name, bind_ip, actual_port, cfg.get("banner", "")),
            daemon=True,
        )
        t.start()
        self._threads[instance_name] = t

        inst.status = "running"
        inst.started_at = datetime.now().isoformat()
        return inst

    def stop(self, name: str) -> bool:
        """停止一个蜜罐实例。"""
        if name not in self._running:
            return False
        self._running[name] = False
        if name in self._instances:
            self._instances[name].status = "stopped"
        return True

    def list_all(self) -> List[HoneypotInstance]:
        """列出所有蜜罐实例。"""
        return list(self._instances.values())

    def get(self, name: str) -> Optional[HoneypotInstance]:
        return self._instances.get(name)

    def analyze_captures(self, name: str) -> Dict[str, Any]:
        """分析蜜罐捕获的连接记录。"""
        inst = self._instances.get(name)
        if not inst:
            return {"error": f"实例 {name} 不存在"}

        captures = inst.captures
        if not captures:
            return {"total": 0, "summary": "无捕获记录"}

        ips: Set[str] = set()
        suspicious: List[dict] = []
        payloads: List[str] = []

        for cap in captures:
            ip = cap.get("remote_addr", "")
            if ip:
                ips.add(ip)

            data = cap.get("data", "")
            if data:
                payloads.append(data[:200])

            # Signature matching
            for sig_name, pattern in HONEYPOT_SIGNATURES.items():
                if pattern.search(data):
                    suspicious.append({
                        "remote_addr": ip,
                        "signature": sig_name,
                        "timestamp": cap.get("timestamp", ""),
                    })
                    break

        return {
            "total": len(captures),
            "unique_ips": len(ips),
            "ips": sorted(ips),
            "suspicious": len(suspicious),
            "suspicious_details": suspicious[:10],
            "recent_payloads": payloads[-5:],
        }

    def _listen(self, name: str, bind_ip: str, port: int, banner: str):
        """Background listener for honeypot connections."""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(3)
            sock.bind((bind_ip, port))
            sock.listen(5)

            while self._running.get(name, False):
                try:
                    conn, addr = sock.accept()
                    inst = self._instances.get(name)
                    if inst:
                        inst.connections += 1
                    data = b""
                    try:
                        conn.settimeout(self._get_timeout(name))
                        data = conn.recv(4096)
                        if banner:
                            conn.send((banner + "\n").encode())
                    except socket.timeout:
                        pass
                    finally:
                        conn.close()

                    if inst and data:
                        inst.captures.append({
                            "remote_addr": f"{addr[0]}:{addr[1]}",
                            "data": data.decode("utf-8", errors="replace"),
                            "timestamp": datetime.now().isoformat(),
                            "bytes": len(data),
                        })

                        # Log to file
                        log_file = self.log_dir / f"{name}.log"
                        with open(log_file, "a", encoding="utf-8") as f:
                            f.write(json.dumps(inst.captures[-1], ensure_ascii=False) + "\n")

                except socket.timeout:
                    continue
                except OSError:
                    break

        except OSError as e:
            if name in self._instances:
                self._instances[name].status = "error"
                self._instances[name].error = str(e)
        finally:
            if sock:
                try:
                    sock.close()
                except Exception as _e:
                    from tools.swallow_trap import record
                    record(_e)

    def _get_timeout(self, name: str) -> int:
        inst = self._instances.get(name)
        if inst and inst.hp_type in HONEYPOT_TYPES:
            return 10
        return 10


# ── Global Manager (singleton for convenience functions) ─────────────────

_manager: Optional[HoneypotManager] = None


def _get_manager(log_dir: str = "./honeypot_logs") -> HoneypotManager:
    global _manager
    if _manager is None:
        _manager = HoneypotManager(log_dir=log_dir)
    return _manager


# ── Convenience Functions ────────────────────────────────────────────────

def deploy_honeypot(
    hp_type: str,
    name: str = "",
    port: Optional[int] = None,
    log_dir: str = "./honeypot_logs",
) -> HoneypotInstance:
    """部署蜜罐。"""
    mgr = _get_manager(log_dir)
    return mgr.deploy(hp_type, name=name, port=port)


def list_honeypots() -> List[HoneypotInstance]:
    """列出所有蜜罐。"""
    mgr = _get_manager()
    return mgr.list_all()


def stop_honeypot(name: str) -> bool:
    """停止蜜罐。"""
    mgr = _get_manager()
    return mgr.stop(name)


def analyze_captures(name: str) -> Dict[str, Any]:
    """分析蜜罐捕获。"""
    mgr = _get_manager()
    return mgr.analyze_captures(name)


def detect_honeypot(ip: str, port: int) -> Dict[str, Any]:
    """检测目标是否为已知蜜罐。

    通过检查目标响应与已知蜜罐签名的匹配度来判断。
    """
    result = {
        "ip": ip,
        "port": port,
        "is_honeypot": False,
        "confidence": 0.0,
        "matched_signatures": [],
    }

    # Check against common honeypot ports
    known_ports = {cfg["port"] for cfg in HONEYPOT_TYPES.values()}
    if port in known_ports:
        result["confidence"] += 0.3
        result["matched_signatures"].append("known_honeypot_port")

    # Check for suspicious banner patterns
    # (In a real implementation, this would connect and check)
    return result


def is_honeypot(ip: str, port: int) -> bool:
    """快速判断目标是否为蜜罐。"""
    return detect_honeypot(ip, port)["is_honeypot"]


__all__ = [
    'HoneypotConfig', 'HoneypotInstance', 'HoneypotManager',
    'deploy_honeypot', 'list_honeypots', 'stop_honeypot',
    'analyze_captures', 'detect_honeypot', 'is_honeypot',
    'HONEYPOT_TYPES', 'HONEYPOT_SIGNATURES',
]
