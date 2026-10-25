"""蜜罐检测 — 识别远程主机是否为蜜罐（供红队规避用）。"""

from __future__ import annotations

import socket
from typing import Any, Dict, List, Optional, Tuple


# -- Known honeypot signatures ------------------------------------------------

HONEYPOT_SIGNATURES: List[Dict[str, Any]] = [
    # Cowrie SSH
    {"type": "cowrie", "port": 22, "banner": b"SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2",
     "method": "banner_match", "confidence": 0.9,
     "note": "Cowrie 默认 SSH banner，真实 Debian 7 已 EOL 多年"},
    {"type": "cowrie", "port": 23, "banner": b"",
     "method": "telnet_options", "confidence": 0.7,
     "note": "Cowrie Telnet 不支持多数协商选项"},

    # Kippo
    {"type": "kippo", "port": 22, "banner": b"SSH-2.0-OpenSSH_5.1p1 Debian-5",
     "method": "banner_match", "confidence": 0.9,
     "note": "Kippo 默认 SSH banner"},

    # Dionaea
    {"type": "dionaea", "port": 445, "smb_dialect": b"NT LM 0.12",
     "method": "smb_negotiate", "confidence": 0.6,
     "note": "Dionaea SMB 仅支持有限方言"},

    # Conpot
    {"type": "conpot", "port": 502, "modbus_response_delay_ms": 0,
     "method": "timing_analysis", "confidence": 0.5,
     "note": "Conpot Modbus 响应无延迟，真实 PLC 有 5-50ms 延迟"},

    # General Docker-hosted honeypots
    {"type": "docker_honeypot", "port": 0,
     "mac_prefix": "02:42:", "method": "mac_check", "confidence": 0.8,
     "note": "Docker 默认 MAC 前缀 02:42:"},

    # Glastopf
    {"type": "glastopf", "port": 80,
     "http_server": "Apache/2.2.22 (Debian)",
     "method": "header_match", "confidence": 0.85,
     "note": "Glastopf 默认 Server header"},
]


# -- Detection functions ------------------------------------------------------

def _check_banner(host: str, port: int, expected_banner: bytes) -> Tuple[bool, str]:
    """检查服务 banner 是否匹配已知蜜罐签名。"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        sock.settimeout(3)
        banner = sock.recv(1024)
        sock.close()
        if expected_banner in banner:
            return True, f"Banner 匹配: {banner[:80]!r}"
        return False, f"Banner 不匹配: {banner[:80]!r}"
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return False, f"连接失败: {e}"


def _check_mac_prefix(host: str) -> Tuple[bool, str]:
    """检查 ARP 表中的 MAC 地址前缀。"""
    from tools.core.tool_invoker import invoke
    r = invoke("arp", ["-a", host], timeout=5)
    if r.ok:
        for line in r.stdout.splitlines():
            if "02:42:" in line:
                return True, f"Docker MAC 前缀: {line.strip()}"
        return False, "无 Docker MAC 前缀"
    return False, "无法检查 ARP"


def _check_http_server(host: str, port: int = 80,
                       expected_server: str = "") -> Tuple[bool, str]:
    """检查 HTTP Server header。"""
    try:
        import urllib.request
        url = f"http://{host}:{port}/"
        req = urllib.request.Request(url, method="HEAD",
                                     headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            server = resp.headers.get("Server", "")
            if expected_server and expected_server.lower() in server.lower():
                return True, f"Server header 匹配: {server}"
            return False, f"Server: {server}"
    except Exception as e:
        return False, f"HTTP 请求失败: {e}"


def detect_honeypot(host: str, port: int = 0) -> List[Dict[str, Any]]:
    """扫描目标，检测所有匹配的蜜罐签名。

    Returns:
        [{"type": "cowrie", "confidence": 0.9, "evidence": "..."}, ...]
    """
    results = []
    for sig in HONEYPOT_SIGNATURES:
        check_port = sig["port"] if port == 0 else port
        method = sig["method"]
        evidence = ""
        matched = False

        if method == "banner_match" and check_port > 0:
            matched, evidence = _check_banner(host, check_port, sig.get("banner", b""))
        elif method == "mac_check":
            matched, evidence = _check_mac_prefix(host)
        elif method == "header_match" and check_port > 0:
            matched, evidence = _check_http_server(host, check_port,
                                                   sig.get("http_server", ""))
        elif method == "timing_analysis":
            # Placeholder — would need actual timing measurement
            evidence = "时序分析需要主动探测"

        if matched:
            results.append({
                "type": sig["type"],
                "confidence": sig["confidence"],
                "evidence": evidence,
                "note": sig.get("note", ""),
            })

    return results


def is_honeypot(host: str, port: int = 0,
                min_confidence: float = 0.7) -> Tuple[bool, List[Dict[str, Any]]]:
    """判断目标是否为蜜罐。

    Returns:
        (is_honeypot, detections)
    """
    detections = detect_honeypot(host, port)
    strong = [d for d in detections if d["confidence"] >= min_confidence]
    return len(strong) > 0, detections
