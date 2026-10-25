"""蜜罐部署 — 支持 7 种蜜罐类型的 Docker/本地部署。"""

from __future__ import annotations

import json
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


# -- Honeypot type registry ---------------------------------------------------

HONEYPOT_TYPES: Dict[str, Dict[str, Any]] = {
    "cowrie": {
        "name": "Cowrie SSH/Telnet",
        "description": "中交互 SSH/Telnet 蜜罐，记录 shell 命令和文件下载",
        "default_port": 2222,
        "protocol": "tcp",
        "image": "cowrie/cowrie:latest",
        "docker_flags": ["-v", "cowrie_logs:/cowrie/var/log"],
    },
    "dionaea": {
        "name": "Dionaea",
        "description": "低交互多协议蜜罐 (SMB/HTTP/FTP/MSSQL/MySQL/SIP)",
        "default_port": 0,  # multi-port
        "protocol": "tcp",
        "image": "dionaea/dionaea:latest",
        "docker_flags": ["-v", "dionaea_data:/opt/dionaea/var"],
    },
    "conpot": {
        "name": "Conpot ICS/SCADA",
        "description": "工控协议蜜罐 (Modbus/S7/SNMP/HTTP/BACnet)",
        "default_port": 502,
        "protocol": "tcp",
        "image": "honeynet/conpot:latest",
        "docker_flags": [],
    },
    "glastopf": {
        "name": "Glastopf Web",
        "description": "Web 应用蜜罐，模拟常见漏洞 (SQLi/LFI/RFI)",
        "default_port": 80,
        "protocol": "tcp",
        "image": "glastopf/glastopf:latest",
        "docker_flags": [],
    },
    "mailoney": {
        "name": "Mailoney SMTP",
        "description": "SMTP 蜜罐，捕获垃圾邮件和钓鱼尝试",
        "default_port": 25,
        "protocol": "tcp",
        "image": "phage/mailoney:latest",
        "docker_flags": [],
    },
    "elastichoney": {
        "name": "ElasticHoney",
        "description": "Elasticsearch 蜜罐，捕获数据泄露尝试",
        "default_port": 9200,
        "protocol": "tcp",
        "image": "jordanpotti/elastichoney:latest",
        "docker_flags": [],
    },
    "simple_http": {
        "name": "Simple HTTP Fake",
        "description": "轻量 HTTP 假服务（Python内置，无需Docker），记录所有请求",
        "default_port": 8888,
        "protocol": "tcp",
        "image": None,  # 本地 Python 实现
        "docker_flags": [],
    },
}


# -- Data types ---------------------------------------------------------------

@dataclass
class HoneypotConfig:
    """蜜罐部署配置。"""
    honeypot_type: str = "cowrie"
    port: int = 0  # 0 = use default
    bind_address: str = "0.0.0.0"
    name: str = ""
    log_dir: str = ""  # 空 = 默认 ./honeypot_logs/


@dataclass
class HoneypotInstance:
    """运行中的蜜罐实例。"""
    name: str = ""
    honeypot_type: str = ""
    port: int = 0
    container_id: str = ""
    status: str = "stopped"  # running / stopped / error
    log_path: str = ""
    started_at: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name, "type": self.honeypot_type,
            "port": self.port, "container_id": self.container_id,
            "status": self.status, "log_path": self.log_path,
        }


# -- Deployment ---------------------------------------------------------------

def _deploy_docker(config: HoneypotConfig, hp_type: dict) -> HoneypotInstance:
    """通过 Docker 部署蜜罐。"""
    image = hp_type["image"]
    name = config.name or f"honeypot_{config.honeypot_type}"
    port = config.port or hp_type["default_port"]
    log_dir = config.log_dir or "./honeypot_logs"
    Path(log_dir).mkdir(parents=True, exist_ok=True)

    cmd = [
        "docker", "run", "-d",
        "--name", name,
        "--restart", "unless-stopped",
        "-p", f"{config.bind_address}:{port}:{port}",
        "-v", f"{Path(log_dir).resolve()}:/var/log/honeypot",
        "--label", f"froghackerg.honeypot={config.honeypot_type}",
    ] + hp_type.get("docker_flags", []) + [image]

    from tools.core.tool_invoker import invoke
    r = invoke("docker", cmd[1:], timeout=60)
    container_id = r.stdout.strip()[:12]
    if r.ok and container_id:
        return HoneypotInstance(
            name=name, honeypot_type=config.honeypot_type,
            port=port, container_id=container_id,
            status="running", log_path=log_dir,
        )
    if r.returncode == -1:
        return HoneypotInstance(
            name=name, honeypot_type=config.honeypot_type,
            status="error", error="Docker pull 超时",
        )
    return HoneypotInstance(
        name=name, honeypot_type=config.honeypot_type,
        port=port, status="error", error=r.stderr[:500] or "Docker 未安装或未在 PATH 中",
    )


def _deploy_simple_http(config: HoneypotConfig) -> HoneypotInstance:
    """部署轻量 HTTP 假服务（Python 内置，无需 Docker）。"""
    port = config.port or 8888
    name = config.name or f"honeypot_simple_http_{port}"
    log_dir = config.log_dir or "./honeypot_logs"
    log_path = Path(log_dir) / f"http_{port}.jsonl"
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # Write a standalone honeypot script
    script = f'''
import json, sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime
from urllib.parse import unquote

LOG = "{log_path}"

class H(BaseHTTPRequestHandler):
    def log_request(self, code='-', size='-'):
        pass
    def _log(self, method, path, headers, body):
        with open(LOG, "a") as f:
            json.dump({{"time": datetime.now().isoformat(), "method": method,
                        "path": path, "headers": dict(headers), "body": body,
                        "client": self.client_address[0]}}, f)
            f.write("\\n")
    def do_GET(self):
        self._log("GET", unquote(self.path), self.headers, "")
        self.send_response(200); self.end_headers()
        self.wfile.write(b"<html><body><h1>Welcome</h1></body></html>")
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
        self._log("POST", unquote(self.path), self.headers, body)
        self.send_response(200); self.end_headers()
        self.wfile.write(b'{{"status":"ok"}}')
    def do_HEAD(self):
        self._log("HEAD", self.path, self.headers, "")
        self.send_response(200); self.end_headers()

s = HTTPServer(("{config.bind_address}", {port}), H)
print(f"HONEYPOT_READY port={port}")
s.serve_forever()
'''
    script_path = Path(tempfile.gettempdir()) / f"froghackerg_honeypot_{port}.py"
    script_path.write_text(script)

    try:
        proc = subprocess.Popen(
            ["python", str(script_path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace",
        )
        # Wait for ready signal
        import time
        time.sleep(1)
        if proc.poll() is None:
            return HoneypotInstance(
                name=name, honeypot_type="simple_http", port=port,
                container_id=str(proc.pid), status="running",
                log_path=str(log_path),
            )
        return HoneypotInstance(
            name=name, honeypot_type="simple_http",
            status="error", error=proc.stderr.read()[:500],
        )
    except Exception as e:
        return HoneypotInstance(
            name=name, honeypot_type="simple_http",
            status="error", error=str(e),
        )


def deploy_honeypot(honeypot_type: str = "cowrie", port: int = 0,
                    name: str = "", bind: str = "0.0.0.0",
                    log_dir: str = "") -> HoneypotInstance:
    """部署一个蜜罐实例。

    Args:
        honeypot_type: 蜜罐类型 (cowrie/dionaea/conpot/glastopf/mailoney/elastichoney/simple_http)
        port: 监听端口 (0 = 使用默认端口)
        name: 实例名称 (空 = 自动生成)
        bind: 绑定地址
        log_dir: 日志目录

    Returns:
        HoneypotInstance — 部署后的实例状态
    """
    hp_type = HONEYPOT_TYPES.get(honeypot_type)
    if not hp_type:
        return HoneypotInstance(
            status="error",
            error=f"未知蜜罐类型: {honeypot_type}。可用: {list(HONEYPOT_TYPES.keys())}",
        )

    config = HoneypotConfig(
        honeypot_type=honeypot_type, port=port,
        bind_address=bind, name=name, log_dir=log_dir,
    )

    if honeypot_type == "simple_http":
        return _deploy_simple_http(config)

    return _deploy_docker(config, hp_type)
