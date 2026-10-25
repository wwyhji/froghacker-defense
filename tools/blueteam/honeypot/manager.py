"""蜜罐管理器 — 列出、停止、状态监控。"""

from __future__ import annotations

from typing import List

from tools.blueteam.honeypot.deploy import HoneypotInstance, deploy_honeypot
from tools.blueteam.honeypot.analyze import analyze_captures


def list_honeypots() -> List[HoneypotInstance]:
    """列出所有运行中的蛙客蜜罐容器。"""
    instances = []
    from tools.core.tool_invoker import invoke
    r = invoke("docker", ["ps", "-a", "--filter", "label=froghackerg.honeypot",
               "--format", "{{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Ports}}\t{{.Labels}}"],
               timeout=10)
    if r.ok:
        for line in r.stdout.strip().splitlines():
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) >= 4:
                cid = parts[0][:12]
                name = parts[1]
                status = "running" if "Up" in parts[2] else "stopped"
                ports = parts[3]
                labels = parts[4] if len(parts) > 4 else ""

                # Extract port number
                port = 0
                import re
                port_match = re.search(r':(\d+)->', ports)
                if port_match:
                    port = int(port_match.group(1))

                # Extract honeypot type from labels
                hp_type = ""
                type_match = re.search(r'froghackerg\.honeypot=([^,]+)', labels)
                if type_match:
                    hp_type = type_match.group(1)

                instances.append(HoneypotInstance(
                    name=name, honeypot_type=hp_type,
                    port=port, container_id=cid, status=status,
                ))

    return instances


def stop_honeypot(name_or_id: str) -> HoneypotInstance:
    """停止并删除一个蜜罐容器。"""
    from tools.core.tool_invoker import invoke
    r1 = invoke("docker", ["stop", name_or_id], timeout=30)
    r2 = invoke("docker", ["rm", name_or_id], timeout=10)
    if r1.ok or r2.ok:
        return HoneypotInstance(name=name_or_id, status="stopped")
    return HoneypotInstance(name=name_or_id, status="error", error="Docker 操作失败")


class HoneypotManager:
    """蜜罐管理器 — 部署、监控、分析一站式接口。"""

    def __init__(self, log_dir: str = "./honeypot_logs"):
        self.log_dir = log_dir
        self.instances: List[HoneypotInstance] = []

    def deploy(self, honeypot_type: str, port: int = 0) -> HoneypotInstance:
        """部署蜜罐并追踪。"""
        inst = deploy_honeypot(honeypot_type, port=port, log_dir=self.log_dir)
        if inst.status == "running":
            self.instances.append(inst)
        return inst

    def list_all(self) -> List[HoneypotInstance]:
        """列出所有蜜罐（本管理器 + Docker）。"""
        docker_instances = list_honeypots()
        known_names = {i.name for i in self.instances}
        for di in docker_instances:
            if di.name not in known_names:
                self.instances.append(di)
        return self.instances

    def stop_all(self) -> int:
        """停止所有追踪中的蜜罐。"""
        count = 0
        for inst in self.instances:
            if inst.status == "running":
                stop_honeypot(inst.name)
                inst.status = "stopped"
                count += 1
        return count

    def analyze(self, honeypot_type: str = "") -> dict:
        """分析所有蜜罐日志。"""
        return analyze_captures(self.log_dir, honeypot_type)
