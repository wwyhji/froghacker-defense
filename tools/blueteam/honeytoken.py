"""Honeytoken — 金丝雀诱饵部署与检测.

布置诱饵账号/凭证/文件/URL，攻击者一触碰就告警。区别于网络蜜罐（服务层），
honeytoken 落在应用/数据层，检测「攻击者已进入内部」的横向活动。

诱饵值用随机生成保证唯一性，正常日志不会出现，故子串匹配即告警、无误报。

Usage:
    from tools.blueteam.honeytoken import HoneytokenDeployer, HoneytokenDetector
    d = HoneytokenDeployer()
    d.deploy("file", "/var/www/html/password.txt", "诱饵文件")
    det = HoneytokenDetector(d)
    det.detect({"path": "/var/www/html/password.txt"})  # 命中
"""

from __future__ import annotations

import json
import secrets
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class Honeytoken:
    """一枚金丝雀。"""
    token_type: str   # account / credential / file / url
    value: str        # 诱饵内容（账号名/凭证值/文件路径/URL）
    description: str = ""
    triggered: bool = False


def generate_account(prefix: str = "svc_backup") -> str:
    """生成诱饵账号名（随机后缀保证唯一）。"""
    return f"{prefix}_{secrets.token_hex(3)}"


def generate_credential(prefix: str = "AKIA_BACKUP") -> str:
    """生成诱饵凭证（随机后缀保证唯一）。"""
    return f"{prefix}_{secrets.token_hex(8).upper()}"


class HoneytokenDeployer:
    """金丝雀部署器 — 布置诱饵并持久化到 registry。"""

    def __init__(self, registry_file: str = ".honeytokens.json"):
        self.registry_file = registry_file
        self.tokens: List[Honeytoken] = []
        self._load()

    def deploy(self, token_type: str, value: str, description: str = "") -> Honeytoken:
        """布置一枚金丝雀。"""
        t = Honeytoken(token_type, value, description)
        self.tokens.append(t)
        self._save()
        return t

    def _load(self) -> None:
        p = Path(self.registry_file)
        if p.exists():
            try:
                for item in json.loads(p.read_text(encoding="utf-8")):
                    self.tokens.append(Honeytoken(**item))
            except (json.JSONDecodeError, TypeError):
                pass

    def _save(self) -> None:
        Path(self.registry_file).write_text(
            json.dumps([asdict(t) for t in self.tokens], indent=2),
            encoding="utf-8")

    def list_tokens(self) -> List[Honeytoken]:
        return self.tokens


class HoneytokenDetector:
    """金丝雀检测器 — 判断事件是否触碰诱饵。"""

    def __init__(self, deployer: HoneytokenDeployer):
        self.deployer = deployer

    def detect(self, event: Dict) -> Optional[Honeytoken]:
        """检测事件是否触碰某金丝雀，命中返回 token 并标记 triggered。"""
        text = " ".join(str(v).lower() for v in event.values())
        for t in self.deployer.tokens:
            if t.value.lower() in text:
                t.triggered = True
                self.deployer._save()
                return t
        return None


__all__ = ["HoneytokenDeployer", "HoneytokenDetector", "Honeytoken",
           "generate_account", "generate_credential"]
