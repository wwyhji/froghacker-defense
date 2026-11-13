"""File Integrity Monitor — 文件完整性监控 (FIM).

监控关键文件/目录的 SHA-256 基线，检测篡改：webshell 落地、系统二进制被
替换、持久化后门、配置被改。经典 FIM 防御手段，纯 Python 无外部依赖。

Usage:
    from tools.blueteam.fim import FileIntegrityMonitor
    fim = FileIntegrityMonitor(["/etc/passwd", "/usr/bin/sshd"])
    fim.build_baseline()
    changes = fim.check()   # [] 表示无变化
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class FileChange:
    """一条文件变化。"""
    path: str
    change: str      # added / modified / deleted
    old_hash: str
    new_hash: str


class FileIntegrityMonitor:
    """文件完整性监控器 — 基线 + 变更检测。"""

    def __init__(self, paths: List[str], baseline_file: str = ".fim_baseline.json"):
        self.paths = [Path(p) for p in paths]
        self.baseline_file = baseline_file
        self.baseline: Dict[str, dict] = {}

    # ── 哈希 ────────────────────────────────────────────────────

    @staticmethod
    def _hash_file(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    def _scan(self) -> Dict[str, dict]:
        """扫描所有路径，返回 {path: {hash, size}}（排除基线文件自身）。"""
        result: Dict[str, dict] = {}
        baseline_resolved = Path(self.baseline_file).resolve()
        for base in self.paths:
            try:
                if base.is_file():
                    if base.resolve() != baseline_resolved:
                        result[str(base)] = {
                            "hash": self._hash_file(base),
                            "size": base.stat().st_size,
                        }
                elif base.is_dir():
                    for f in base.rglob("*"):
                        if f.is_file() and f.resolve() != baseline_resolved:
                            result[str(f)] = {
                                "hash": self._hash_file(f),
                                "size": f.stat().st_size,
                            }
            except OSError:
                continue
        return result

    # ── 基线 ────────────────────────────────────────────────────

    def build_baseline(self) -> int:
        """建立基线，返回纳入监控的文件数。"""
        self.baseline = self._scan()
        Path(self.baseline_file).write_text(
            json.dumps(self.baseline, indent=2), encoding="utf-8")
        return len(self.baseline)

    def load_baseline(self) -> bool:
        """加载已有基线，成功返回 True。"""
        p = Path(self.baseline_file)
        if not p.exists():
            return False
        self.baseline = json.loads(p.read_text(encoding="utf-8"))
        return True

    # ── 检查 ────────────────────────────────────────────────────

    def check(self) -> List[FileChange]:
        """对比当前状态与基线，返回变化列表（无变化则空）。"""
        if not self.baseline:
            self.load_baseline()
        current = self._scan()
        changes: List[FileChange] = []

        for path, info in current.items():
            if path not in self.baseline:
                changes.append(FileChange(path, "added", "", info["hash"]))
            elif self.baseline[path]["hash"] != info["hash"]:
                changes.append(FileChange(
                    path, "modified", self.baseline[path]["hash"], info["hash"]))

        for path in self.baseline:
            if path not in current:
                changes.append(FileChange(path, "deleted", self.baseline[path]["hash"], ""))

        return changes


__all__ = ["FileIntegrityMonitor", "FileChange"]
