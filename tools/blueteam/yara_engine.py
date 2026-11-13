"""YARA Engine — 轻量恶意样本特征规则匹配.

不依赖 yara-python，纯 Python 实现 YARA 风格核心子集：
  规则 = 名称 + 字符串特征（文本/regex/hex）+ 条件（any/all/N of them）

特征匹配三种写法：
  - 文本子串:  "eval("
  - 正则:      "re:\\$_(GET|POST|REQUEST)"
  - hex 字节:  "hex:4d5a"  (PE/MZ 头)

Usage:
    from tools.blueteam.yara_engine import YaraEngine, default_rules
    e = YaraEngine(default_rules())
    e.scan(b"<?php eval($_POST['cmd']); ?>")   # -> ["php_webshell"]
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List


@dataclass
class YaraRule:
    """一条 YARA 风格规则。"""
    name: str
    strings: List[str]       # 特征列表（文本 / re: / hex:）
    condition: str = "any"   # any / all / "N of them"
    description: str = ""


class YaraEngine:
    """轻量恶意样本特征匹配引擎。"""

    def __init__(self, rules: List[YaraRule] = None):
        self.rules = rules or []

    def add_rule(self, rule: YaraRule) -> None:
        self.rules.append(rule)

    def _match_string(self, pattern: str, data: bytes) -> bool:
        if pattern.startswith("hex:"):
            try:
                needle = bytes.fromhex(pattern[4:])
                return needle in data
            except ValueError:
                return False
        if pattern.startswith("re:"):
            return re.search(pattern[3:], data.decode("utf-8", errors="ignore"),
                             re.IGNORECASE) is not None
        return pattern.encode("utf-8", errors="ignore").lower() in data.lower()

    def _rule_hit(self, rule: YaraRule, data: bytes) -> bool:
        matched = [self._match_string(s, data) for s in rule.strings]
        if not matched:
            return False
        cond = rule.condition.lower()
        if cond == "all":
            return all(matched)
        if cond == "any":
            return any(matched)
        m = re.match(r"(\d+)\s*of", cond)
        if m:
            return sum(matched) >= int(m.group(1))
        return any(matched)

    def scan(self, data: bytes) -> List[str]:
        """扫描数据，返回命中的规则名列表。"""
        return [r.name for r in self.rules if self._rule_hit(r, data)]


def default_rules() -> List[YaraRule]:
    """内置常见恶意样本规则集（22 条，覆盖 8 类威胁）。"""
    return [
        # 网页木马
        YaraRule("php_webshell",
                 ["eval(", "base64_decode", "re:\\$_(GET|POST|REQUEST|COOKIE)"],
                 "any", "PHP 一句话木马"),
        YaraRule("asp_webshell",
                 ["execute(", "eval(", "wscript.shell"],
                 "any", "ASP 脚本木马"),
        YaraRule("jsp_webshell",
                 ["runtime.getruntime", "processbuilder", "getoutputstream"],
                 "any", "JSP 脚本木马"),

        # 恶意脚本
        YaraRule("powershell_download",
                 ["downloadstring", "invoke-webrequest", "system.net.webclient"],
                 "any", "PowerShell 下载执行"),
        YaraRule("reverse_shell",
                 ["/dev/tcp", "nc -e", "bash -i", "socket.connect", "os.system"],
                 "any", "反弹 shell"),
        YaraRule("macro_malware",
                 ["autoopen", "auto_open", "document_open", "shell(", "createobject"],
                 "any", "恶意 Office 宏"),

        # 凭证窃取
        YaraRule("mimikatz",
                 ["mimikatz", "sekurlsa", "wdigest"],
                 "any", "Mimikatz 凭证窃取"),
        YaraRule("credential_dump",
                 ["lsass", "procdump", "sam dump", "ntds.dit"],
                 "any", "凭证/哈希转储"),

        # 勒索/破坏
        YaraRule("ransom_note",
                 ["ransom", "decrypt", "bitcoin"],
                 "all", "勒索信（三词同时出现）"),
        YaraRule("shadow_delete",
                 ["vssadmin", "delete shadows", "wbadmin", "delete catalog"],
                 "any", "删除卷影副本"),
        YaraRule("disk_wipe",
                 ["cipher /w", "sdelete", "shred", "dd if="],
                 "any", "磁盘擦除"),

        # 挖矿
        YaraRule("crypto_miner",
                 ["xmrig", "minerd", "stratum", "cryptonight", "monero"],
                 "any", "加密货币挖矿"),

        # 远控/后门
        YaraRule("keylogger",
                 ["getasynckeystate", "setwindowshookex", "keylog"],
                 "any", "键盘记录"),
        YaraRule("remote_access",
                 ["backdoor", "reverse connect", "screen capture", "shell.execute"],
                 "any", "远控木马"),

        # 注入/利用
        YaraRule("sqli_payload",
                 ["union select", "information_schema", "sleep(", "or 1=1"],
                 "any", "SQL 注入"),
        YaraRule("xss_payload",
                 ["<script>", "javascript:", "onerror=", "alert("],
                 "any", "XSS 跨站脚本"),
        YaraRule("cmd_injection",
                 ["| bash", "| sh", "$(id)", "`whoami`", "&& curl"],
                 "any", "命令注入"),

        # 文件头（识别样本类型）
        YaraRule("pe_header", ["hex:4d5a"], "any", "PE 可执行文件 (MZ)"),
        YaraRule("elf_header", ["hex:7f454c46"], "any", "ELF 可执行文件"),
        YaraRule("macho_header", ["hex:cffaedfe", "hex:feedfacf"], "any", "Mach-O 可执行文件"),
        YaraRule("pdf_header", ["hex:25504446"], "any", "PDF 文档"),
        YaraRule("zip_header", ["hex:504b0304"], "any", "ZIP 压缩包"),
    ]


__all__ = ["YaraEngine", "YaraRule", "default_rules"]
