"""web — Web 攻击域防御检测规则 (LFI / SQLi / webshell / 二次编码 / 敏感文件).

防御端 45 条 detect 规则原缺 web 域，本目录从取证端 server_logs 的
_ATTACK_PATTERNS 反向注入，补全最常见的 Web 攻击检测。
"""
