"""preemptive.py — 先敌发现：攻击者视角弱点扫描。

以攻促防 — 复用攻击工具链扫描自身攻击面，抢在敌军之前发现薄弱点。

用法:
    from tools.blueteam.preemptive import preemptive_scan, AttackerFinding

    result = preemptive_scan("192.168.1.1")
    for f in result["findings"]:
        print(f"{f.risk_level}: port {f.port} — {f.attack_vector}")

安全底线:
    - 纯被动信息收集，不做任何 exploit
    - 不依赖 nuclei，无 fallback 风险
    - Windows 用 socket fallback，不触发 ntfs.sys
    - 无文件系统遍历
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# -- Dataclasses -----------------------------------------------------------

@dataclass
class AttackerFinding:
    """攻击者视角发现的薄弱点。"""
    port: int = 0
    service: str = ""
    attack_vector: str = ""
    risk_level: str = "info"       # critical / high / medium / low / info
    risk_reason: str = ""
    evidence: str = ""
    mitre_technique: str = ""
    remediation: str = ""
    confidence: float = 0.7


# -- Risk ordering ----------------------------------------------------------

_RISK_ORDER: dict[str, int] = {
    "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
}


# -- Port attack vector knowledge base -------------------------------------
#  (port, service, attack_vector, risk_level, risk_reason, mitre, remediation)

_PORT_ATTACK_MAP: dict[int, dict] = {
    # ── Critical ──────────────────────────────────────────────────────────
    3389: {
        "service": "RDP",
        "vectors": [
            {
                "attack_vector": "BlueKeep (CVE-2019-0708) / BlueGate RCE",
                "risk_level": "critical",
                "risk_reason": "远程桌面协议历史 RCE 漏洞，无需交互即可执行代码",
                "mitre_technique": "T1210",
                "remediation": "安装 KB4499175+；启用 NLA (网络级认证)；非必要不开放 3389",
            },
            {
                "attack_vector": "RDP 弱口令爆破",
                "risk_level": "high",
                "risk_reason": "常见弱口令或默认凭据，爆破成功即可远程桌面登录",
                "mitre_technique": "T1110.001",
                "remediation": "强密码策略 + 账户锁定；RD Gateway + MFA",
            },
        ],
    },
    445: {
        "service": "SMB",
        "vectors": [
            {
                "attack_vector": "EternalBlue (MS17-010) RCE",
                "risk_level": "critical",
                "risk_reason": "NSA 泄露漏洞，WannaCry/NotPetya 核心传播载体",
                "mitre_technique": "T1210",
                "remediation": "安装 MS17-010 补丁；禁用 SMBv1；封堵 445 入站",
            },
            {
                "attack_vector": "SMB 签名未强制 / NTLM 中继",
                "risk_level": "high",
                "risk_reason": "未启用 SMB 签名可被中继到其他服务获取权限",
                "mitre_technique": "T1557.001",
                "remediation": "强制 SMB 签名；启用 EPA；禁用 NTLM 回退",
            },
            {
                "attack_vector": "匿名共享枚举",
                "risk_level": "medium",
                "risk_reason": "可枚举共享文件夹，泄露内部文件结构",
                "mitre_technique": "T1135",
                "remediation": "禁用匿名枚举；RestrictAnonymous=1",
            },
        ],
    },
    6379: {
        "service": "Redis",
        "vectors": [
            {
                "attack_vector": "未授权访问 → 写 SSH key / crontab / webshell",
                "risk_level": "critical",
                "risk_reason": "Redis 默认无密码，可直接写入 authorized_keys 获取服务器权限",
                "mitre_technique": "T1059.004",
                "remediation": "设置 requirepass；bind 127.0.0.1；禁用 CONFIG；rename-command 危险命令",
            },
        ],
    },
    27017: {
        "service": "MongoDB",
        "vectors": [
            {
                "attack_vector": "未授权访问 → 数据窃取 / 勒索",
                "risk_level": "critical",
                "risk_reason": "MongoDB 默认无认证，被勒索攻击高频利用",
                "mitre_technique": "T1190",
                "remediation": "启用认证 (auth=true)；bind 127.0.0.1；防火墙限制来源 IP",
            },
        ],
    },
    2375: {
        "service": "Docker API",
        "vectors": [
            {
                "attack_vector": "Docker Remote API 未授权 → 容器逃逸 / 宿主机控制",
                "risk_level": "critical",
                "risk_reason": "攻击者可启动提权容器挂载宿主机根目录 → 完全控制",
                "mitre_technique": "T1610",
                "remediation": "禁止 TCP 暴露 Docker API；TLS 客户端认证；Unix socket only",
            },
        ],
    },
    2376: {
        "service": "Docker API (TLS)",
        "vectors": [
            {
                "attack_vector": "Docker Remote API 弱 TLS 配置",
                "risk_level": "high",
                "risk_reason": "TLS 配置不当可能被绕过或中间人攻击",
                "mitre_technique": "T1610",
                "remediation": "验证 TLS 证书链；仅允许受信任客户端",
            },
        ],
    },

    # ── High ──────────────────────────────────────────────────────────────
    22: {
        "service": "SSH",
        "vectors": [
            {
                "attack_vector": "SSH 弱口令 / 默认凭据爆破",
                "risk_level": "high",
                "risk_reason": "常见弱口令或 vendor 默认凭据，爆破成功即可远程执行命令",
                "mitre_technique": "T1110.001",
                "remediation": "禁用密码登录，仅允许密钥认证；fail2ban；更改默认 SSH 端口",
            },
            {
                "attack_vector": "SSH 旧版本已知漏洞 (CVE-2024-6387 regreSSHion)",
                "risk_level": "high",
                "risk_reason": "OpenSSH 信号竞争条件，可未授权 RCE",
                "mitre_technique": "T1190",
                "remediation": "升级 OpenSSH >= 9.8p1",
            },
        ],
    },
    21: {
        "service": "FTP",
        "vectors": [
            {
                "attack_vector": "匿名登录 / 弱口令爆破",
                "risk_level": "high",
                "risk_reason": "FTP 明文传输，常见匿名访问泄露敏感文件",
                "mitre_technique": "T1078.001",
                "remediation": "禁用匿名登录；启用 FTPS/SFTP；限制来源 IP",
            },
            {
                "attack_vector": "FTP 反射 DDoS (bounce attack)",
                "risk_level": "medium",
                "risk_reason": "FTP PORT 命令可被利用反射流量",
                "mitre_technique": "T1498.001",
                "remediation": "禁用 PORT 命令；限制 PORT 外连 IP",
            },
        ],
    },
    23: {
        "service": "Telnet",
        "vectors": [
            {
                "attack_vector": "明文凭据窃取 / 弱口令爆破",
                "risk_level": "high",
                "risk_reason": "Telnet 无加密，凭据/会话可被嗅探；IoT 设备常见默认密码",
                "mitre_technique": "T1040",
                "remediation": "关闭 Telnet，改用 SSH；网络隔离 IoT 设备",
            },
        ],
    },
    3306: {
        "service": "MySQL",
        "vectors": [
            {
                "attack_vector": "弱口令爆破 / 未授权访问",
                "risk_level": "high",
                "risk_reason": "MySQL 弱口令可被爆破，成功后可读取/篡改数据库",
                "mitre_technique": "T1190",
                "remediation": "强密码；bind 127.0.0.1；关闭 root 远程登录",
            },
            {
                "attack_vector": "UDF 提权",
                "risk_level": "high",
                "risk_reason": "MySQL 以高权限运行时可通过 UDF 执行系统命令",
                "mitre_technique": "T1548.002",
                "remediation": "MySQL 以低权限用户运行；关闭 --secure-file-priv",
            },
        ],
    },
    1433: {
        "service": "MSSQL",
        "vectors": [
            {
                "attack_vector": "弱口令爆破 / xp_cmdshell 命令执行",
                "risk_level": "high",
                "risk_reason": "SA 账户弱口令常见，xp_cmdshell 可执行系统命令",
                "mitre_technique": "T1059.003",
                "remediation": "强 SA 密码；禁用 xp_cmdshell；禁用 xp_cmdshell_proxy_account",
            },
        ],
    },
    5432: {
        "service": "PostgreSQL",
        "vectors": [
            {
                "attack_vector": "弱口令 / CVE RCE",
                "risk_level": "high",
                "risk_reason": "PostgreSQL 弱口令 + COPY PROGRAM 可命令执行；版本漏洞 (CVE-2019-9193)",
                "mitre_technique": "T1059.003",
                "remediation": "强密码；pg_hba.conf 限制来源；禁用 PROGRAM 特性",
            },
        ],
    },
    1521: {
        "service": "Oracle DB",
        "vectors": [
            {
                "attack_vector": "TNS Poisoning / 弱口令",
                "risk_level": "high",
                "risk_reason": "Oracle TNS 监听器漏洞 + 默认账户大量未锁定",
                "mitre_technique": "T1190",
                "remediation": "TNS 监听器加密码；锁定默认账户；打 CPU 补丁",
            },
        ],
    },
    11211: {
        "service": "Memcached",
        "vectors": [
            {
                "attack_vector": "未授权访问 → 数据窃取 / UDP DDoS 放大",
                "risk_level": "high",
                "risk_reason": "Memcached UDP 可达 50000x 放大系数，常被用于反射 DDoS",
                "mitre_technique": "T1498.001",
                "remediation": "bind 127.0.0.1；禁用 UDP (--udc-port=0)；防火墙限制",
            },
        ],
    },
    9200: {
        "service": "Elasticsearch",
        "vectors": [
            {
                "attack_vector": "未授权访问 → 数据泄露",
                "risk_level": "high",
                "risk_reason": "ES 默认无认证，索引数据可直接读取",
                "mitre_technique": "T1190",
                "remediation": "启用 X-Pack Security；HTTPS；Kibana 加认证",
            },
        ],
    },
    5985: {
        "service": "WinRM",
        "vectors": [
            {
                "attack_vector": "弱口令 → 远程 PowerShell 控制",
                "risk_level": "high",
                "risk_reason": "WinRM 允许远程 PowerShell，爆破成功即可完全控制 Windows 主机",
                "mitre_technique": "T1021.006",
                "remediation": "强密码 + JEA (Just Enough Administration)；HTTPS only",
            },
        ],
    },
    5986: {
        "service": "WinRM (HTTPS)",
        "vectors": [
            {
                "attack_vector": "证书验证绕过 / 弱口令",
                "risk_level": "high",
                "risk_reason": "自签名证书或弱口令可被利用",
                "mitre_technique": "T1021.006",
                "remediation": "使用正式证书；强密码 + MFA",
            },
        ],
    },
    # ── Medium ────────────────────────────────────────────────────────────
    25: {
        "service": "SMTP",
        "vectors": [
            {
                "attack_vector": "开放中继 (Open Relay) / 用户枚举",
                "risk_level": "medium",
                "risk_reason": "SMTP 开放中继可被用于发送垃圾邮件 / 钓鱼；VRFY/EXPN 可枚举用户",
                "mitre_technique": "T1589.001",
                "remediation": "关闭开放中继；禁用 VRFY/EXPN；SPF+DKIM+DMARC",
            },
        ],
    },
    5900: {
        "service": "VNC",
        "vectors": [
            {
                "attack_vector": "弱口令 / 无认证远程桌面",
                "risk_level": "medium",
                "risk_reason": "VNC 常见无密码或弱密码 (最多 8 字符截断)",
                "mitre_technique": "T1021.005",
                "remediation": "强密码；SSH 隧道/VPN；改用 RDP+SmartCard",
            },
        ],
    },
    2049: {
        "service": "NFS",
        "vectors": [
            {
                "attack_vector": "未授权挂载 → 数据窃取",
                "risk_level": "medium",
                "risk_reason": "NFS 导出未限制 IP，可挂载后读取所有文件",
                "mitre_technique": "T1040",
                "remediation": "exports 限制 IP；Kerberos 认证；使用 NFSv4+",
            },
        ],
    },
    111: {
        "service": "RPC (Portmapper)",
        "vectors": [
            {
                "attack_vector": "NFS/RPC 服务枚举",
                "risk_level": "medium",
                "risk_reason": "Portmapper 可泄露所有 RPC 服务端口，辅助内网渗透",
                "mitre_technique": "T1046",
                "remediation": "防火墙限制 RPC 来源；非必要不暴露 111 端口",
            },
        ],
    },
    135: {
        "service": "MSRPC",
        "vectors": [
            {
                "attack_vector": "DCOM/WMI 远程调用",
                "risk_level": "medium",
                "risk_reason": "MSRPC 暴露可配合 DCOM/WMI 横向移动",
                "mitre_technique": "T1021.003",
                "remediation": "Windows 防火墙限制 RPC 来源；非必要不暴露",
            },
        ],
    },
    139: {
        "service": "NetBIOS",
        "vectors": [
            {
                "attack_vector": "NetBIOS 名称枚举 / NBT-NS 投毒",
                "risk_level": "medium",
                "risk_reason": "NetBIOS 可泄露主机名、域信息，辅助内网侦察",
                "mitre_technique": "T1557.001",
                "remediation": "禁用 NetBIOS over TCP/IP；不开放 139",
            },
        ],
    },
    161: {
        "service": "SNMP",
        "vectors": [
            {
                "attack_vector": "SNMP public/private community 信息泄露",
                "risk_level": "medium",
                "risk_reason": "默认 community string 可泄露系统/网络配置、进程列表",
                "mitre_technique": "T1590",
                "remediation": "使用 SNMPv3 + 强口令；ACL 限制来源",
            },
        ],
    },
    389: {
        "service": "LDAP",
        "vectors": [
            {
                "attack_vector": "匿名绑定 → 域信息枚举",
                "risk_level": "medium",
                "risk_reason": "LDAP 匿名绑定可枚举 AD 用户/组/计算机",
                "mitre_technique": "T1087.002",
                "remediation": "禁用匿名 LDAP 绑定；LDAPS 加密",
            },
        ],
    },
    636: {
        "service": "LDAPS",
        "vectors": [
            {
                "attack_vector": "LDAPS 证书验证绕过",
                "risk_level": "medium",
                "risk_reason": "自签名证书可被接受，中继攻击",
                "mitre_technique": "T1557.001",
                "remediation": "使用 PKI 证书；强制通道绑定",
            },
        ],
    },
    873: {
        "service": "Rsync",
        "vectors": [
            {
                "attack_vector": "未授权访问 → 文件同步窃取",
                "risk_level": "medium",
                "risk_reason": "Rsync 无认证可列出/下载模块文件",
                "mitre_technique": "T1048",
                "remediation": "配置 rsyncd.conf secrets file；SSH 传输模式",
            },
        ],
    },
    1434: {
        "service": "MSSQL Browser",
        "vectors": [
            {
                "attack_vector": "MSSQL 实例枚举",
                "risk_level": "medium",
                "risk_reason": "MSSQL Browser 泄露实例名/端口，辅助精准攻击",
                "mitre_technique": "T1046",
                "remediation": "非必要关闭 SQL Browser 服务",
            },
        ],
    },
    3128: {
        "service": "Squid Proxy",
        "vectors": [
            {
                "attack_vector": "开放代理 → 内网穿透",
                "risk_level": "medium",
                "risk_reason": "未授权代理可被攻击者用于访问内网资源",
                "mitre_technique": "T1090.001",
                "remediation": "配置 ACL 限制来源 IP + 认证",
            },
        ],
    },
    5060: {
        "service": "SIP",
        "vectors": [
            {
                "attack_vector": "SIP 暴力枚举/呼叫欺诈",
                "risk_level": "medium",
                "risk_reason": "SIP 服务未限制可被用于 VoIP 欺诈",
                "mitre_technique": "T1190",
                "remediation": "SIP over TLS；强密码；fail2ban",
            },
        ],
    },
    8089: {
        "service": "Splunk",
        "vectors": [
            {
                "attack_vector": "Splunk 未授权 API → 日志泄露/RCE",
                "risk_level": "medium",
                "risk_reason": "Splunk 管理接口未认证可执行搜索/任意命令",
                "mitre_technique": "T1059",
                "remediation": "启用 Splunk 认证；非必要不暴露管理端口",
            },
        ],
    },
    9092: {
        "service": "Kafka",
        "vectors": [
            {
                "attack_vector": "Kafka 未授权访问 → 消息窃取/注入",
                "risk_level": "medium",
                "risk_reason": "Kafka 无认证可读取/写入任意 topic",
                "mitre_technique": "T1190",
                "remediation": "SASL/SSL 认证；ACL 控制 topic 访问",
            },
        ],
    },

    # ── Low ───────────────────────────────────────────────────────────────
    53: {
        "service": "DNS",
        "vectors": [
            {
                "attack_vector": "DNS 区域传输 → 域名/记录泄露",
                "risk_level": "low",
                "risk_reason": "未限制 AXFR 可泄露整个域名空间",
                "mitre_technique": "T1590.001",
                "remediation": "限制 AXFR 来源 IP；TSIG 签名",
            },
            {
                "attack_vector": "DNS 放大反射 DDoS",
                "risk_level": "low",
                "risk_reason": "开放递归可被利用反射 DNS 放大攻击",
                "mitre_technique": "T1498.001",
                "remediation": "限制递归查询来源；ACL 控制",
            },
        ],
    },
    110: {
        "service": "POP3",
        "vectors": [
            {
                "attack_vector": "明文认证 → 凭据嗅探",
                "risk_level": "low",
                "risk_reason": "POP3 默认明文传输凭据/邮件",
                "mitre_technique": "T1040",
                "remediation": "启用 POP3S (995)；过渡到 IMAPS",
            },
        ],
    },
    143: {
        "service": "IMAP",
        "vectors": [
            {
                "attack_vector": "明文认证 → 凭据嗅探",
                "risk_level": "low",
                "risk_reason": "IMAP 默认明文传输邮件内容",
                "mitre_technique": "T1040",
                "remediation": "启用 IMAPS (993)",
            },
        ],
    },
    554: {
        "service": "RTSP",
        "vectors": [
            {
                "attack_vector": "摄像头匿名查看",
                "risk_level": "low",
                "risk_reason": "RTSP 无认证可查看实时视频流",
                "mitre_technique": "T1190",
                "remediation": "RTSP 认证；网络隔离摄像头 VLAN",
            },
        ],
    },
    1883: {
        "service": "MQTT",
        "vectors": [
            {
                "attack_vector": "MQTT 未授权 → IoT 消息窃听/注入",
                "risk_level": "low",
                "risk_reason": "MQTT Broker 无认证可订阅/发布任意 topic",
                "mitre_technique": "T1190",
                "remediation": "启用用户名/密码认证；TLS",
            },
        ],
    },
    8080: {
        "service": "HTTP-Alt",
        "vectors": [],  # handled by web probe below
    },
    8443: {
        "service": "HTTPS-Alt",
        "vectors": [],  # handled by web probe below
    },
}


# -- Web tech risk knowledge base -----------------------------------------

_WEB_TECH_RISK: dict[str, dict] = {
    # CMS
    "WordPress": {
        "risk_level": "high",
        "risk_reason": "插件/主题漏洞频发，xmlrpc.php 可被爆破/SSRF，未授权 REST API 枚举用户",
        "mitre_technique": "T1190",
        "remediation": "定期更新核心+插件；禁用 xmlrpc.php；WAF 防护",
    },
    "Drupal": {
        "risk_level": "critical",
        "risk_reason": "Drupalgeddon (CVE-2018-7600) 系列 RCE，历史严重漏洞",
        "mitre_technique": "T1190",
        "remediation": "立即更新到最新版本；WAF；禁用不必要的模块",
    },
    "Joomla": {
        "risk_level": "high",
        "risk_reason": "扩展/模板漏洞多，常见 SQLi + RCE 组合",
        "mitre_technique": "T1190",
        "remediation": "更新核心+扩展；移除未使用的扩展",
    },

    # Java ecosystem
    "Tomcat": {
        "risk_level": "high",
        "risk_reason": "Manager 弱口令 → WAR 部署 → RCE；CVE 历史 RCE 漏洞",
        "mitre_technique": "T1190",
        "remediation": "强 Manager 密码；非必要不暴露 /manager /host-manager",
    },
    "Java": {
        "risk_level": "medium",
        "risk_reason": "反序列化漏洞 (shiro/fastjson/weblogic) 常见",
        "mitre_technique": "T1059",
        "remediation": "升级框架版本；RASP 防护",
    },
    "Jenkins": {
        "risk_level": "high",
        "risk_reason": "未授权 Script Console → Groovy RCE；凭据泄露",
        "mitre_technique": "T1059",
        "remediation": "启用认证；RBAC 权限控制；非必要不暴露外网",
    },

    # Python ecosystem
    "Django": {
        "risk_level": "medium",
        "risk_reason": "DEBUG 模式泄露源码/SECRET_KEY；CSRF 配置不当",
        "mitre_technique": "T1082",
        "remediation": "生产环境关闭 DEBUG；定期更新 Django 版本",
    },
    "Flask": {
        "risk_level": "medium",
        "risk_reason": "Debug 模式可执行任意 Python 代码 (Werkzeug console)",
        "mitre_technique": "T1059",
        "remediation": "生产环境关闭 Debug；使用 Gunicorn/uWSGI",
    },
    "FastAPI": {
        "risk_level": "medium",
        "risk_reason": "Swagger docs 公开暴露 API 结构；缺少限速",
        "mitre_technique": "T1082",
        "remediation": "生产环境关闭 /docs；API 限速 + 认证",
    },

    # Middleware
    "IIS": {
        "risk_level": "high",
        "risk_reason": "IIS 历史 RCE (CVE-2017-7269)；WebDAV PUT 写 webshell",
        "mitre_technique": "T1190",
        "remediation": "更新 IIS 补丁；禁用不用的扩展 (WebDAV/ASP)",
    },
    "Apache": {
        "risk_level": "medium",
        "risk_reason": "Apache 版本漏洞；.htaccess 误配；目录列表",
        "mitre_technique": "T1190",
        "remediation": "更新 Apache；关闭 Directory Listing；审查配置",
    },
    "Nginx": {
        "risk_level": "medium",
        "risk_reason": "路径穿越误配；CRLF injection；alias 穿越",
        "mitre_technique": "T1190",
        "remediation": "审查 Nginx 配置；使用 talisman 自动审计",
    },

    # Special
    "Swagger": {
        "risk_level": "medium",
        "risk_reason": "API 文档公开暴露所有端点 + 参数结构",
        "mitre_technique": "T1082",
        "remediation": "生产环境关闭 Swagger UI；Internal IP only",
    },
    "JWT": {
        "risk_level": "medium",
        "risk_reason": "JWT 算法混淆攻击；none 算法；弱密钥",
        "mitre_technique": "T1557",
        "remediation": "固定算法白名单；强密钥；短过期时间",
    },
    "PHP": {
        "risk_level": "medium",
        "risk_reason": "PHP 版本漏洞；phpinfo 泄露；disable_functions 绕过",
        "mitre_technique": "T1190",
        "remediation": "更新 PHP 版本；隐藏 phpinfo；硬化 php.ini",
    },
    "ASP.NET": {
        "risk_level": "medium",
        "risk_reason": "ViewState MAC 未启用；Telerik 组件漏洞",
        "mitre_technique": "T1190",
        "remediation": "启用 ViewState MAC；更新第三方组件",
    },

    # Tools
    "phpMyAdmin": {
        "risk_level": "high",
        "risk_reason": "弱口令 → 数据库完全控制；历史 RCE",
        "mitre_technique": "T1190",
        "remediation": "IP 白名单；强密码 + 2FA；非必要不暴露",
    },
    "GitLab": {
        "risk_level": "high",
        "risk_reason": "GitLab 历史 RCE (CVE-2021-22205)；Runner 未授权注册",
        "mitre_technique": "T1190",
        "remediation": "更新到最新版本；限制 Runner 注册",
    },

    # WAF (informational — tells attacker which WAF to bypass)
    "Cloudflare": {
        "risk_level": "info",
        "risk_reason": "CDN/WAF 存在 → 需要绕过 Cloudflare 获取真实 IP",
        "mitre_technique": "T1590",
        "remediation": "验证源 IP 不泄露 (DNS 历史/SSL cert/censys)",
    },
    "ModSecurity": {
        "risk_level": "info",
        "risk_reason": "WAF 存在 → 可针对性绕过规则集",
        "mitre_technique": "T1590",
        "remediation": "CRS 规则更新；自定义规则补强",
    },
}


# -- Web ports ────────────────────────────────────────────────────────────

_WEB_PORTS: set[int] = {80, 443, 8080, 8443, 8000, 8888, 9000, 9090, 3000, 5000, 7000, 8008, 9443}


# -- Tech name normalization (alias → canonical) ──────────────────────────

_TECH_ALIASES: dict[str, str] = {
    "Java": "Tomcat",      # Java often implies Tomcat in Chinese environments
}


# -- Public API ───────────────────────────────────────────────────────────

def preemptive_scan(
    target: str = "localhost",
    profile: str = "common",
    probe_web: bool = True,
) -> dict:
    """攻击者视角弱点扫描 — 抢在敌军之前发现攻击面薄弱点。

    Args:
        target:    IP / 域名
        profile:   端口扫描 profile ("common" = 28常用端口)
        probe_web: 是否探测 Web 端口进行指纹识别

    Returns:
        {
            "target": str,
            "findings": list[AttackerFinding],      # 按风险排序
            "risk_distribution": dict[str, int],     # {critical: N, high: N, ...}
            "platform_used": str,                    # "nmap" or "socket_fallback"
        }

    安全承诺:
        - 纯被动信息收集，不做任何 exploit
        - Windows 安全 (socket fallback, 无 rglob, 无 ntfs 遍历)
    """
    from tools.recon.port_scanner import scan_ports
    from tools.recon.web_probe import probe_http as _http_probe

    findings: list[AttackerFinding] = []

    # Step 1: port scan
    scan_result = scan_ports(target, profile=profile)
    platform = "nmap" if scan_result.nmap_version else "socket_fallback"
    open_ports = scan_result.open_ports

    # Step 2: map each open port to attack vectors
    for port in open_ports:
        mapping = _PORT_ATTACK_MAP.get(port)
        if mapping and mapping.get("vectors"):
            for vec in mapping["vectors"]:
                findings.append(AttackerFinding(
                    port=port,
                    service=mapping["service"],
                    attack_vector=vec["attack_vector"],
                    risk_level=vec["risk_level"],
                    risk_reason=vec["risk_reason"],
                    evidence=f"端口 {port} 开放 ({mapping['service']})",
                    mitre_technique=vec["mitre_technique"],
                    remediation=vec["remediation"],
                    confidence=0.85,
                ))

    # Step 3: web port fingerprinting
    if probe_web:
        web_open = [p for p in open_ports if p in _WEB_PORTS]
        for port in web_open:
            scheme = "https" if port in (443, 8443, 9443) else "http"
            url = f"{scheme}://{target}:{port}"
            try:
                svc = _http_probe(url, timeout=5)
            except Exception:
                continue

            if svc.status == 0:
                continue

            # Tech-based risk assessment
            for tech in svc.techs:
                canonical = _TECH_ALIASES.get(tech, tech)
                risk_info = _WEB_TECH_RISK.get(canonical)
                if risk_info is None:
                    risk_info = _WEB_TECH_RISK.get(tech)
                if risk_info:
                    findings.append(AttackerFinding(
                        port=port,
                        service=f"Web/{svc.server or 'HTTP'}",
                        attack_vector=f"{tech} 技术栈暴露 → {risk_info['risk_reason'][:60]}",
                        risk_level=risk_info["risk_level"],
                        risk_reason=risk_info["risk_reason"],
                        evidence=f"{url} — {tech} — {svc.title or 'No title'}",
                        mitre_technique=risk_info["mitre_technique"],
                        remediation=risk_info["remediation"],
                        confidence=0.7,
                    ))

    # Step 4: sort by risk (critical first)
    findings.sort(key=lambda f: _RISK_ORDER.get(f.risk_level, 99))

    # Step 5: compute risk distribution
    dist: dict[str, int] = {}
    for f in findings:
        dist[f.risk_level] = dist.get(f.risk_level, 0) + 1

    return {
        "target": target,
        "findings": findings,
        "risk_distribution": dist,
        "platform_used": platform,
    }
