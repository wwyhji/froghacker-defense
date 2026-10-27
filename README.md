# FrogHacker Defense 🛡️

<div align="center">

**蛙客 AI 防御端（开源版）** — 统一检测引擎 · 蜜罐 · IDS · 防火墙 · 加固 · 巡逻

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](./pyproject.toml)
[![检测规则](https://img.shields.io/badge/检测规则-45-brightgreen.svg)]()
[![零依赖](https://img.shields.io/badge/依赖-纯标准库-important.svg)]()

响应时代号召，开源蛙客网络安全分析自动化平台的**防御端（蓝队）**常规防御能力。

</div>

## 这是什么

蛙客（FrogHacker）是攻·防·取三端共生的安全分析自动化平台。本仓库开源的是其中的**防御端**：
一套纯标准库、零第三方依赖的蓝队防御工具集，覆盖从「先敌发现」到「加固报告」的完整防御管线。

> ⚠️ 本仓库只开源**业界通用的常规防御能力**。受专利保护的数学检测引擎（同调/Petri/因果/FCA）已剥离，见下方「专利保护与开源边界」。

## 🗺️ 蛙客开源仓库导航

蛙客平台按能力拆为五个独立仓库，本仓库是其中的**防御端（蓝队）**：

| 仓库 | 定位 |
|------|------|
| **[froghacker-defense](https://github.com/wwyhji/froghacker-defense)** | 防御端（蓝队）：检测规则 / 蜜罐 / IDS / 防火墙 / 加固（本仓库） |
| [froghacker-reveng](https://github.com/wwyhji/froghacker-reveng) | 逆向关联追踪引擎：APK 逆向找 key |
| [froghacker-ant-swarm](https://github.com/wwyhji/froghacker-ant-swarm) | 蚁群协作调度底座：多 Agent 任务分配 |
| [froghacker-antihallucination](https://github.com/wwyhji/froghacker-antihallucination) | 算法抗幻觉：确定性验证 + 事实断言裁决 |
| [froghacker-audit](https://github.com/wwyhji/froghacker-audit) | 代码静态安全审计：regex + AST 污点 |

## ✨ 特性

- **统一检测引擎** — 45 条检测规则，跨 7 个安全域，多特征事件匹配
- **蜜罐** — 7 型蜜罐部署 / 检测 / 捕获分析
- **IDS** — Suricata / Snort 规则包生成与导出
- **防火墙** — 基线规则 + 封 IP
- **系统加固** — SSH / 文件权限 / 内核参数审计
- **周期巡逻** — 9 项安全检查
- **威胁狩猎** — IOC 驱动的主动狩猎
- **先敌发现** — 薄弱点预扫描
- **动态防御** — 四级威胁自适应 + 自动封 IP
- **崩溃守护** — 进程崩溃自动守护
- **事件源** — EVTX 结构化拉取 + 实时订阅
- **零依赖** — 纯 Python 标准库，无需 pip install

## 🏗️ 架构

```
先敌发现 → 蜜罐 → 监控 → 检测 → 响应 → 加固 → 报告
preemptive  honeypot  event   detection  responder  harden  report
                        │
                        ├─ 45 条 detect_*.py 规则（7 域）
                        ├─ IDS 规则包
                        └─ 动态防御（四级威胁 + 封 IP）
```

## 🛡️ 检测规则覆盖（45 条 / 7 域）

| 域 | 数量 | 覆盖 |
|----|------|------|
| AD 域 | 9 | DCSync / Kerberos / NTLM / BloodHound / ADCS / Azure AD / GPO / LAPS |
| AI 安全 | 7 | Prompt 注入 / Jailbreak / Agent 劫持 / 模型攻击 / 配置注入 |
| 工控 ICS | 8 | PLC / SCADA / Modbus / OPC-UA / IEC61850 / 固件 |
| 移动 | 8 | APK / iOS / Frida / 恶意软件 / WebView |
| 无线 | 6 | WiFi / BLE / RFID / GPS / 蜂窝 / IoT |
| Windows | 4 | LSASS Dump / PowerShell / UAC / WMI |
| 通用蓝队 | 3 | C2 / 数据外泄 / 横向移动 |

## 🚀 快速上手

```bash
# 克隆
git clone https://github.com/wwyhji/froghacker-defense.git
cd froghacker-defense
```

### 单点检测（无需安装）

```python
from tools.blueteam import DetectionEngine

e = DetectionEngine()
print('规则数:', e.rule_count())  # 45

# 检测 DCSync 攻击（事件 4662 + DRSUAPI）
alerts = e.scan({'event_code': '4662', 'raw': 'DRSUAPI replication'})
for a in alerts:
    print(a.attack_type, a.severity, a.recommendations)
```

### 完整防御管线

```python
from tools.blueteam import BlueTeamPipeline

r = BlueTeamPipeline().run('localhost', deploy_honeypots=False, skip_threat_hunt=True)
print(r.summary)
```

> **权限提示**：封 IP（写 Windows 防火墙 `netsh`）、读 `Security`/`Sysmon` 事件日志需要管理员权限。

## 🛡️ 专利保护与开源边界（重要）

本开源包**已剥离**以下受专利保护的技术方案（见 [NOTICE](./NOTICE)、[MANIFEST.md](./MANIFEST.md)），它们**不在**本仓库内：

- 代数拓扑 / 同调论知识库盲区检测（Betti 数）
- 形式概念分析（FCA）告警聚类
- 因果推断告警根因
- Petri 网攻击行为链建模
- 归一化压缩距离（NCD）与 KL 散度
- 知识库自充飞轮（AlphaLoop）与统一管线调度

上述方案已申请发明专利（申请日 2026-10-13）。本仓库仅开源业界通用的常规防御能力，**不构成**对上述专利技术方案的实施许可。

## 📁 目录结构

```
froghacker-defense/
├── LICENSE               Apache-2.0
├── NOTICE                专利保留声明
├── MANIFEST.md           文件清单与剥离说明
├── pyproject.toml        打包配置
└── tools/
    ├── blueteam/         蓝队核心模块
    │   ├── detection_engine.py   统一检测引擎（45 规则 + 多特征匹配）
    │   ├── honeypot.py / honeypot/   7 型蜜罐（部署/检测/分析/管理）
    │   ├── ids.py                IDS 规则包（Suricata / Snort）
    │   ├── firewall.py           防火墙（基线规则 + 封 IP）
    │   ├── harden.py             系统加固
    │   ├── patrol.py             周期巡逻（9 项检查）
    │   ├── threat_hunt.py        威胁狩猎
    │   ├── preemptive.py         先敌发现
    │   ├── dynamic_defense.py    动态防御（四级威胁 + 封 IP）
    │   ├── crash_defense.py      崩溃守护
    │   ├── event_source.py       事件源（EVTX 拉取）
    │   ├── realtime_source.py    实时事件订阅
    │   ├── log_analyzer.py       日志分析
    │   ├── dump_analyzer.py      dump 分析
    │   ├── responder.py          处置闭环
    │   ├── recon_warning.py      侦察预警
    │   └── defense_benchmark.py  防御基准
    ├── core/             logger + discovery（轻依赖）
    ├── ad_attack/defense/    9 条 AD 域检测规则
    ├── ai_security/defense/  7 条 AI 安全检测规则
    ├── ics/defense/          8 条工控检测规则
    ├── mobile/defense/       8 条移动检测规则
    ├── wireless/defense/     6 条无线检测规则
    └── windows/defense/      4 条 Windows 检测规则
```

## 📄 许可证

Apache License 2.0，© 2026 FrogHacker (wwyhji)。专利保留声明见 [NOTICE](./NOTICE)。
