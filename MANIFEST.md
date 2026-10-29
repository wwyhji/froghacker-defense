# defense-oss 文件清单与剥离说明

> 生成日期：2026-10-25
> 来源仓库：`D:\froghacker`（蛙客 v5.2，主仓库为专有软件）

## 一、开源内容（本仓库）

### 蓝队核心模块（`tools/blueteam/`）

| 模块 | 能力 |
|------|------|
| `detection_engine.py` | 统一加载 60 条 `detect_*.py` 规则，多特征事件检测 |
| `honeypot.py` + `honeypot/` | 蜜罐部署/检测/分析/管理（7 型） |
| `ids.py` | IDS 规则生成与导出 |
| `firewall.py` | 防火墙规则基线/封 IP |
| `harden.py` | 系统加固审计 |
| `patrol.py` | 周期安全巡逻 |
| `threat_hunt.py` | 威胁狩猎 |
| `preemptive.py` | 先敌发现（薄弱点扫描） |
| `dynamic_defense.py` | 四级威胁自适应 + 封 IP |
| `crash_defense.py` | 崩溃守护 |
| `responder.py` | 告警处置闭环 |
| `event_source.py` / `realtime_source.py` | 事件源（EVTX/实时） |
| `log_analyzer.py` / `dump_analyzer.py` | 日志/dump 分析 |
| `recon_warning.py` | 侦察预警 |
| `defense_benchmark.py` | 检测基准 |
| `sysmon-config.xml` | Sysmon 配置 |

### 检测规则（60 条，8 域）

| 域 | 数量 | 覆盖 |
|----|------|------|
| ad_attack | 9 | ADCS/DCSync/Kerberos/NTLM/BloodHound/... |
| ai_security | 17 | Prompt注入/Jailbreak/Agent劫持/模型攻击/MCP工具滥用/记忆投毒/非人类身份/供应链/无界消耗/... |
| ics | 8 | Modbus/DNP3/PLC/SCADA/... |
| mobile | 8 | APK/iOS/Frida/恶意软件/... |
| wireless | 6 | WiFi/BLE/RFID/GPS/... |
| windows | 4 | LSASS/PowerShell/UAC/WMI |
| blueteam | 3 | C2/Exfil/Lateral |
| web | 5 | LFI/SQLi/Webshell/二次编码/敏感文件 |

### 轻依赖（`tools/core/`）

- `logger.py` — 日志（纯标准库）
- `schemas/discovery.py` — Discovery dataclass（纯标准库）

## 二、已剥离（**不在**本仓库，受专利保护或属攻击侧）

| 文件 | 剥离原因 |
|------|---------|
| `alert_cluster.py` | FCA 概念格（专利04） |
| `behavior_chain.py` | Petri 网行为链（专利04） |
| `coverage_homology.py` | 同调盲区检测（专利04 核心） |
| `root_cause.py` | 因果推断根因（专利04） |
| `math_demo.py` / `math_detect_engine.py` / `math_poc.py` / `math_vs_naive.py` | 数学引擎演示/对照 |
| `weaponize_blindspot.py` | 依赖同调（`homology_holes`） |
| `weaponize_scorer.py` | 武器化评分（攻击侧辅助 + Shodan） |
| `attacker_recon.py` | 攻击侧侦察（依赖 `requests`） |
| `cli.py` | 依赖 `tools.core.cli_registry`（平台架构） |
| `__init__.py` 中 `run_self_heal` / AlphaLoop / Flywheel | 知识库飞轮（专利 P003） |

## 三、改写说明

- `tools/blueteam/__init__.py`：删除 `__weld_status__`、`run_self_heal()`、AlphaLoop/Flywheel 摄入段落，仅保留 `BlueTeamPipeline.run()` 防御主线（先敌发现→蜜罐→IDS→日志→狩猎→防火墙→加固）。
- 各域 `__init__.py` 置为空文件（原文件 import 攻击侧模块，避免连带拖入）。
- `tools/windows/` 原为命名空间包，此处补空 `__init__.py` 以稳定导入。

### 2026-10-29 补强 Security for AI（对齐 OWASP）

- `tools/ai_security/defense/` 新增 10 条检测规则，对齐 OWASP LLM Top 10 (2025) 与 Agentic Security Initiative (ASI)：
  `sensitive_info_disclosure`(LLM02) / `supply_chain`(LLM03) / `improper_output_handling`(LLM05) /
  `excessive_agency`(LLM06) / `system_prompt_leakage`(LLM07) / `unbounded_consumption`(LLM10) /
  `mcp_tool_misuse`(ASI02) / `agent_memory_poisoning`(ASI06) / `nonhuman_identity_abuse`(ASI03) / `inter_agent_comm`(ASI07)。
- 每条新增规则的 `SIGNATURE` 增加 `owasp` 字段用于对齐标注（`detection_engine` 不消费该字段，无副作用）。
- AI 安全域规则数 7 → 17，总规则数 50 → 60。
