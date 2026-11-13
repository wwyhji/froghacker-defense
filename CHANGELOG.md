# Changelog

## v0.2.0 — 2026-11-13

### 新增

- **4 个防御手段**（纯 Python 标准库，零依赖）：
  - `fim.py` — 文件完整性监控（SHA-256 基线，检测新增/修改/删除）
  - `honeytoken.py` — 金丝雀诱饵（账号/凭证/文件/URL，触碰即告警）
  - `yara_engine.py` — 轻量 YARA 特征匹配（22 规则，文本/regex/hex + any/all/N 条件）
  - `block_backend.py` — 封 IP 后端抽象（`WindowsFirewallBackend` / `NullBackend` 可注入）
- **2 条检测规则**：
  - `detect_recon_scan.py` — 网络侦察（TA0043）
  - `detect_data_staging.py` — 数据收集（TA0009）
- 检测规则 **60 → 62**

### 修复

- `tool_invoker` 悬空依赖 — 补精简版纯 `subprocess` 实现，修复 `honeypot` / `threat_hunt` / `harden` / `firewall` 调用外部工具（nmap/docker 等）时 `ModuleNotFoundError`

### 合规（重要）

- 撤回 `dns_security`（香农熵属信息论技术范畴，专利保留）
- 移除 `discovery` schema（来源常量映射专利模块清单）

## v0.1.0 — 2026-10-25

- 首次发布：AI 防御端开源版（Apache-2.0），60 条检测规则跨 8 域，蜜罐/IDS/防火墙/加固/巡逻/狩猎/动态防御等核心模块。
