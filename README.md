# FrogHacker Defense — 蛙客 AI 防御端（开源版）

> 响应时代号召，开源蛙客网络安全分析自动化平台的**防御端**。
> 本仓库是防御能力的开源发布，许可证 **Apache-2.0**，详见 [LICENSE](./LICENSE) 与 [NOTICE](./NOTICE)。

## 这是什么

蛙客（FrogHacker）是攻·防·取三端共生的安全分析自动化平台。本仓库开源的是**防御端（蓝队）**：
常规防御能力，含统一检测引擎、蜜罐、IDS、防火墙、加固、巡逻、威胁狩猎、先敌发现、动态防御等。

```text
先敌发现 → 蜜罐 → 监控 → 检测 → 响应 → 加固 → 报告
```

## 能力清单

| 模块 | 能力 |
|------|------|
| `DetectionEngine` | 统一加载 45 条检测规则（跨 AD域/AI安全/工控/移动/无线/Windows/C2），多特征事件匹配 |
| 蜜罐 | 7 型蜜罐部署/检测/捕获分析 |
| IDS | Suricata/Snort 规则包生成与导出 |
| 防火墙 | 基线规则 + 封 IP |
| 加固 | 系统加固审计（SSH/文件权限/内核参数） |
| 巡逻 | 周期安全巡逻（9 项检查） |
| 威胁狩猎 | IOC 驱动的威胁狩猎 |
| 先敌发现 | 薄弱点预扫描 |
| 动态防御 | 四级威胁自适应 + 自动封 IP |
| 崩溃守护 | 进程崩溃自动守护 |
| 事件源 | EVTX 结构化拉取 + 实时订阅 |

## 快速开始

```bash
# 单点检测（无需安装，纯标准库）
python -c "
from tools.blueteam import DetectionEngine
e = DetectionEngine()
print('规则数:', e.rule_count())
for a in e.scan({'event_code': '4662', 'raw': 'DRSUAPI replication'}):
    print(a.to_dict())
"

# 完整防御管线
python -c "
from tools.blueteam import BlueTeamPipeline
r = BlueTeamPipeline().run('localhost', deploy_honeypots=False, skip_threat_hunt=True)
print(r.summary)
"
```

> 封 IP / 读 Security 事件日志需管理员权限（Windows 上写防火墙 `netsh`，读 `Security`/`Sysmon` 事件）。

## 专利保护与开源边界（重要）

本开源包**已剥离**以下受专利保护的技术方案，它们**不在**本仓库内（见 [NOTICE](./NOTICE)、[MANIFEST.md](./MANIFEST.md)）：

- 代数拓扑/同调论知识库盲区检测（Betti 数）
- 形式概念分析（FCA）告警聚类
- 因果推断告警根因
- Petri 网攻击行为链建模
- 知识库自充飞轮（AlphaLoop）与统一管线调度

本仓库仅开源业界通用的常规防御能力，不构成对上述专利技术方案的实施许可。

## 许可证

Apache License 2.0，© 2026 FrogHacker (wwyhji)。专利保留声明见 [NOTICE](./NOTICE)。

## 目录结构

```
defense-oss/
├── LICENSE               Apache-2.0
├── NOTICE                专利保留声明
├── MANIFEST.md           文件清单与剥离说明
└── tools/
    ├── blueteam/         蓝队核心模块
    ├── core/             logger + discovery（轻依赖）
    └── */defense/        45 条检测规则（7 域）
```
