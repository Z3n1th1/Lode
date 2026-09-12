# Lode — AI 驱动的 SRC 漏洞挖掘平台

> 跨平台（Windows / Linux / macOS）。统一入口 `lode.py`。

## 快速开始

```bash
# 1. 配置（首次）
cp .env.example .env
# 编辑 .env：填入 LLM_API_KEY、Console 密码

# 2. 环境检查
python lode.py doctor

# 3. 启动 Console
python lode.py console
# → 浏览器打开 http://127.0.0.1:8088
```

## 核心命令

| 命令 | 作用 |
|------|------|
| `python lode.py console` | 启动 Console（管理入口） |
| `python lode.py scan <url> --scope scope.json` | 表面发现 |
| `python lode.py auto <url> --scope scope.json` | 全自动：扫描→分析 |
| `python lode.py agent <blackboard> --scope scope.json` | LLM agent 循环 |
| `python lode.py sessions` | 列出历史会话 |
| `python lode.py resume <session_id> --scope scope.json` | 继续上次会话 |
| `python lode.py progress` | 测试进度总览 |
| `python lode.py doctor` | 环境检查 |

## Console API

| 端点 | 作用 |
|------|------|
| `POST /api/v1/session` | 登录 |
| `POST /api/v1/src-agent/chat` | 与 agent 对话（主入口） |
| `GET /api/v1/src-agent/events` | 实时事件流 |
| `GET /api/v1/src-agent/progress` | 测试进度 |
| `POST /api/v1/src-agent/start` | 后台一键跑 |

## Agent 工具（全部 scope-checked，只发 GET/HEAD）

| 工具 | 作用 |
|------|------|
| `scan_target` | 被动表面发现 |
| `run_agent_analysis` | LLM 深度分析候选 |
| `fetch_url` | 抓指定 URL（scope + 写操作拦截） |
| `show_blackboard` | 查看黑板状态 |
| `add_candidates` | 手动加候选 |
| `show_progress` | 测试进度 |
| `auto_scan` | 全自动：扫描→分析→报告 |

## 项目结构

```
lode.py             统一入口（三平台）
agents/                     src_agent(LLM循环) / src_chat(对话+工具) / surface_discovery / src_autopilot
core/                       config / src_blackboard / test_log / model_client / guardrails
references/                 src-pentest-skill.md + knowledge-base/（49 个漏洞类型模块）
projects/<program>/         每个 H1 项目一个文件夹（project.json + <site>.md + runs/）
deploy/multi-platform.md    多平台部署指南（Windows/Linux/macOS）
```

## 多平台部署

见 `deploy/multi-platform.md`：
- **Windows**: `run-console.ps1` / NSSM 服务
- **Linux**: `run-console.sh` / systemd / Docker
- **macOS**: `run-console.sh` / launchd

## 安全边界

- 只发 GET/HEAD，scope 内，低频
- 语义写操作拦截（delete/update/pay/send 等）
- 发现需证据，不报未验证猜测
- VPS 部署详见 `docs/security-boundary.md`

---

# 附：原 pentest-agent 设计与纪律

> 本次 SRC surface 与公开安全情报两条链路的快速测试入口见 `README_TEST.md`。

> 状态：骨架（2026-08-06 建立）。**完整设计见 `../docs/agent迁移设计_2026-08-06.md`（22+ 节），先读它再动工。**
> 部署目标：VPS 上自动渗透 + 代码审计 + 报告；多并发优先效率；自身安全（当前服务固定 bind `127.0.0.1`，远程管理另走独立发布方案）；支持 MoA 多模型与多核心融合；支持自进化（正向门守门）。

## 目录职责与纪律

| 目录 | 职责 | 关键纪律（违反=返工） |
|---|---|---|
| `core/` | fork 的现成 runtime（Strix/pentestagent 待定） | **尽量少改；core 不被任何插件依赖**（依赖单向，设计 §12） |
| `guardrails-mcp/` | ★全部护栏收敛成的唯一 MCP server（gateway/policy/人工门/Verifier/证据/三问门/stall/reflect） | **护栏只此一份**（根治漂移）；契约见设计 §10 |
| `registries/` | 扩展点注册处：tools/roles/gates/signals/models | 新增能力只加注册项，**禁碰 core** |
| `agents/` | 角色定义（Scout/Hypothesis/CodeAuditor/Verifier/Reporter/Notifier）+ TargetQueue + 碰墙自愈闭环 | 角色=声明式 RoleCard（数据） |
| `code-audit/` | 白盒审计隔离区（clone 落点/semgrep 规则/CodeAuditCard） | **克隆代码永不执行**（不 build/不跑 install 脚本） |
| `notify/` | Notifier 渠道适配 + 飞书白名单控制入口 | 渠道配置走 deploy env；普通通知只出不进，飞书指令仅允许显式白名单；只发结论不发报告或证据细节 |
| `console/` | 本地只读控制台（Goal/Task/profile/sandbox 状态） | 当前固定 loopback；写操作、审批与远程管理尚未接入 |
| `references/` | 领域知识/打法卡（数据，非代码） | 热更新生效（L1 通道）；新卡必须带 source+双审 |
| `evals/` | golden CTF + A/B + 正向门 + 对抗 eval | 每次改动三门全绿才可部署 |
| `audit/` | InvariantGate/AdversarialReview/AuditSweep/AcceptanceRun 产物 | 执行者≠审查者 |
| `evolution/` | 自进化：`candidates/`（未过门提案）、`ledger/`（每次自改留痕+回滚点）、`freeze_state` | 连续回归失败≥2 自动冻结；L3(core/安全门)永不自改 |
| `deploy/` | docker-compose + WireGuard + self-check 基线脚本 + systemd | 当前服务一律 bind `127.0.0.1`；远程发布须单独验收 |
| `build/` | 唯一生成脚本（派生物全部 build 产出） | 禁止手改派生物 |
| `ci/` | SSOT diff + 回归 + 正向门 + 审计门 | 红则不合并 |

## 五条架构硬决策（来自设计文档，动工前复述）

1. **不自造 agent 核心**——fork 现成 runtime，护城河在护栏+知识+Verifier。
2. **SSOT**：一份 canonical + build 生成派生 + CI diff 门；漂移病的唯一解药。
3. **硬门优先于软规则**：能被绕的提示词不叫护栏，代码路径强制才叫护栏。
4. **正向提升才入库**：新模型/新核心/新打法/自改进提案，全部过正向门（golden 回归 + A/B + 误报不升）；不过就留在候选区。
5. **授权边界是启动前置硬门**：scope.yaml/授权确认缺失时 agent 拒绝启动。

## 起步顺序（对应设计 §15 分阶段 plan）

1. 定底座（设计 §16.1：Strix vs pentestagent vs Hermes）→ 放进 `core/`
2. `guardrails-mcp/` 先包 5 个 tool 跑通最小闭环：`gateway_request` / `policy_grade` / `human_gate` / `record_evidence` / `verify_finding`
3. 只读侦察 agent 接 MCP，验证"绕不过 gateway"
4. 多角色 + MoA + 碰墙闭环（§6）→ 批量 TargetQueue（§17）→ CodeAuditor（§18）
5. evals + CI 三门 → deploy 上 VPS（WireGuard mesh）

## 相关文档

- **★总体实施计划（最终选型 + 分阶段，先读这份）**：`../docs/pentest-agent总体实施计划_最终选择_2026-08-07.md`
- **模型分级 + 设计自审补强（3档模型策略 + 33项对抗审计缺陷 + 落地优先级）**：`../docs/agent模型分级与设计自审补强_2026-08-07.md`
- **★策略修订（红队后·物理强制+动作门放松安全落地，收紧上面若干条，以此为准）**：`../docs/agent策略修订_物理强制与动作门放松安全落地_红队后_2026-08-07.md`
- **安全需求补充（敏感金库2FA/安全告警/自查/append-only备份，铁律,给未来基线agent）**：`../docs/agent安全需求补充_敏感金库2FA与安全告警与自查_2026-08-08.md`
- **★实施计划（基线闭环+安全功能落地·任务板/契约/阻塞项,当前动工以此为准）**：`../docs/agent实施计划_基线闭环与安全功能落地_2026-08-08.md`
- 迁移设计（主文档）：`../docs/agent迁移设计_2026-08-06.md`
- **核心设计 v2 补强**（profile 统一 schema / 坑账本硬不变量 / hook→core 落点映射 / 并发+服务器配置 / 决策清单）：`../docs/agent核心设计v2补强_profile统一与坑账本与hook去核化_2026-08-07.md`
- **工程纪律与运行时设计**（策略固化模板 / 反漂移审计 / 破瓶颈防循环 / 搜索优先 / 代理池 mihomo / 资源治理 / docker化 / 备份 / RAG / 防幻觉）：`../docs/agent工程纪律与运行时设计_反漂移破瓶颈代理池资源备份RAG_2026-08-07.md`
- 渗透 Skill 预期行为与验收基准：`../docs/渗透Skill预期行为与验收基准.md`
- 复盘与整改 plan：`../docs/复盘_2026-08-05_gm-test-996sdk_dp测试不足与整改plan.md`
- 现有 skill canonical：`../skills/ai-pentest-matrix/`（护栏与知识的迁移来源）

## 本地只读 ControlPlane Console（2026-08-12）

`console/` 现提供中文、本地认证的运行状态工作台。它只投影 `goals.jsonl`、`pending_profiles.jsonl`、`strix_tasks.jsonl` 和合成 `SandboxRunCard` 的字段白名单；不会创建目标、批准动作、执行工具或向浏览器返回指令、会话标识、原始证据、文件路径或密钥。

首次构建与启动：

```powershell
Set-Location .\console
npm ci --ignore-scripts
npm run build
Set-Location ..

$env:WEBUI_ADMIN_PASSWORD = '<至少16字符的独立强口令>'
$env:WEBUI_SESSION_SECRET = '<至少32字符的随机会话签名密钥>'
python -m console.server --state-dir 'C:\path\to\feishu-state' --port 8088
```

访问 `http://127.0.0.1:8088`。启动器将 host 固定为 `127.0.0.1`，没有开放地址参数；API 需要本地会话登录，`/healthz` 只用于健康检查。开发前端运行 `console\npm run dev`，它同样固定 loopback，并只将 `/api` 代理到本地 `8088`。不要把此服务或开发服务器直接暴露到公网；远程管理仍需单独的 TLS、独立账号、IP allowlist、速率限制和审计发布方案。
