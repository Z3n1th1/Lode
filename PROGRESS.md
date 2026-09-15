# Lode 当前进度

更新时间：2026-09-13（重写。旧版停留在 P2 之前的状态，提到的 `/dsh`、`/arl`、
intel 路由、17 面板抽屉、`pentest-agent/` 目录都已不存在。）

这份文件是下一次接手的起点。**以代码和测试为准**，本文件的数字若与代码冲突，以代码为准。

## 一句话架构

**一个入口**：`UnifiedChat` 是一条对话流。你在某个模式下说一句话 → `core/intent_router`
判断该回话还是该升级 → 升级就落成一个**持久化任务**（`core/job_registry` + `core/job_runner`）
→ 任务的所有事件写进该会话的 append-only 事件日志（`core/event_log`）→ 前端用 SSE
按 `seq` 回放，子任务进度就长在同一段对话里。

两种入口都在这条链上：

```
浏览器 → POST /api/v1/chat/sessions/{id}/messages  (202 + job_id)
       → GET  /api/v1/chat/sessions/{id}/stream    (SSE, since=游标续传)
```

## 怎么跑（Windows）

```powershell
# 1) 依赖（只需一次）
D:\Environment\Python\miniforge\envs\py310\python.exe -m pip install -r requirements.txt
cd console; npm install; npm run build; cd ..

# 2) 起服务（读仓库根的 .env）
.\run-console.ps1                 # 或： python lode.py console
# 打开 http://127.0.0.1:8088
```

登录密码与端口都在仓库根的 `.env` 里，**不要**把它们抄进任何被提交的文件：

| 变量 | 作用 |
|---|---|
| `LODE_ADMIN_PASSWORD` | Console 登录密码（本地自用，非生产凭据） |
| `LODE_SESSION_SECRET` | 会话 cookie 签名密钥（≥32 字符） |
| `LODE_PORT` | 监听端口，默认 8088 |
| `LLM_API_KEY` / `LLM_BASE_URL` / `LLM_MODEL` | 模型配置，当前 `deepseek-flash` |
| `SRC_MAX_CYCLES` / `SRC_MAX_EXPLORE` / `SRC_DELAY_SECONDS` | 扫描预算与节流 |

`.env` 已在 `.gitignore` 里。想改密码就改那一行后重启服务。

### 怎么开始挖洞

1. 头部**模式选择器**选「SRC 黑盒」。
2. 对话框里直接说，例如：`在授权范围内对 https://example.com 做只读侦察`。
3. 回合会自己升级成 `src_loop` 子任务，进度以卡片形式流在对话里；
   黑板/DAG/候选队列在左侧「控制面板 → SRC 黑板」。
4. **只读铁律**：agent 只发 GET/HEAD；任何写操作会停下来要人工确认。

### 另一个入口：新建项目（先确认，再开跑）

「项目」页 → **新建**：填目标 + 一句「这次要看什么」+ 策略档 + 动作开关。

1. **预览确认单**：只铸一张 digest 绑定的预览，不执行、不落卡；同时进「待确认」队列（15 分钟有效）。
2. **确认并开跑**：把 `intake_id` + `options_digest` 回显给门核对，核对上了才落 `TargetCard`
   （`ai-pentest-evidence/projects/<target_id>/target.yaml`），然后按**卡上那一份 scope**起一轮
   `target_run`，进度流进它自己的会话 —— 弹窗里点「去看运行」直接跳过去。
3. 确认单绑的就是你当时看到的那张单：目标 / 主机 / 入口 / 策略档 / 说明 / 开关全在 `options_digest` 里。
   卡在确认之后被改过，运行会拒绝启动（digest 不匹配），不会按改过的范围跑。
4. 开关里没有爆破：门上直接 400 `brute_force_out_of_scope`，不会静默丢掉你拨的开关。

命令行等价入口（不走 Console）：

```powershell
python lode.py auto https://example.com --scope scope.json     # 扫描 → agent 全流程
python lode.py scan https://example.com --scope scope.json     # 只做表面发现
python lode.py agent out/src-blackboard.json --scope scope.json
python lode.py sessions / progress / doctor
```

## 当前状态

| 模块 | 状态 | 说明 |
|---|---|---|
| Console（统一对话） | 可用 | 模式 + 持久化任务 + SSE 事件流 + 卡片渲染；单一主视图 |
| 对话模式 | 2 个 | `chat` / `pentest`（挖洞），配置在 `config/modes.yaml` |
| 技能包 | 6 个 | `.codebuddy/skills/**`，由 `core/skills.py` 每轮注入 system prompt |
| SRC 黑板 | 可用 | facts/intents/dead_ends/hints/claims + 租约心跳，跨进程原子写 |
| 任务层 | 可用 | 状态落盘、租约幂等、cooperative stop、重启后标记 interrupted |
| 目标准入（intake 门） | 可用 | 预览 → 确认 → `TargetCard` 的 digest 绑定；确认后按卡起 `target_run` |
| SRC surface | 可用，无授权即拒绝 | scope 内低频 GET + 候选提取，不提交表单、不爆破 |
| 主动渗透（Strix） | **依赖外部 runner** | 缺 Strix / 私有 skill 时按设计阻断，不伪造成功 |
| 飞书出站 | 已接脱敏路由 | **未做真实租户验收** |
| SignalHarbor（资讯） | 可用 | 独立 `news run` 管道；与 SRC 页面无关 |
| intel / guardrails-mcp | 可用 | 独立包：`news/pipeline.py`、`notify/task_router.py` 在用 |

HTTP 面共 **33 个 API 路由**，全集冻结在 `tests/test_route_contract.py`。改路由必须**显式**
改那个集合，这是有意为之——它挡住过一批"文档有、代码没有"的幽灵路由。

## 事件流契约（排障先看这里）

事件形状：`{seq, ts, session_id, turn_id, agent_id, kind, ...载荷}`，`seq` 单调、靠
`since` 游标续传。当前真正会被发出的 kind：

```
subtask_started   job_kind / target / title      ← 任务开场（由 JobRunner 发，只能发一次）
subtask_progress  phase / findings?              ← 阶段推进
subtask_finished  status / error                 ← 终态
user_message / assistant_message / mode_changed
```

`core/event_log.EVENT_KINDS` 还声明了 `tool_call` / `tool_result` / `finding` /
`approval_*` / `reasoning` / `assistant_delta`，前端已能渲染，但目前没有生产端发它们。

**这个边界很脆**：`JobContext.emit` 是 kwargs 塞进 dict 再 merge，载荷键会和信封撞名，
或者和 `JobRunner` 自己发的事件重复——两种都不会报类型错。2026-09-13 在这里修掉过两个真
bug（`kind=` 载荷让 `append` 抛 TypeError 被静默吞掉 → 所有 `subtask_started` 都没进流；
以及同一子任务被宣告两次）。`tests/test_chat_api.py::EscalationTests` 现在锁住这条链路。

## 回归

```powershell
# Python（必须 py310）
D:\Environment\Python\miniforge\envs\py310\python.exe -m pytest -q
# 前端
cd console; npm run typecheck; npm run test; npm run build
```

当前基线（2026-09-13，连续三次结果一致）：

- Python **354 passed, 7 skipped**
- 前端 **33 passed**，`vue-tsc` 与 `vite build` 干净

## 已知限制

1. **没对真实目标跑过完整扫描。** 所有验证止于单元/集成测试 + 本机冒烟。真实目标的
   误报率、耗时、单源限速、候选质量都还没有数据。这是当前最大的未知。
2. 主动渗透仍**依赖外部 Strix runner** 和未随仓库提供的私有 skill/契约；缺失时阻断。
3. 飞书没有真实租户验收：没有 `FEISHU_APP_ID` / `FEISHU_APP_SECRET`，没向真实群发过消息。
4. `notify/task_router.py` 里 `from runner_contract import RunnerBlockedError` 指向一个**仓库里
   不存在的模块**（历史遗留）。飞书任务路由一旦走到那条分支就会 ImportError，走不到就没事。
5. X/Twitter 采集默认关闭，需要官方 API token。
6. `npm audit` 未复核（国内镜像 404、官方源 `ECONNRESET`）。
7. `deepseek-flash` **默认开启思考模式**：小 `max_tokens` 会被思考吃光而返回**空 content**
   （实测 8 token 全进 `reasoning_content`）。请求里加 `"thinking": {"type": "disabled"}`
   可关闭（实测有效、`reasoning_tokens` 归零）。扫描循环里大量调用受影响，值得评估。
8. `PROGRESS.md` 本文是新的；`README_TEST.md` / `USAGE.md` / `docs/*.md` 部分章节仍描述已删
   功能，未逐篇清理。

## 近期三层历史

- `f1ad831` 删掉重构留下的死代码（control_plane shim、H1 intake 层、会话管理操作、
  陈旧 pnpm 锁），抽出 `core/file_lock.replace_with_retry`。
- `658559d` 收敛成单一对话面：新增 `UnifiedChat` + 事件流前端，删除
  `/api/v1/src-agent/*`（12 路由）、旧 Strix 对话子系统、三个早已 404 的死面板。
- `ecd078c` / `c0d7603` P6 死代码 / P4 统一对话 + 模式 + 意图路由 + 技能包。

## 纪律

- 每个阶段都要让 pytest + vitest 保持绿；改路由就**显式**同步 `test_route_contract.py`。
- 模型与密钥不进代码、不进日志、不进事件、不进飞书消息。
- 原始请求/响应、cookie、token、证据文件只留在本机。
- `.env` **不要**用项目级 sed 批量替换（历史上这么干把密码改坏过）。
