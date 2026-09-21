# Lode 当前进度

更新时间：2026-09-21（最近一次改动：授权文档入口链 + 多并发收尾，并在真实程序上把授权文档
入口链跑通一遍——见「已知限制 1」。旧版停留在 2026-09-13，
旧版提到的 `/dsh`、`/arl`、intel 路由、17 面板抽屉、`pentest-agent/` 目录都已不存在。）

这份文件是下一次接手的起点。**以代码和测试为准**，本文件的数字若与代码冲突，以代码为准。
先读「接下来」，再读「当前状态」。

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

1. 头部**模式选择器**选「挖洞」（`console/src/views/chat/ModeSelect.tsx`；另一个是「对话」，
   配置在 `config/modes.yaml`）。
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

HTTP 面的全集冻结在 `tests/test_route_contract.py`（**那个文件是唯一权威**；这里不写数字——
写过一次 33，等发现时实际已经是 35）。改路由必须**显式**改那个集合，这是有意为之——它挡住过
一批"文档有、代码没有"的幽灵路由。

## 接下来（接手先看这里）

前三件事是同一个主题：**多并发的收尾**。速率盖子已经做完了（见下一节），剩下的是
"并发起来的那些任务，操作员看不看得见、命令行享不享得到、断了能不能接着跑"。
每条都附了"怎么证明它还没做"，别只信本文。

1. **队列可见性 + 背压。** 池子宽度是 `LODE_JOB_WORKERS`（`core/job_runner.py:25`，缺省 8），
   `ThreadPoolExecutor` 的队列无上限、也不可见——`console/src/` 里 grep 不到 `queued` /
   `backpressure`。数据其实是有的（`job_registry` 有 `QUEUED`，`submit` 先落
   `status=queued` 再进池，`GET /api/v1/jobs` 原样返回），缺的是**它进不了对话**：

   - `subtask_started` 是**工人取到 job 的那一刻**才发的（`core/job_runner.py:155`，只在
     `_run` 里），不是提交时。所以一次确认 30 台主机，界面上只有 **8 张卡**，另外 22 台
     **一张卡都没有**——操作员分不出"在等"和"根本没建起来"。
   - 前端 `SubtaskStatus`（`console/src/chatEvents.ts:22`）只有 `running` / `completed` /
     `failed` 三种，连一个能渲染"排队中"的值都没有。
   - 总数只在 `POST …/engagement/confirm` 的响应 `run.launched` 里出现过一次，刷新就没了。

   所以这件要补的不只是"给池子加个队列视图"，而是**提交时就要有一条事件**（或让
   `/jobs` 的排队数进对话），否则那张卡永远出不来。
2. **命令行批并发。** `lode.py:116` 的 `cmd_scan` 还是 `for target in targets` 串行。控制台
   已经会按主机 fan-out 了，命令行不会——同一份授权文档，两个入口的吞吐不一样。
3. **长跑可恢复。** `JobRegistry.recover` 在 `auto_resume=True` 时会重新入队
   （`core/job_registry.py:209`），但**没有任何调用方传它**：`console/app.py:58` 用缺省值，
   于是重启把未完成的 job 一律标成 `interrupted`。也没有 job 内的检查点，所以"接着跑"目前
   指的是"从头再跑一遍"。先用 `grep -rn "auto_resume=True"` 确认这条是否仍然成立。
4. **候选质量**（前三件做完再做）。候选来自 robots/HTML，而 Explorer 只发 GET，所以
   "有候选"从来不等于"验证得下去"。**但别再把它当成 0 findings 的主因**——2026-09-21 实测
   证明主因是 reasoner 被 `max_tokens` 截死（见「已知限制 7」），那时 hunt 根本没跑过第 1 圈。
   修完后同样的候选跑出 21 次探索，且漏出来的都是 design-by-default 的信息面。
   模板折叠已落在 `src_autopilot._template_id`（改它**不要**动 `candidate_id` 的算法，
   那会破坏重启安全）。`authz_boundary` 这类假设今天无法验证：没有 header/凭据通道。
5. **engine seam。** `core/governed_request.py` **还不存在**。治理现在重复在
   `agents/surface_discovery.py` 和 `agents/src_agent.py` 两处，`intel/network.py` 是第二条
   无治理的出站。想接 codex/cc/pi 之前先把这条收成单一收口。

明确**不做**：header/cookie 通道、逐主机速率覆盖、真正把 Pi/CC/Codex 接上。

## 授权文档入口（一份 scope 文件 → 一次确认 → 每台主机一个 job）

CLI 一直读 `scope-<program>.json`（`lode.py:_load_scope` → `SurfaceScope.from_mapping`）；
控制台以前只会把对话里那个 URL 手工拼成 scope。现在三条入口共用一条链：

```
粘贴对话      ┐
上传文件      ├─→ agents/scope_document（判定 + 解析，唯一一处）
监听目录      ┘        ↓
             core/intake_state 的待确认槽（和手打 URL 共用同一格，一格只放一样）
                       ↓  操作员确认（回显 intake_id + options_digest）
             console/engagement：EngagementAuthorization/v1 落盘（装文档**原文**）
                       ↓
             console/jobs：每个精确主机一个 engagement_host_run
```

- 判定只在服务端一处（`agents/scope_document.looks_like_scope_document`）。前端**不做镜像**：
  两份判定会互相走样，而走样那一份就是会授权错东西的那一份。
- 每个 job 的 scope 是 `from_mapping(原文)` 再**只**在主机轴上 `dataclasses.replace`。主机之外的
  字段（方法、body 许可、速率、排除清单、超时）全部继承 canonical 解析——绝不重新推导。
  `_scope_from_confirmed_card` 是反面教材：它只搬运 `forbidden_hosts`，方法维度在那条路上直接没了。
- `allowed_domains` 非空、`allowed_ips` 含 CIDR、以及 `*.host` 一律拒绝：它们授权的是操作员没有
  逐一看过的目标（`9045ee3` 的形状）。
- 上限取文档自己写的 `max_fanout`（缺省 30，常量在 `agents/scope_document`，控制台从那里读）；
  超出部分如实回报。
- 速率：一次授权的所有 job 共用一个令牌桶，所以文档写 3 req/s 就是聚合 3 req/s，不是 3×N。
- 监听目录**只铸待确认卡，绝不自动开跑**：放文件这个动作没有任何签名。

## 事件流契约（排障先看这里）

事件形状：`{seq, ts, session_id, turn_id, agent_id, kind, ...载荷}`，`seq` 单调、靠
`since` 游标续传。当前真正会被发出的 kind：

```
subtask_started   job_kind / target / title      ← 任务开场（由 JobRunner 发，只能发一次）
subtask_progress  phase / findings?              ← 阶段推进
subtask_finished  status / error                 ← 终态
user_message / assistant_message / mode_changed
scope_preview     intake_id / summary / digest   ← 认出一份授权文档，待确认（无 document，见下）
```

`scope_preview` 是唯一一个"还没发出任何请求"的事件：它只说"我认出了一份授权文档、
它授权这些主机、等你确认"。**带原文的那一份不发进事件流**（`console/jobs.py` 在 emit 前
剔掉 `document`）——原文留在 intake ledger，确认时按 digest 复读。抄一份进事件流只会让
两份"真相"有机会互相打架。`tests/test_chat_api.py:616` 锁着这条。

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

当前基线（2026-09-21 实测）：

- Python **681 passed, 7 skipped**（`py310`，约 34s）
- 前端 **54 passed**（vitest，4 个文件），`tsc --noEmit` 干净

（2026-09-13 那版写的是 354 / 33 且前端工具写成 `vue-tsc`——控制台早已迁到 React + TS，
`typecheck` 跑的是 `tsc --noEmit`，别再去找 vue-tsc。）

## 已知限制

1. **真实目标跑过,但只到 surface 这一层,而且只走 CLI。** 2026-09-19/20 对 nba.com 跑了两次
   `lode.py scan`（输入是仓库根的 `scope-nba.json` + `targets-nba-hot.txt`，产物在 `out/`，
   三个文件现在都在 `.gitignore` 里）：

   | 轮次 | 目标 | 可达 | paths | api_urls | scripts | 失败 |
   |---|---|---|---|---|---|---|
   | `out/nba-hot.log` | 45 | 40 | 44 | **0** | 20 | 5 `base_unreachable` |
   | `out/nba-batch.log` | 12 | 11 | 45 | 3 | 268 | 1 `base_unreachable` |

   范围闸门在真实目标上确实拦下过请求（`blocked:…host_not_in_scope`，courtside-next.nba.com
   不在 scope 里）——这是 scope 治理目前唯一的真机证据。

   仍然未知的是**跑得出东西**：findings 一个都没有，候选面极薄（hot 那轮 `api_urls` 是 0）。
   上面「候选来自 robots/HTML、Explorer 只发 GET」是**解释**，不是已验证的结论。

   **2026-09-21 补上了答案，而且推翻了"0 findings 是目标问题"这个解释。** 真跑了一轮
   完整 hunt（`lode.py auto` / `lode.py agent`，目标 `login-dev.nba.com`，22 个候选）：

   - **hunt 过去根本没跑起来。** 第一次 `auto` 的输出是 `cycles_run: 1` /
     `total_explored: 0` / `stop_reason: reasoner_failed` / `errors: ["reasoner_returned_none"]`
     —— 22 个候选一个都没被看过。原因是 `_default_llm_complete` 硬编码
     `max_tokens=2048`，而 `deepseek-flash` 默认开思考：实测 2048 时
     `reasoning_content` 7653 字符把预算吃光、`content` 返回 **0 字符**。见下面「已知限制 7」。
     修掉之后同一份黑板跑出 `cycles_run: 8` / `total_explored: 21`。
   - **漏斗本身是好的**（离线注入 fetcher/LLM 验过）：一个带 `evidence` 的 medium 置信
     finding 正常落成 `total_findings: 1` + 黑板 hint。`src_agent.py` 只在缺 confidence
     或缺 evidence 时才丢。
   - **真正挖出来的东西**（未带任何凭据、只读 GET，已逐条独立复核）：`/openidm/info/version`
     200（`9.0.0-20260827231835-a3d41327…`）、`/openidm/config/ui/themerealm` 200（426 KB）、
     `/openidm/info/uiconfig` 200（泄露 `managed/teammembergroup/{super-admins,tenant-admins,
     tenant-auditor,brand-admin}` 与 `adminOauthClient: idmAdminClient`）。
     **判断是 Informational**：`uiconfig`/`ui/*` 是登录页认证前必须读到的 UI 配置，
     ForgeRock 本就如此设计；漏的是命名与地图，不是入口。另外 12 个真值钱的 config 对象
     （`repo.jdbc`、`authentication`、`provisioner.*`、`script`、`secrets`…）**全是 403**，
     敏感面是关着的。所以别再拿这几条当战果。
   - `login-qa.nba.com` 是另一台有真实 surface 的主机（也是 22 paths），还没跑。
     45 台里只有这两台出 surface，其余 33 台 paths+scripts 全为 0。

   另外：**授权文档入口链已经在真实程序上跑过了**（2026-09-21，`run-console.ps1` + 真 HTTP，
   目标是 IANA 保留域名 example.com/.org/.net，只读 GET）。三条入口各验了一遍：

   - **预览 → 确认 → 每台主机一个 job**：一份 3 台主机的文档铸出 `I-8c8adf56d01e`，
     回显 `intake_id` + `options_digest` 后落 `lode-state/authorizations/
     lode-chain-verification-9f02e52591ae.json`（`EngagementAuthorization/v1`，装着文档原文、
     `hosts`、`requests_per_second`），同时起 3 个 `engagement_host_run`（共用一个
     `session_id` + `turn_id`），18 条事件全部落在同一条对话里，三个 job 都 `completed`。
   - **集中速率是真的**：3 个 job 只产生 `lode-state/rate-limit/` 下**一个**桶
     （`key: "lode-chain-verification"`，`rate_per_second: 3.0`）——3 req/s 是聚合值，不是 3×3。
   - **主机轴之外不重新推导**：每个 run 的 `scope.json` 只有自己那一台主机，
     `allowed_methods` / `allow_request_body` 全部继承文档。
   - **粘贴进对话**：只发 `scope_preview` 事件（**确认过里面没有 `document` 键**）+ 一句
     assistant 说明，**没起任何 job**。
   - **监听目录**：槽被占时文件留在原地（`waiting`，不是 rejected）；丢掉待确认卡后下一轮
     才被收走（进 `accepted/`），**同样没自动开跑**。

   新增的实测数字：`LODE_JOB_WORKERS` 缺省 8，3 个 job 真的同时在跑（`GET /api/v1/jobs`
   同时三个 `running`）。零 findings 是意料之中——example.com 的候选面本来就空
   （`autopilot-state.json` 里 `new_candidates: 0`、黑板空），和下面第 4 条同源。

   手打 URL 那条路**也真跑通了**（2026-09-21）：故意回显错的 `options_digest` 得到
   **409 `intake_confirmation_binding_mismatch`**（绑定真的在拦），正确回显后 `TargetCard` 落
   `ai-pentest-evidence/projects/example-com-a379a6f6eeaf/target.yaml`，`target_run`
   （`J-1790003185098-33c8dc`）起跑并 `completed`。所以控制台两条入口都不是纸面绿了。
   唯一还没验的是**浏览器里点**——驱动的都是 UI 调的那几个 HTTP 端点。
2. 主动渗透仍**依赖外部 Strix runner** 和未随仓库提供的私有 skill/契约；缺失时阻断。
3. 飞书没有真实租户验收：没有 `FEISHU_APP_ID` / `FEISHU_APP_SECRET`，没向真实群发过消息。
4. `notify/task_router.py` 里 `from runner_contract import RunnerBlockedError` 指向一个**仓库里
   不存在的模块**（历史遗留）。飞书任务路由一旦走到那条分支就会 ImportError，走不到就没事。
5. X/Twitter 采集默认关闭，需要官方 API token。
6. `npm audit` 未复核（国内镜像 404、官方源 `ECONNRESET`）。
7. ~~`deepseek-flash` 默认开启思考模式……~~ **已修（`9f9fa11`）。** 这条曾经是整个 hunt 的
   唯一死因，不是"值得评估"：`agents/src_agent.py` 的 `_default_llm_complete` 硬编码
   `max_tokens=2048`，实测同一份真实 Reasoner 提示词（system 4479 / user 10506 字符）

   | 配置 | content | reasoning_content | JSON |
   |---|---|---|---|
   | `max_tokens=2048`（旧） | **0 字符** | 7653 字符 | 截断 → `Unterminated string` |
   | `max_tokens=8192`（新缺省） | 1901 字符 | 9442 字符 | 合法 |

   空 content 让函数返回 `None` → `reasoner_returned_none` → hunt 在第 1 圈终止。现在 `max_tokens`
   可配（`LODE_LLM_MAX_TOKENS`），默认 8192 —— 回补 `config/model_policy.example.yaml` 里
   早写好的 `max_tokens: null`。同时那次失败不再是一句无声的 `None`：会带上
   `reasoning_content` 长度，且 reasoner 的"没给内容"和"给的不是 JSON"分开报。
8. `README_TEST.md` / `USAGE.md` / `docs/*.md` 部分章节仍描述已删功能，未逐篇清理。
   `docs/security-boundary.md` 是唯一跟得上代码的（写权限、能力维度那几段）。

## 近期历史（新在前）

- `9f9fa11` / `2fa7c4e`（2026-09-21）**hunt 第一次真的跑起来了**。两处修复：`agents/src_agent.py`
  的 `max_tokens` 截断（上面「已知限制 7」——这是 hunt 从来没跑过第 1 圈的唯一原因），以及
  `total_findings` 漏掉 `needs_human` 分支（**置信度最高的那几条发现反而不计数**，摘要报 0）。
  另外 `core/file_lock.AdvisoryFileLock.__enter__` 写 sidecar 首字节那步没重试，在 Windows
  并发下抛 `PermissionError` 逃出 `EventLog.append`、把发事件的线程带走并**静默丢掉那批事件**
  （实测 4 线程 × 10 条只剩 30 条；控制台 8 个 worker 同时 emit 走的就是这条路）。

- `fd2ee8b`…`90a1c85`（2026-09-21）**授权文档入口链 + 多并发收尾**：一份 scope 文档只有一处
  解析（`agents/scope_document`），三条入口共用，确认后落 `EngagementAuthorization/v1`，
  每台精确主机一个 job 且共用同一个令牌桶；写闸门改成读操作员签的文档（`602eac8`）。
  细节见上面「授权文档入口」和「接下来」两节。
- `add4c99` / `c19f156`（2026-09-20）**多并发打底**：一次 engagement 一个令牌桶且跨进程
  （`core/rate_limit.FileTokenBucket`），池子宽度 `LODE_JOB_WORKERS`（缺省 8），速率改取
  程序文档的原话单位 req/s。`c19f156` 当时按 program 建桶 → 一次粘贴 20 目标 = 20 个桶，
  `add4c99` 修掉了这个泄漏。
- `f1ad831` 删掉重构留下的死代码（control_plane shim、H1 intake 层、会话管理操作、
  陈旧 pnpm 锁），抽出 `core/file_lock.replace_with_retry`。
- `658559d` 收敛成单一对话面：新增 `UnifiedChat` + 事件流前端，删除
  `/api/v1/src-agent/*`（12 路由）、旧 Strix 对话子系统、三个早已 404 的死面板。

## 纪律

- 每个阶段都要让 pytest + vitest 保持绿；改路由就**显式**同步 `test_route_contract.py`。
- 模型与密钥不进代码、不进日志、不进事件、不进飞书消息。
- 原始请求/响应、cookie、token、证据文件只留在本机。
- `.env` **不要**用项目级 sed 批量替换（历史上这么干把密码改坏过）。
