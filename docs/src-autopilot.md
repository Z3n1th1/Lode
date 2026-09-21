# SRC 自动化使用说明

`src_autopilot.py` 是一个有界的 SRC surface 分诊器，不是自动利用器。它只在书面授权 scope 内复用 `surface_discovery` 的低频 GET 结果，生成去重、排序、脱敏的候选队列，并把候选同步到本地黑板。

## 首轮

先把 `scope.example.json` 复制成自己的 scope 文件，填写书面授权说明和精确的域名/主机。scope 缺失授权或允许范围时命令会直接失败。

```powershell
.\run-src-autopilot.ps1 `
  -Scope .\scope.json `
  -Target https://authorized.example `
  -OutDir .\src-autopilot-data `
  -MaxRounds 4
```

首轮没有 `-ResultFile` 时会执行被动 surface discovery；后续轮次应传入新的 `SrcSurfaceResult/v1` JSON：

```powershell
.\run-src-autopilot.ps1 `
  -Scope .\scope.json `
  -Target https://authorized.example `
  -OutDir .\src-autopilot-data `
  -ResultFile .\runner-results\surface-002.json
```

每个候选会带有 `A-passive-triage`、`B-authorized-review` 或 `C-human-gated-verification` 阶段。C 阶段也只是人工门前的 intent，不会自动提交表单、爆破、复用凭据、扩大 scope 或定级漏洞。

## 黑板和多并发

`src-blackboard.json` 中分开保存：

- `facts`：从 surface 结果观察到的候选事实；
- `intents`：需要人工/已授权 runner 复核的工作意图；
- `dead_ends`：明确不再重试的死路；
- `hints`：人工或 worker 提供的短提示；
- `claims`：带 heartbeat 和过期时间的单 worker 租约。

runner 接入时使用 `core.src_blackboard.SrcBlackboard` 的 `claim_next()`、`heartbeat()` 和 `finish()`。过期租约会在下一次 claim 时自动回收，进程重启不会留下永久占用。结果引用不应写入 Console 投影；报告和证据继续只留在本机。

最小 worker 循环如下，实际请求前仍要在 runner 自己的 TargetCard/guardrail 中再次校验：

```python
from core.src_blackboard import SrcBlackboard

board = SrcBlackboard("./src-autopilot-data/src-blackboard.json")
claimed = board.claim_next("runner-01", phases=["B-authorized-review"])
if claimed:
    intent_id = claimed["intent"]["intent_id"]
    # 在 runner 的授权门通过后执行一个复核步骤；长任务期间定期 heartbeat。
    board.heartbeat(intent_id, "runner-01")
    board.finish(intent_id, "runner-01", status="completed")
```

黑板锁和 autopilot 状态锁都是跨进程 sidecar 锁，并使用临时文件原子替换。多个 worker 可以并发处理不同 intent；同一 intent 在同一时间只会有一个有效 claim。

## Console

本地 Console 的“SRC 自动化”面板只读展示轮次、候选、租约、死路和提示。默认从 Console state 目录读取 `src-blackboard.json`；黑板放在单独目录时设置 `PA_SRC_BLACKBOARD_PATH`，autopilot 状态文件可用 `PA_SRC_AUTOPILOT_STATE` 指定。两个变量都只影响本机投影，不会改变 scope 或执行策略。

如果还没有黑板，面板显示“等待黑板”，这不是失败；先完成首轮授权 surface 分诊即可。

## LLM 驱动的 SRC Agent

`src_autopilot.py` 只做候选分诊；真正“自动挖洞”的引擎是 `agents/src_agent.py` 里的 `SrcAgentLoop`，采用 Cairn 式三阶段循环 + 成本分层：**廉价 Reasoner 选意图，任意 provider 做 Explorer**。

```powershell
$env:LLM_API_KEY = "sk-your-deepseek-key"

# 1) 表面发现 + 候选分诊(已有能力)
python src_autopilot.py --scope scope.json --target "https://target.com" --out-dir .\out

# 2) LLM agent 循环(读黑板,选 intent,scope 内 GET,分析响应,回写黑板)
python src_agent.py --scope scope.json --blackboard .\out\src-blackboard.json --max-cycles 10
```

每一轮循环:

1. **Reason** —— 读取黑板全量快照,选出 `queued` intent,并生成漏洞假设;提示词明确“候选未经验证,不得重复建议死路”。
2. **Explore** —— `claim` 一个 intent，对目标做 scope 校验后的请求（默认 GET/HEAD；探测档见下），把响应消毒(剥离 cookie/auth,body 截断)后交给 LLM 分析,产出 `fact` / `dead_end` / `hint` 写回黑板。
3. 黑板更新后进入下一轮,直到没有可挖 intent 或触达 `--max-cycles` 硬上限。

`SrcAgentLoop` 在每一步都 fail-closed:

- 初始化即调用 `scope.require_authorization()`，授权缺失直接失败；
- 每次请求前按序过全部闸门：`scope.check_url()`（在不在范围里）→ 破坏性方法（`DELETE` 直接拒）→ 方法准入（`allowed_methods` 声明过没有）→ body 准入（`allow_request_body`）→ **准入判定**（`core.action_admission`）→ 请求额度 → `scope.delay_seconds` 限速。**默认只读**：授权文档不声明，就只有 GET/HEAD。
- **探测档：默认拒绝，只有能正面证明是读的请求才放行。** `DELETE` 不是合法取值。`OPTIONS` 随时可用。`POST` 只在 URL 里的操作选择器声明了读操作（`?action=query` 等）或 body 是 GraphQL `query` 时放行 —— **空 body 不算证明**。`PUT`/`PATCH` 可以声明但恒被拒（`mutating_request_refused:update_semantics`）。分类器（复用 `guardrails` 的 `action_kind` + `value_scanners`）不可用时 fail-closed：探测档关闭，GET/HEAD 照常。
- **写操作是硬拒，不是警告。** 改状态形状的 URL（`GET /logout`、`GET /api/deleteUser`）对**任何**方法都无条件拒（`state_changing_endpoint`），`?action=sendEmail` 这类操作选择器同样，`?_method=POST` 的旧豁免已删除（那是写声明，不是读证明）。**没有可达的人工门** —— `human_gate` 恒为 `hard_blocked`，所以"需要人判断"在这里等于拒绝。
- **每轮请求数有硬上限**（`core.rate_limit.RequestBudget`，默认 60、硬顶 120，爬虫与 agent 共用）。速率盖"多快"，它盖"多少"。
- 每次出站落 `http-actions.jsonl`（run 目录内，含请求体全文与响应指纹，带 `kind`/`decision`）—— 三个出口都覆盖：intent 首取、`http_actions` 循环、控制台 `fetch_url`。黑板与时间线只留指纹。被拦下来的尝试同样记录。
- Explorer 只允许报告可追溯到响应内容的发现,防止幻觉；
- 任意异常收敛为 `dead_end`,绝不静默成功；
- C 阶段 intent 带 `requires_human_review=True`,写操作/爆破/凭据复用/跨租户访问不会自动执行。

Console 的“SRC 挖掘”主视图即通过 `/api/v1/src-agent/{sessions,history,chat,progress}` 驱动同一套循环,并把会话历史持久化到磁盘,重启不丢。

## 自动挖洞策略

ZIP 中的材料提供的是方法论，不是可直接执行的命令。当前 agent 采用以下安全闭环：

1. 资产种子 → 同 host 的 HTML/JS/API/OpenAPI/GraphQL 候选；不做无边界搜索。
2. 每个候选按未授权访问、对象归属、认证、注入、SSRF、XSS、上传和业务逻辑矩阵排队；先读后写。
3. 每个假设保留正常基线、最小探针、响应差异和复现条件；只有证据闭环才进入人工复核。
4. 写操作、删除、更新、爆破、凭据复用、跨租户访问和 PoC 利用永远不由 autopilot 自动执行；自有对象的可逆验证也必须通过 TargetCard 和 guardrail。
5. 已知 CVE/PoC 只用于生成“待人工确认”的窄候选，不能因为版本字符串或 200/403 就自动判定漏洞。

这样可以长时间运行候选收集和分诊，但不会把外部 skill 中的 RCE、外带、全量扫描或破坏性 payload 直接交给模型。
