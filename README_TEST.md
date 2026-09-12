# pentest-agent SRC + 公开安全情报测试包

这个包分成两条明确链路：

明天继续开发时先看 [`PROGRESS.md`](./PROGRESS.md)，里面记录已修复项、验证结果、已知限制和下一步测试顺序。

1. `src_surface.py` 属于 pentest-agent，只对一份明确授权 scope 内的单个目标做顺序、低频 GET，提取 HTML/JS 路由、API、OpenAPI/Swagger、GraphQL、manifest 和 source map 候选。
2. `src_autopilot.py` 在上述 surface 结果之上做有限轮次的候选分诊，并通过本地 Blackboard 为多个授权 runner 提供 claim/heartbeat/finish 租约；使用说明见 [`docs/src-autopilot.md`](./docs/src-autopilot.md)。
3. `python -m intel` 是公开“资讯雷达”收集层（代码模块名保留 `intel`），采集安全漏洞/CVE/PoC、AI/开发者动态、财经金融市场 RSS/Atom 和可选官方 X/Twitter。它不会请求目标站点做路由提取，也不会自动启动扫描器。

两条链路的输出都只是候选，不是漏洞结论。只有已经确认的 TargetCard、`target_id` 和 card digest 才能进入 pentest-agent 的后续 runner。

## 0. 环境

- Python 3.10+；情报与 surface 核心只使用标准库。
- Console 运行时直接使用已经构建好的 `console/dist`，不需要 `node_modules`。
- 精简运行包不含 `node_modules`；完整离线开发包包含一份经过重新安装和验证的依赖树，可离线执行 `npm run test/build`。
- `console/node_modules` 仅用于开发测试（本机约 416 MB），不会被运行时加载或打入精简产物。
- 可设置 `PA_PYTHON` 为 Python 可执行文件；否则脚本会探测可用的 Python 3.10+ 解释器。

启动本机 Console：

```powershell
$env:WEBUI_ADMIN_PASSWORD = '<至少12位本机密码>'
$env:WEBUI_SESSION_SECRET = '<至少32位随机会话密钥>'
.\run-console.ps1 -StateDir .\lode-state -Port 8088
```

浏览器访问 `http://127.0.0.1:8088`。服务固定绑定 loopback，完整本机报告可以在登录后的 Console 中读取；报告和证据不会因此进入飞书外发通道。

## 1. 先跑离线情报回放

```powershell
Set-Location <解压目录>\pentest-agent
.\run-intel.ps1 -Mode collect `
  -Scope .\tests\fixtures\intel\scope.json `
  -OutDir .\test-output\intel-offline `
  -InputFile .\tests\fixtures\intel\candidates.json `
  -NoNetwork
```

长期 worker 的两轮离线验证：

```powershell
.\run-intel.ps1 -Mode watch `
  -Scope .\tests\fixtures\intel\scope.json `
  -OutDir .\test-output\intel-watch `
  -InputFile .\tests\fixtures\intel\candidates.json `
  -NoNetwork -IntervalSec 1 -MaxRuns 2 -FeishuDryRun
```

检查 `test-output\intel-watch\watch-state.json`，应为 `completed` 且 `runs_completed` 为 `2`。

## 2. 配置真实公开情报源

想直接启用安全、AI/开发者和财经市场示例源，可使用资讯雷达包装器：

```powershell
.\run-radar.ps1 -Mode watch `
  -Scope .\scope.json `
  -OutDir .\radar-data `
  -IntervalSec 900
```

安全平台默认注册表是 `sources.security.example.json`，只包含 CVE/漏洞披露/PoC/研究源。AI/开发者和财经市场使用独立的 `run-news.ps1` 与 `sources.news.example.json`；可选用 `python -m news summarize` 调用 DeepSeek 处理公开摘要。每个 provider 单独隔离失败，源只读抓取公开 RSS/Atom，不访问目标站点。

将 `sources.example.json` 复制为一个独立状态目录中的 `sources.json`，然后运行：

```powershell
.\run-intel.ps1 -Mode watch `
  -Scope .\scope.json `
  -Registry .\intel-state\sources.json `
  -OutDir .\intel-data `
  -IntervalSec 900
```

内置 CISA KEV 默认启用；示例还包括 Project Zero、GitHub Security Lab、PortSwigger Research 和 Nuclei templates release Atom。每个 provider 独立报错，单个源失败不会卡住 watcher；连续全源失败达到阈值才停止。

X/Twitter 来源默认关闭。先设置官方 API token，再在 Console 或 `sources.json` 中启用：

```powershell
$env:X_BEARER_TOKEN = '<official-api-token>'
```

token 只从 `X_BEARER_TOKEN` 或 `TWITTER_BEARER_TOKEN` 读取，不写入配置或输出。

## 3. 飞书摘要

```powershell
$env:FEISHU_WEBHOOK = '<bot-webhook>'
$env:FEISHU_SECRET = '<optional-signing-secret>'
.\run-intel.ps1 -Mode watch -Scope .\scope.json -OutDir .\intel-data -IntervalSec 900 -Feishu
```

RSS/Atom 的 `title/description/summary/published` 和 X 帖子正文会先被提取、截断，再组成飞书摘要。默认不二次抓取文章全文，不调用 LLM，不发送请求响应、cookie、token、凭据或敏感证据。`-FeishuDryRun` 只打印 payload，不联网发送。情报摘要不能直接触发扫描；飞书入站审批仍受白名单和人工门控制。

pentest-agent 的完整报告、skill 输出、原始请求响应和证据文件只保存在本机 Console/工作区。飞书只发送目标主机、任务状态、风险计数和高层漏洞类型；所有文本、回复、卡片和 webhook payload 在传输层再次脱敏，广播审计只记录内容哈希和字节数。

### pentest-agent 双向 Bot

独立情报摘要使用上面的 `FEISHU_WEBHOOK`；pentest-agent 的 `status/pause/resume/approve/reject` 和 `/goal` 则由 `notify/feishu_reply_consumer.py` 处理，两者不是同一条链路。飞书应用需订阅 `im.message.receive_v1`，并开通接收消息、回复消息和添加表情回复所需权限。

飞书入口不会直接对测试目标发起请求：单向播报只发送脱敏状态消息；双向 Bot 也只把白名单用户的封闭指令追加到本地命令队列。`/goal` 必须经过 intake、策略选择、TargetCard 和人工确认，真正执行仍由外部 runner 与 guardrails 负责；缺少 runner 或物理 egress 确认时 fail-closed。

WebSocket 长连接模式不需要公网回调地址，但需额外安装 `lark-oapi`：

```powershell
$env:FEISHU_APP_ID = 'cli_xxx'
$env:FEISHU_APP_SECRET = '<app-secret>'
$env:FEISHU_TRUSTED_USERS = 'ou_xxx,ou_yyy'
python .\notify\feishu_reply_consumer.py --mode ws --command-file .\runtime\notify_commands.jsonl
```

HTTP webhook 模式还必须配置与飞书后台一致的 verification token。服务只允许绑定 loopback，应通过你自己的 HTTPS 反向代理暴露回调地址：

```powershell
$env:FEISHU_APP_ID = 'cli_xxx'
$env:FEISHU_APP_SECRET = '<app-secret>'
$env:FEISHU_TRUSTED_USERS = 'ou_xxx,ou_yyy'
$env:FEISHU_VERIFICATION_TOKEN = '<verification-token>'
python .\notify\feishu_reply_consumer.py --mode webhook --listen 127.0.0.1:9876 `
  --command-file .\runtime\notify_commands.jsonl
```

webhook 的 HTTP 响应仅用于确认事件收到，不会自动出现在聊天里；本工具会另行调用飞书官方消息回复 API。无效 token、缺少 `message_id/chat_id/user_id`、非文本事件和不在白名单内的用户都不会触发指令。`FEISHU_APP_ID`、`FEISHU_APP_SECRET` 和 `FEISHU_TRUSTED_USERS` 在两种模式下都必填。

## 4. 授权 SRC surface

先把 `scope.example.json` 另存为 `scope.json`，填写真实书面授权说明和精确 scope。默认示例留空，因此会 fail-closed。

```powershell
.\run-surface.ps1 `
  -Scope .\scope.json `
  -Target https://authorized.example `
  -OutDir .\surface-data
```

该命令不会提交表单、修改状态、爆破或调用 LLM/利用器。请求不跟随重定向，每次请求前重新检查 scope，默认串行且至少间隔 0.4 秒。

## 5. 回归测试

```powershell
python -m pytest -q

Set-Location .\console
npm install
npm run test
npm run build
```

2026-09-06 交付验证结果：Python 全仓 `206 passed, 10 skipped`；Console `25 passed`；生产构建通过。跳过项是未随附件提供的私有 `ai-pentest-matrix` 证据/执行契约和平台可选测试，不是静默失败。

`skills/ai-pentest-matrix/scripts` 不在当前工作区或附件中，完整主动渗透仍需要外部 Strix runner 和这套私有 guardrail/evidence 依赖。缺失时系统按设计 fail-closed；精简包与完整离线包都不会伪造或替代私有 skill，也不会把其中的报告内容发送到飞书。

## 6. 历史 ZIP 说明

之前的 v4 ZIP 仍是历史交付物；本轮源码和 `console/dist` 已直接验证，不再生成新的 ZIP。

- `runtime-slim`：包含 Python 源码、测试、Console `dist` 和配置示例，不含 `node_modules`。运行已构建 Console、情报 worker 和 surface 提取时用这个。
- `offline-webdev`：在精简包基础上包含用 `package-lock.json` 全新安装并验证的 Console 开发依赖，可断网执行 `npm run test` 和 `npm run build`。

本地原 `console/node_modules` 是 npm 与 pnpm 混装后的依赖树，约 416.56 MiB / 57,431 文件，其中 `.pnpm`、`.ignored` 和顶层 hoisted 包存在大量重复；`.vite` 与 `.vite-temp` 是缓存。它们不是全部无用，但不适合原样打包。
