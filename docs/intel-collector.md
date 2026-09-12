# 公开安全情报收集层（Intel）

`intel` 是与 Strix、LLM、飞书和 Console 解耦的公开资讯收集引擎（代码模块名保留 Intel）。SRC 安全平台默认只使用安全源；AI/开发者和财经金融市场使用独立的 `run-news.ps1`/`sources.news.example.json`，可选通过 `python -m news summarize` 调用 DeepSeek 处理公开摘要。所有源只读公开 RSS/Atom/API，不负责目标站点路由提取或主动扫描：

- 读取一份明确授权的 scope 或已经确认的 `TargetCard/v1`；
- 从 scope seed、crt.sh、CISA KEV、RSS/Atom、page-watch、官方 X/Twitter API 和离线 JSON/JSONL/CSV 导入候选；
- 在落盘前做 host/URL/IP scope 过滤；
- 合并多来源重复项，按“新资产、敏感功能 hint、多源确认、证书观察”排序；
- 保存可回放的 `run.json`、`candidates.jsonl` 和 `history.json`。

它不会对目标站点做 HTML/JS 路由提取，不会自动利用漏洞、爆破、修改业务状态或访问真实用户数据。候选仍然只是待人工确认的情报/资产线索，不是漏洞结论。

SRC 目标的 HTML/JS、路由、OpenAPI/Swagger、GraphQL、manifest 和 source map 提取属于
`pentest-agent` 侧的 `src_surface.py`，因为它会对明确授权目标发起低频 GET；两条链路不会共享 provider 或默认配置。

## 第一次运行

使用 AegisPilot 的 scope 文件时，至少填写 `authorization`、`allowed_domains` 或 `allowed_hosts`，以及 `seed_urls`：

```powershell
$py = 'C:\Users\Z3n1th\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
& $py -m intel collect `
  --scope E:\path\to\scope.json `
  --out-dir E:\path\to\intel-data
```

### 本机离线演示

如果本机的代理/TUN 将公网 DNS 映射到 `198.18.0.0/15`，网络层会按设计拒绝这些地址；不要通过放宽私网校验来绕过。可以先用内置演示候选验证分类、排序、持久化和飞书 dry-run：

```powershell
.\run-radar.ps1 -Mode collect -NoNetwork `
  -Scope .\tests\fixtures\intel\scope.json `
  -OutDir .\runtime-smoke\radar-demo `
  -InputFile .\tests\fixtures\intel\radar-demo.json
```

该演示包含安全/CVE、AI/开发者和财经/市场三类公开条目，不会发出任何网络请求。网络恢复后，去掉 `-NoNetwork` 和 `-InputFile` 即可抓取注册表中的真实 RSS/Atom；单源失败会在 `run.json` 中隔离记录。

输出目录按 run 隔离。重点查看：

- `runs/<run_id>/candidates.jsonl`：按 score 排序的 in-scope 候选，保留完整结构；
- `runs/<run_id>/candidates.csv`：同一批候选的 Excel/脚本友好导出；
- `runs/<run_id>/run.json`：各 provider 的 `ok/error`、越界数量、重复合并数量；
- `history.json`：只保存候选 key，用于下一轮标记 `is_new`。

离线回放或没有网络时：

```powershell
& $py -m intel collect --no-network `
  --scope .\scope.json --out-dir .\intel-data `
  --file .\fixtures\assets.jsonl
```

## 长时间轮询

需要持续观察证书和公开 feed 时使用 `watch`。它每轮重新读取启用的数据源，单实例运行，状态写入 `watch-state.json`；Ctrl+C 或服务停止信号会优雅退出。默认连续 5 轮全源失败后停止，单个来源失败不会影响其他来源。

```powershell
& $py -m intel watch `
  --scope E:\path\to\scope.json `
  --out-dir E:\path\to\intel-data `
  --registry E:\path\to\pentest-state `
  --interval-sec 900
```

测试或回放时限制轮数，避免忘记停止：

```powershell
& $py -m intel watch --no-network `
  --scope .\scope.json --out-dir .\intel-data `
  --file .\fixtures\assets.jsonl --interval-sec 1 --max-runs 3
```

`watch-state.json` 会记录 `running/completed/stopped/failed`、最后一轮、连续失败次数和错误。上次进程中断后再次启动会记录 `recovered_previous=true`。它仍然只是公开情报 worker；不会自动调用 Strix、LLM、爆破器或主动漏洞利用器。

## 飞书摘要

使用 `watch --feishu` 时，采集完成后只筛选新增且达到阈值的候选，发送标题、URL/标识、score、来源和标签摘要。它不发送文章全文、请求响应、凭据、cookie、token 或敏感证据；默认还会经过已有节流器。`--feishu-dry-run` 只打印将要发送的 payload，不发网络请求。

环境变量仍由现有通知适配器读取：`FEISHU_WEBHOOK` 和可选的 `FEISHU_SECRET`。飞书入站 bot 的白名单、人工门和任务审批继续由 `notify/feishu_reply_consumer.py` 负责，情报 watcher 的摘要消息不能直接触发扫描。

Twitter/X provider 只使用官方 recent-search API，token 只从 `X_BEARER_TOKEN` 或 `TWITTER_BEARER_TOKEN` 读取，不写入 `sources.json`。来源在 Console 中默认关闭，填写 query、设置环境变量并人工启用后才会采集。

## 数据源注册表

Console 的“资讯雷达数据源”接口现在写入 `<state_dir>\sources.json`。默认有两个 builtin：`seed` 和 `crtsh`。Console 新增的 `rss`/`page_watch` 默认不可信，URL 只能是公网 HTTP(S)，网络层还会重新解析并拒绝 loopback、私网、保留地址和本地域名。

注册表只管理来源和启停，不在 Console 请求线程里抓取网络。采集 CLI 传入 `--registry <state_dir>\sources.json` 或 state 目录即可加载启用来源；来源失败会记录为 provider error，不影响其他来源和 scope 过滤。

## 从候选继续挖

按 score 从上到下，一次只选一个候选进入后续人工确认或已验收 runner：

1. 先看 `is_new=true` 且有 `api/auth/admin/upload/export/payment` 等 hint 的资产。
2. 用低频、只读方式确认状态码、标题、技术栈和公开 API 面。
3. 对登录后功能使用两个自有测试账号做对象/租户边界对照。
4. 每个假设保留正常基线、负向对照、原始请求/响应和影响说明；未满足这些条件只保留为 hypothesis。

不要把新子域名直接交给任意主动扫描器，也不要因为 401/403、关键字或错误页面就自动判定高危。只有明确授权并通过 `pentest-agent` intake、TargetCard digest 和 runner 护栏的任务，才能进入后续主动验证。
