# SignalHarbor 信号舱

`run-news.ps1` 是与 SRC 控制面分离的公开资讯 worker。它调用独立的 `news` 管道，使用 `sources.news.example.json` 和有界的 `news-data` 状态目录，内容包括 AI/开发者、财经金融和市场资讯。只请求白名单里的公开 RSS/Atom，不打开文章链接，不读取 SRC 报告。

```powershell
.\run-news.ps1 -Mode run
.\run-news.ps1 -Mode watch -IntervalSec 1800 -MaxConsecutiveErrors 0
```

`run` 和 `collect` 都是单轮，`watch` 每轮完成后等待指定时间。默认每轮最多 20 个来源、每源 20 条、5 条摘要和 3 条飞书消息，缓存保留最近 1000 条。`-NoAi` 明确禁止调用模型；没有 API key 时自动保留来源摘要。

配置 DeepSeek 后，每轮会自动摘要待处理条目。只发送公开标题和已有摘要，不发送 SRC 报告、凭据、cookie、原始响应或证据：

```powershell
$env:DEEPSEEK_API_KEY = '<your-key>'
.\run-news.ps1 -Mode run
```

DeepSeek 单条失败保留资讯并在后续轮次重试，不会使采集失败。可查看 `news-data/last-run.json` 的 `summary_errors`、`degraded` 和各来源状态。

飞书是可选的单向消息：配置官方 `FEISHU_WEBHOOK` 和可选 `FEISHU_SECRET`，再加 `-Feishu`。不启用入站控制，不测试任何 SRC 目标。为避免泄漏，消息仅含标题、摘要、来源和公开文章链接；请为信号舱建立独立机器人，不使用 SRC 报告通知群。

VPS 使用 [systemd 定时运行手册](../deploy/lode-runbook.md)，无需启动 Console 或开放新端口。底层等价命令是：

```bash
python -m news run --registry sources.news.example.json --state-dir news-data --allow-missing-ai
```
