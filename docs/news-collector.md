# Pulse

`run-news.ps1` 是与 SRC 控制面分离的公开安全情报 worker。它调用独立的 `news` 管道，使用 `sources.news.example.json` 和有界的状态目录，重点覆盖漏洞/CVE、厂商公告、威胁研究、AI 安全、云和开源供应链安全。只请求白名单里的公开 RSS/Atom 或 CISA KEV JSON，不打开文章链接，不读取 SRC 报告。两小时简报经飞书发送。

```powershell
.\run-news.ps1 -Mode run
.\run-news.ps1 -Mode watch -IntervalSec 1800 -MaxConsecutiveErrors 0
```

`run` 和 `collect` 都是单轮，`watch` 每轮完成后等待指定时间，默认持续重试。Pulse 的 `digest` 每两小时收集一次新内容，按 AI、金融/宏观、国际局势分类，并优先发送政策、央行、战争/制裁、重大模型或公司动作等高价值条目。没有翻译 Key 时保留英文原文并明确标注；配置 DeepSeek 后一次批量翻译本轮条目，生成中英双语简报。

## 配置与推送

独立配置放在项目根目录 `.env.news.local`（已被 Git 忽略），不读取 SRC 的 `.env`。也可用 `-EnvFile` 指定路径。只接受 Pulse 相关变量，已有进程环境变量优先，不执行文件里的命令。

```dotenv
FEISHU_WEBHOOK=
FEISHU_SECRET=
DISCORD_WEBHOOK=
DEEPSEEK_API_KEY=
DEEPSEEK_MODEL=deepseek-flash
```

飞书 Webhook 从群聊自定义机器人的设置中复制；启用了签名时也填写 `FEISHU_SECRET`。配置凭据本身不会开启推送，还需选择开关：

```powershell
.\run-news.ps1 -Mode run -Feishu
.\run-news.ps1 -Mode run -Discord
.\run-news.ps1 -Mode run -Feishu -Discord
# 读取真实公开源，预览消息；不调用 AI、不发送、不改变投递状态。
.\run-news.ps1 -Mode run -Feishu -DryRun
```

当前安全简报使用 `python -m news digest`，按漏洞、威胁、AI 安全、云与供应链内容排序；一般宏观/国际新闻已从 VPS 来源中移除。CISA KEV 以结构化 JSON 导入，并限制为合法 CVE 编号。

两小时简报的底层命令是：

```powershell
python -m news digest --registry .\sources.news.example.json --state-dir .\news-data --feishu
```

配置 `DEEPSEEK_API_KEY` 后，Pulse 会批量翻译本轮最多 20 条；不调用模型时不会消耗 Token。翻译失败只影响中文字段，英文原文和飞书投递仍继续。

X 使用官方 Recent Search API，仅查询有限的安全机构/研究账号及漏洞关键词。创建 X Developer Project 后，把 Bearer Token 放入 VPS `/etc/pulse/pulse.env` 的 `X_BEARER_TOKEN`；不需要发到聊天。没有 Token 时 X 来源会安全跳过，其余情报照常推送。API 是否可用取决于 X 账号当前套餐和额度；不抓取网页、不使用非官方镜像。

两边各自记录成功状态，失败和超额消息下一轮继续处理，成功后不重复发送。旧版本的 `delivered` 仅迁移为飞书已发送。Discord 消息禁止 `@everyone`、角色和用户提醒。若远端已接收但响应在途中丢失，Webhook 无幂等保证，重试仍可能出现重复。

## 自动运行

Windows 登录期间每 30 分钟执行一次，可用：

```powershell
# 不带通道开关时只采集；填好凭据后重新执行加上 -Feishu 或 -Discord。
.\deploy\register-news-task.ps1
.\deploy\register-news-task.ps1 -Feishu
Get-ScheduledTaskInfo -TaskName 'Pulse'
```

任务使用当前用户的普通权限、隐藏窗口和无 profile 的 PowerShell，禁止重叠运行。电脑关机或用户注销期间不会运行，重新登录后补跑。状态文件 `news-data/last-run.json` 包含来源成功/失败、缓存数、每个通道的发送数、待发数和错误；文件不会包含 Webhook。

Clash TUN 的 `198.18.0.0/15` Fake-IP 会自动通过固定的阿里/腾讯 HTTPS DNS 端点获取真实公网 IP。连接固定到检查过的地址并保留原域名 TLS 验证；每次重定向重新检查，不会直接放行虚拟地址、私网或本机地址。无需设置 `HTTP_PROXY` / `HTTPS_PROXY`，也不需要修改系统 DNS。

配置 DeepSeek 后，每轮会自动摘要待处理条目。只发送公开标题和已有摘要，不发送 SRC 报告、凭据、cookie、原始响应或证据：

```powershell
$env:DEEPSEEK_API_KEY = '<your-key>'
.\run-news.ps1 -Mode run
```

DeepSeek 单条失败保留资讯并在后续轮次重试，不会使采集失败。可查看 `news-data/last-run.json` 的 `summary_errors`、`degraded` 和各来源状态。

推送按漏洞/厂商公告、威胁事件、AI 安全、云与供应链、研究分段；条目间用分隔线，标注 HIGH 优先级，双语原题和摘要相邻显示。仅含公开标题、摘要、来源和文章链接；不发送 SRC 报告、凭据、cookie、原始响应或证据。

VPS 使用 [systemd 定时运行手册](../deploy/lode-runbook.md)，无需启动 Console 或开放新端口。底层等价命令是：

```bash
python -m news digest --registry sources.news.example.json --state-dir news-data --feishu
```
