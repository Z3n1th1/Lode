# SurfaceForge / SignalHarbor 当前进度

## 2026-09-06 最新续作

- 用户可见名称：SurfaceForge（猎面台，SRC 控制面）与 SignalHarbor（信号舱，独立资讯）；内部目录名保持兼容。
- SignalHarbor 已使用独立 `news run` 管道；systemd 改为 oneshot + timer，避免不匹配的 watchdog。每轮资源、采集、摘要和消息均有上限，单条摘要失败降级。
- RSS 解析拒绝 DTD/实体并保留合法 CDATA，包含 UTF-16 回归；状态和锁文件拒绝符号链接。
- Surface 入口增加有副作用 GET 和未知 operation selector 拦截；guardrails 修复 base allow 覆盖语义写操作检查的问题。
- 本轮验证：Python `232 passed, 11 skipped`；WebUI `25 passed`；类型检查及 production build 通过。构建仍提示一个大于 500 kB 的 chunk，FastAPI 测试有上游弃用警告。
- 尚未登录/加固 VPS，未做真实 DeepSeek/飞书验收，未接通完整外部 SRC runner。物理出站变量不是防火墙；部署和源码保密边界见 `docs/security-boundary.md`。

以下保留历史进度，若数字或默认入口与上面冲突，以最新续作为准。

更新时间：2026-09-06

这份文件是下一次继续开发时的接续点。当前以源码和已构建 WebUI 为准；本轮不重新打 ZIP。

## 当前状态

| 模块 | 状态 | 说明 |
|---|---|---|
| 独立公开情报层 | 可离线回放，待真实源持续验证 | RSS/Atom、CISA KEV、漏洞披露、研究文章、PoC release、可选 X/Twitter；不做目标站点路由提取 |
| SRC surface | 可运行，授权缺失时拒绝 | 只做 scope 内低频 GET 和候选提取，不提交表单、不爆破、不自动判定漏洞 |
| pentest-agent 控制面 | 可用但依赖外部 runner | TargetCard、scope、guardrail、人工门和 fail-closed 已保留；缺 Strix/private skill 时不会伪造成功 |
| 飞书出站 | 已接入脱敏和分类路由 | 只发送状态、目标主机、风险计数和高层类型 |
| 飞书双向 Bot | 代码链路已修复，待真实租户验收 | WebSocket 和 loopback webhook 都支持；webhook 通过官方 reply API 回消息 |
| WebUI | 本机可用 | loopback + 登录；登录后可查看完整本机报告，报告不进飞书 |
| SRC 黑板/长跑协调 | 可用 | facts/intents/dead_ends/hints/claims；跨进程锁、原子写、heartbeat lease、过期回收 |

## 本轮已修复

### 飞书 Bot

- `url_verification` 先校验 verification token，再返回 challenge。
- `make_webhook_handler()` 没有 token 配置时直接 `503`，错误 token 或缺失 token 返回 `403`。
- webhook 不再误以为 HTTP callback body 会出现在聊天里，而是调用官方消息 reply API。
- WS/webhook 两种模式都强制要求 `FEISHU_APP_ID` 和 `FEISHU_APP_SECRET`。
- 缺少 `user_id`、`message_id`、`chat_id`、文本内容或事件结构异常时，不进入 dispatcher。
- 非文本消息不触发指令；群聊中的 `<at>机器人</at> status` 会先去掉 mention 标记。
- 保留白名单、封闭指令集、持久化去重和审计；重复消息不会重复执行。

### 路由和保密边界

- 未知通知分类不再回退到 `ops_selfcheck`，避免拼写错误误投群。
- `FeishuRoutes/v1`、路由表、`oc_...` chat_id 启动时严格校验。
- `send_text`、`send_card`、`reply_text`、webhook 回执统一经过外发脱敏。
- 完整报告、skill 输出、原始请求/响应、cookie、token、证据文件只保存在本机。
- 广播审计只保存哈希和字节数，不保存报告正文。

### 验证和交付

- Python 全仓：`211 passed, 11 skipped`。
- 飞书专项：`29 passed`。
- WebUI：`25 passed`。
- WebUI production build：通过。
- v4 runtime ZIP 解压回归：通过，且不含 `node_modules`。
- v4 offline-webdev ZIP 解压回归：通过，包含锁定的离线依赖树。

### 2026-09-06 本轮新增

- `core/src_blackboard.py`：吸收 Cairn/Muteki 的 Blackboard、Fact/Intent/Dead-end、事件 revision、单 worker claim/lease 和 heartbeat；不执行网络、不保存原始证据。
- `agents/src_autopilot.py`：load/merge/save 变为单次状态锁内事务；候选同步为需要人工/授权 runner 的 intent；输出文件原子替换，恢复时不会重复覆盖状态。
- WebUI 增加 `/api/v1/src-autopilot` 和“SRC 自动化”只读面板，可查看轮次、候选优先级、claim 租约、死路与提示。
- 增加 `run-src-autopilot.ps1` 和 [`docs/src-autopilot.md`](docs/src-autopilot.md)，支持首轮授权 surface 分诊和后续 `SrcSurfaceResult/v1` 续跑。
- 新增黑板、并发 autopilot、WebUI 投影回归测试；全量回归现为 `209 passed, 10 skipped`，仍不宣称真实端到端 runner 已验收。
- `run-intel.ps1` 与 `run-webui.ps1` 都会探测 Python 3.10+，不会误选 Windows `py.exe` 占位别名。
- WebUI 本机 smoke：`/healthz` 200、登录 204、dashboard 与 `/api/v1/src-autopilot` 200；单进程工作集约 54 MB。
- 新增 `sources.radar.example.json` 与 `run-radar.ps1`，公开名称统一为“资讯雷达”，覆盖安全、AI/开发者、财经/市场 RSS/Atom。
- `run-radar.ps1` 已补齐单源超时、Feishu 最低分和摘要条数参数，长跑可调且不改变常驻进程模型。
- WebUI 现可直接投影资讯雷达最新 run 的候选；离线演示已写入 smoke state，API 可见安全、AI/开发者、财经/市场 7 条候选。
- WebUI intake 服务端强制 brute-force 全禁用（所有标志 false、次数和频率为 0）；飞书入站限制消息长度、目标 ID 格式和备注长度。
- WebUI 目标校验拒绝 URL 内嵌凭据/非法端口；gateway request budget 限制为 1..100，越界 fail-closed。
- SRC 默认源已切换为纯安全 `sources.security.example.json`；AI/开发者与财经/市场迁移到独立 `run-news.ps1`、`sources.news.example.json` 和 `news` DeepSeek 摘要器。
- WebUI smoke state 已切换为仅安全条目（CVE/研究/seed 共 3 条）；独立 news 输出不进入 SRC 页面。
- `docs/src-autopilot.md` 已补充 ZIP 方法论的安全落地：种子队列、类型矩阵、基线/探针/差分、证据闭环和停止条件；未知 CVE/PoC 只生成待人工确认 intent，不自动利用。
- 静态审查两个外部 skill ZIP：内容逐文件一致的重复副本，无二进制/宏/路径穿越/加密；发现 FOFA 脚本内硬编码凭据和未锁定 `npx` 供应链风险，未导入或执行。
- 资讯雷达真实源 smoke 已执行；当前 Clash TUN DNS 将公网域名映射为 `198.18.0.x`，按安全策略被拒绝并逐源隔离，未绕过校验。

## 当前已知限制

1. 尚未使用真实飞书租户做端到端验收。当前环境没有 `FEISHU_APP_ID`、`FEISHU_APP_SECRET`，没有向真实群发送测试消息。
2. 真实飞书验收还需要确认应用权限、事件订阅 `im.message.receive_v1`、机器人在目标群内，以及 reply/reaction 权限。
3. 完整主动渗透仍依赖外部 Strix runner 和未随附件提供的私有 `ai-pentest-matrix` skill/guardrail/evidence 契约；缺失时按设计阻断。
4. X/Twitter 采集默认关闭，需要官方 API token；真实源还要继续测速率限制、分页、重复项和单源故障恢复。
5. npm audit 没有宣称为 0 漏洞：国内镜像返回 404，官方源测试时出现 `ECONNRESET`，需要网络可用时单独复核。
6. 黑板只负责候选协调；真实 Strix/授权 runner 仍需自行实现 `claim_next → heartbeat → finish` 适配，不会由本项目自动执行利用链。

## 明天建议顺序

### P0：真实飞书小流量验收

1. 只在测试群配置 `FEISHU_APP_ID`、`FEISHU_APP_SECRET`、`FEISHU_TRUSTED_USERS`。
2. 先跑 `status`，再跑 `<at>机器人</at> status`，确认收到官方 reply，而不是只看到 HTTP 200。
3. 用非白名单账号、重复 `message_id`、图片消息和错误 token 验证均不执行。
4. 再测 `pause`、`resume`、`approve <target>`，确认人工门和审计文件落盘。

### P1：情报源和摘要质量

1. 给每个 provider 做真实连通性、超时、分页、去重和连续失败恢复测试。
2. 配置官方 X/Twitter API 后，验证正文截断、链接清洗、时间窗口和不触发扫描。
3. 对飞书摘要做人工抽样：只含标题、来源、时间、公开链接和高层摘要，不含原文证据。

### P1：SRC 自动化闭环

1. 先用书面授权的测试目标生成并确认 TargetCard，再执行 `src_surface.py`。
2. 检查 surface 候选如何进入 TargetQueue，确认 scope、速率、重定向和授权门每一步都仍然生效。
3. 接入可用 runner 后做长时间运行、超时、恢复、重复任务和人工中断测试。
4. 让多个 runner 只通过黑板 claim/lease 消费不同 intent；记录候选数、有效路由数、人工确认数、误报数和单目标耗时，之后再决定是否扩大并发。

## 常用回归命令

```powershell
Set-Location .\pentest-agent
python -m pytest -q
python .\notify\feishu_reply_consumer.py --self-test

Set-Location .\webui
npm run test
npm run build
```

真实 Bot 验收前不要把 app secret、verification token 或真实报告放进配置文件、日志、截图或飞书消息。
