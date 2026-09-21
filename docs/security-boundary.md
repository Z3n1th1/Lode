# 安全边界与上线验收

当前状态：本地代码和测试已更新，没有连接或加固任何 VPS。本文是部署要求，不是已完成部署的证明。

## 两类风险分开控制

对 SRC 目标：只运行明确书面授权范围内的任务。自动 surface 只发低频 GET，不提交表单，不执行文章、ZIP 或 PoC 中的代码。请求前检查 host 范围、禁止项、URL 凭据、方法准入和语义写操作；重定向不跟随。GET 语义拦截是额外防线，不能证明未知业务接口无副作用。只在运营方允许的资产、测试账号和已审核的读取入口开始。

对执行平台：目标返回的 HTML、JS、XML、文章和模型输出均是不可信数据。抓到的脚本仅按文本解析，不执行、不安装依赖。资讯模型没有工具，只接收有界的公开标题及摘要。不要为追求自动化开启 always-approve、任意 shell、运行未锁定的 npx 包或挂载 Docker socket。

## 当前已实现

- Surface 每次抓取前重新检查 scope，并拒绝删除、更新、退出、支付、发送等明显有副作用的 URL，以及未知 operation selector。候选 API 路径不会因为被提取到就自动被访问。
- **默认只读，能力由授权文档显式声明**。`SurfaceScope.allowed_methods`（默认 `GET`/`HEAD`，恒并集：声明什么都拿不掉这两个）与 `allow_request_body` 是唯一的能力来源；模型提示词里的能力行由同一份 scope 生成，**而且只广告闸门真会发的方法**，不是硬编码。空/缺失/非法的声明等于只读，所以这个字段出现之前写的 scope 文件行为不变。
- **探测档：默认拒绝，只有能正面证明是读的请求才放行**。方法本身区分不了读写 —— `POST /search` 能揭示路由，`POST /logout` 和 `POST /api/items` 连 body 都不需要就能改状态。所以：
  - `DELETE` **不是合法取值**（不在 `_METHOD_VOCABULARY` 里），实发即 `destructive_method_forbidden`。
  - `OPTIONS` 随时可用（RFC 安全、无 body），也是找路由的最好手段（响应带 `Allow:`）。
  - `POST` 只在两种情况放行：URL 里的操作选择器声明了一个**读**操作（`?action=query` 等，见 `_READ_SELECTOR_VALUES`），或 body 是一个 GraphQL `query`（键集 ⊆ `{query, operationName, variables}`，且不含 `mutation`/`subscription`）。**空 body 不是证明** —— `POST /logout` 就没有 body。其余一律 `probe_not_proven_non_mutating`。
  - `PUT`/`PATCH` 可以声明（好让拒绝理由叫 `mutating_request_refused:update_semantics` 而不是 `method_not_allowed`），但语义上就是"改"，**恒被拒**。
- **写操作是硬拒，不是警告**。「URL 里出现某个改状态词」是启发式而不是证据（`DropDownOptions` 会因驼峰切词命中 update），所以它以前只在文档没有声明写方法时硬拦、声明之后降级成警告 —— 那条降级路径**已删除**：`GET /logout`、`GET /api/deleteUser` 说的是这个操作**做什么**，不是哪个动词载着它。现在 `state_changing_endpoint` 对**任何**方法都无条件拒绝，`unknown_operation_selector` 同样（`?_method=POST` 的旧豁免也没了：它是写声明，不是读证明）。
- **没有可达的人工门**。`guardrails.guardrails.human_gate` 在没有独立审批权威时恒返回 `hard_blocked:approval_authority_unconfigured`，所以本地没有任何路径能把"需要人判断"变成"放行"。在猎手这条路里，**需要人判断 = 拒绝**，审计里写明这一点。真正的分类由 `core.action_admission` 做，它复用 `guardrails` 的 `action_kind` + `value_scanners`（此前是死代码，`agents/` 从未 import），策略比 `refine` 更严：create/modify/delete 一律拒。分类器不可用时 **fail-closed**：探测档关闭，GET/HEAD 照常。
- **每轮请求数有硬上限**。速率桶只管"多快"，管不了"多少" —— 在此之前单目标只受速率约束（20 圈 × 3 次探索 + 3 个动作 × 2 轮 ≈ 420 个请求，`JobContext.spend_request` 存在但零调用者）。现在 `core.rate_limit.RequestBudget` 默认 60、硬顶 120，**爬虫和 agent 共用同一笔**，计数点在准入之后、限速之前（治理拒绝不消耗额度，额度用完立刻返回）。
- 每次出站都写 `http-actions.jsonl`（run 目录内，请求体全文 + 响应指纹，带 `kind` 与 `decision`）。三个出口都覆盖：intent 首取、`http_actions` 循环、控制台的 `fetch_url`。黑板与事件流只留指纹（`sha256[:12]` + 长度 + content-type）。**被拦下来的尝试也记录** —— "它想过但没发出去"同样是审计事实。
- 动作策略重新检查语义操作。上层把 GET 判为 allow，也不能覆盖下层识别出的写动作。创建、修改、删除与危险信号（服务端外联、凭据、不可逆cleanup、共享状态）一律被拒。
- `gateway_request` 在执行内核缺失或物理出站未确认时不进行 live execution。
- Blackboard 提供跨进程 claim、heartbeat、过期回收和状态原子写；它协调任务，不负责约束外部 runner 的实际网络权限。
- SignalHarbor 限制来源数、响应大小、XML DTD、缓存条数、摘要数和消息数。逐源、逐条隔离失败。飞书为可选单向通知，不启动 SRC 测试。

## 防止 VPS 被攻陷后扩大损失

推荐把主控与执行 worker 放在不同的 VM。较低预算可先仅部署 SignalHarbor；不要在资讯服务上同时运行主动 SRC runner。

| 区域 | 放什么 | 不放什么 |
| --- | --- | --- |
| 本地或管理 VM | Console、授权配置、私有方法库、完整报告、审批服务 | 公网可访问的管理端口 |
| SRC 执行 VM | 最小 worker、短期任务、脱敏结果、专用测试凭据 | Git 工作树、私有 skill、审批签名私钥、管理云账号、长期 SSH 密钥 |
| 独立资讯 worker | RSS registry、新闻缓存、限额模型 key、独立飞书 webhook | SRC 报告、目标 cookie、SRC 任务队列 |

只读挂载防修改，不防读取。Python 进程被攻陷后，其可读代码可能泄漏；混淆、打包或改写成 Go 都不能保证保密。要保护源码，必须让执行 VM 根本拿不到敏感源码和方法库。只读镜像也不能防具有宿主机 root 权限的攻击者。

VPS 运行用户不授予 sudo、不加入 docker 组。代码/依赖由 root 拥有且只读，状态目录单独可写。使用及时更新的 OS、Python 和固定依赖版本；不允许 worker 自更新代码。服务设置资源上限、任务超时和有界日志。管理入口仅走 SSH 隧道或管理 VPN，避免公开 Console、审批接口和数据库。

执行 VM 的出站由独立管理层默认拒绝，只允许到受控请求网关。网关在每次请求及重定向处强制授权 host/IP、方法、路径、速率和响应大小，禁止云 metadata、内部管理网段和回连地址。支持 HTTPS 时需要真正能检查 HTTP 语义的受控方案；普通 IP 防火墙看不到加密后的方法或路径。不要把 `GUARDRAILS_PHYSICAL_EGRESS_CONFIRMED=1` 当成隔离实现，该变量本身不会创建 netns、防火墙或代理。

即使出口白名单正确，已被攻陷的 worker 仍可能通过允许访问的站点外传其可读数据。因此还必须最小化挂载、权限和凭据，并分离审批私钥；不能只依赖出口过滤。

## 上线前必须实机验收

1. 使用自有测试服务验证写方法、语义写 GET、越界跳转及方法覆盖全部在发送前被拦截；确认 target 侧确实没有收到请求。
2. 在 worker 内尝试不经过网关直接连接测试地址，必须被内核/网络层拒绝。由独立管理进程观察日志，不接受 worker 自报通过。
3. 验证 worker 不能读取主控源码、报告、审批签名私钥、云凭据或宿主机目录，不能修改代码、安装包或获得额外权限。
4. 用合成任务跑 24 小时 soak：断网、超时、进程异常、重复任务、租约过期和磁盘接近限额。核对资源曲线、任务重复执行和人工停止是否有效。
5. 只用测试账号小范围灰度，人工核对请求审计与业务数据；任何越界、未知副作用或预算耗尽立即停止，不自动扩大范围。

目前没有上述 VPS 实机结果，也没有完整外部 runner 端到端验收。现阶段可长期运行资讯定时采集与 SRC 候选协调，不能宣称已经具备无人值守、零副作用的自动漏洞验证能力。
