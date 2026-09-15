# 知识库索引

实战方法论 / 测试清单 / 场景矩阵。与 `SKILL.md` 流程配合使用。

## 在本产品里怎么被读到

**由工具按需拉取，不进 system prompt。** `pentest` 模式带 `read_knowledge(name)` 工具，
模型认出面相时用卡片名（不带 `.md`，如 `read_knowledge("idor-test")`）拉一篇。
实现见 `agents/src_chat.py::_exec_read_knowledge`，单次上限 12 000 字符、超出显式截断。

所以这里**可以无限长**：长的那部分只在被点名时才进上下文。前提是上面那份文件清单
说得准 —— 清单是模型的可见面，写错就等于把人指向一个不存在的门。

（`~/.grok/rules/...` 那几行是另一个 harness 的约定，在本产品里不生效，只当历史注释看。）

## 使用约定

- 进站先读 `打穿短表.md`；对得上再打开对应模块看细节。文件不长就整篇开；超长篇可先开点名节，不够就继续开。禁止每站通读本目录
- 磁盘有 `*src经验.md` 才开专篇，没有不算缺。开 `SKILL.md` 不会再带集团日记
- 短表和「注入/SSRF/XSS/RCE」都不是上限。本站过全类型矩阵；四件套打在有差分面上（防空窗），不是只测这四类，也不是每个 path 喷 `'`。有会话时越权/逻辑与四件套同硬（`dig-scope` §4.2.3）
- 方便和能力优先；省 token 是顺带，不挡开模块
- 短表点名的手法用标题搜。有指针的肥篇只留实战中文 + 指针段；禁开/几乎不交的篇已收成一行。手法行不删、算成不改矮。
- 篇内跳转已改成本目录真实文件（`idor-test.md` 一类）；不要再跟 `../xxx/SKILL.md`
- 与 `~/.grok/rules` 冲突时 **以 rules 为准**（挖什么 `src-value`；CORS 不挖 `cors-vuln-report-priority`；写不写 `vuln-report-format`）
- **`cors-test.md` / `llm-security-test.md`：不挖/禁开越狱。** `401-403-bypass.md` 不磨登录 HTML。
- 正式 SRC 报告：`~/.grok/rules/vuln-report-format.md`

## 文件清单

| 文件 | 说明 |
|------|------|
| `打穿短表.md` | 挖洞手法索引（一行/指针；正文仍在各模块） |
| `401-403-bypass.md` | **禁开磨登录 HTML**（已收成一行）；业务 API 401 现场自己打 |
| `api-gateway-test.md` | API 网关 |
| `agent-tool-exec-test.md` | 对话口工具真执行（不是越狱、不是云 IDE RPC） |
| `anon-id-chain-test.md` | 匿名总线吐 id → 详情不校验归属；坐席/管理端 JS 里的后台接口 |
| `authbypass-test.md` | 认证绕过（未登录改密/IDaaS + 短表指针；英文字典已砍） |
| `cache-poisoning-test.md` | 缓存投毒/欺骗（原有+补充） |
| `clickjacking-test.md` | 缺头不写（已收成一行） |
| `cloud-ide-codex-rce-chain.md` | 云 IDE/Codex 系：弱口令→RPC RCE→集群/API Key 链（短表有指针） |
| `cors-test.md` | **不挖勿开**（已收成一行） |
| `crlf-injection-test.md` | 几乎不交（已收成一行） |
| `csp-bypass-test.md` | 几乎不交（已收成一行）；XSS 走 `xss-test.md` |
| `csrf-test.md` | 专题知识（hack-skills 导入或融合） |
| `csv-formula-injection-test.md` | 几乎不交（已收成一行） |
| `dangling-markup-test.md` | 几乎不交（已收成一行） |
| `dependency-confusion-test.md` | 几乎不交（已收成一行） |
| `deserialization-test.md` | 专题知识（hack-skills 导入或融合） |
| `dns-rebinding-test.md` | 几乎不交（已收成一行）；SSRF 走 `ssrf-test.md` |
| `el-injection-test.md` | 专题知识（hack-skills 导入或融合） |
| `email-header-injection-test.md` | 几乎不交（已收成一行） |
| `file-upload-test.md` | 文件上传（STS/列桶/分享鉴权等指针） |
| `ghost-bits-cast-test.md` | Ghost Bits 原理+常用字+公式；逐字节两套表已砍 |
| `graphql-test.md` | GraphQL（原有+补充） |
| `hpp-test.md` | 几乎不交（已收成一行） |
| `http-host-header-test.md` | 专题知识（hack-skills 导入或融合） |
| `http-smuggling-test.md` | 请求走私（原有+补充） |
| `http2-attacks-test.md` | 几乎不交（已收成一行）；走私走 `http-smuggling-test.md` |
| `idor-test.md` | 越权（中文主线 + 短表指针） |
| `info-leak-test.md` | 信息泄露 |
| `injection-test.md` | 注入（OR+total / 邮件订阅 iframe / SSTI 探测；英文百科已砍） |
| `insecure-scm-test.md` | 专题知识（hack-skills 导入或融合） |
| `jndi-injection-test.md` | 专题知识（hack-skills 导入或融合） |
| `js-context-xss-bypass-test.md` | XSS 落在 JS 字符串里：闭合数学 / 禁用词替代（模板串调用、`*` 代 `+`）/ 哨兵闭合 |
| `js-reverse-guide.md` | JS 逆向 |
| `llm-security-test.md` | **禁开越狱教材**（已收成一行）；对话工具走 `agent-tool-exec-test.md` |
| `logic-test.md` | 业务逻辑（支付/流程 + 商家促销绑定） |
| `no-param-target-test.md` | 整站找不到参数：登录取 JS → 路由名反推参数 → fuzz 参数名（`order_by` 优先） |
| `oauth-jwt-test.md` | OAuth/JWT/SAML/OIDC（原有+多源补充） |
| `open-redirect-test.md` | 专题知识（hack-skills 导入或融合） |
| `path-traversal-lfi-test.md` | 专题知识（hack-skills 导入或融合） |
| `prototype-pollution-test.md` | 专题知识（hack-skills 导入或融合） |
| `race-condition-test.md` | 竞态（原有+补充） |
| `recon-methodology.md` | 侦察方法论 |
| `signing-oracle-test.md` | 签名预言机：客户端提交完整待签串、服务端拿生产密钥代签；含 403/206 正负控与 IAM 收敛 |
| `ssrf-test.md` | SSRF（IMDS 路径差 / GOPROXY / 对象存储回源） |
| `subdomain-takeover-test.md` | 专题知识（hack-skills 导入或融合） |
| `type-juggling-test.md` | 专题知识（hack-skills 导入或融合） |
| `waf-bypass.md` | WAF 绕过 |
| `websocket-test.md` | WebSocket（原有+补充） |
| `xslt-injection-test.md` | 几乎不交（已收成一行） |
| `xss-test.md` | XSS（中文开场 + 冷门事件 + XSS→RCE / 自定义协议） |
| `xxe-test.md` | 专题知识（hack-skills 导入或融合） |

**合计：52 个知识文件**（不含本 README）。其中 4 张是从 SRC 报告集蒸出来的
（`signing-oracle-test` / `anon-id-chain-test` / `js-context-xss-bypass-test` /
`no-param-target-test`）—— 只留打法，不带客户名。SRC 报告版式不在本库：见
`~/.grok/rules/vuln-report-format.md`。定级只认 format，本库不定级。
