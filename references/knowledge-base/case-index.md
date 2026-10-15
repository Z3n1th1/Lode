---
description: 以前打过的形状对照表。认出面相就拉对应卡，用当前站差分验证。不是清单，没对上的照样挖，不要复述旧报告。
---

# 案例对照（形状 → 卡）

对照是为了**少走弯路**，不是为了把这次挖成上次的复制。认到形状就拉那一张卡，
按**这一站**的基线 vs 探针打。没对上的形状照样挖。禁止把旧报告里的域名/票/FLAG
抄进这次请求。

| 认什么 | 拉哪张 | 一句话 |
|--------|--------|--------|
| DNS 死了 / 401 带业务体 / 同 IP 多 Host | `orphan-origin-test` | `--resolve`/Host 直打源站 |
| 整站看不到参数、只有 SPA | `no-param-target-test` | 登录取 JS，路由名反推，fuzz 参数名 |
| ticket/ws 签在 query 上，换票即跨用户 | `forwardable-ticket-test` | 只换凭据，读别人对象字节 |
| 匿名 STS / sign `key=/` / 桶策略全开 | `file-upload-test` | List 403 别停，换匿名票再打 |
| `endsWith` 裸后缀、JSBridge、导出组件 | `url-trust` · `mobile` | 标签边界；外部真拿到能力 |
| 工作流代码节点 / 共享 PYTHONPATH / vm2 | `sandbox-escape-test` | 认出执行器隔离失效；RCE 给人验证 |
| 排序参 `order_by` / `orderByColumn` | `orderby-sqli-test` | 报错语义判列，elt/decode 造 bool |
| XSS 落在 JS 字符串里 | `js-context-xss-bypass-test` | 闭合数学、禁用词替代 |
| 小程序两层密钥、密文当授权 | `miniprogram-crypto-test` | 解开再打，密文不是访问控制 |
| 授权结论由响应字段决定 | `client-trust-response-test` | 改回包即放行 |
| 客户端提交待签串、服务端代签 | `signing-oracle-test` | 403/206 正负控 |
| 匿名总线吐 id，详情不校验归属 | `anon-id-chain-test` | 坐席/管理端 JS 里的后台口 |
| `/v2/_catalog` 或 Harbor systeminfo | `idor-test` | 制品库 catalog；拉到别人租户才算 |
| 身份口拦了、对话口工具仍跑命令 | `agent-tool-exec-test` | 不是越狱；stdout 要 flag/钥/他文 |
| 未登录发 CSRF / 回跳外域接管 | `csrf-test` | 账号接管要能换会话 |
| 导出广播带 token/cookie | `android-broadcast-leak-test` | 隐式/粘性广播是数据出口 |
| 资产测绘、精确 host、ARL 导出 | `arl-recon` | 先收集精确 host 再打，CDN 丢掉 |

一次只拉一篇。拉完用当前站的差分，不要把表上的例子当 payload。
