---
description: 孤儿后端（Origin-Direct）：域名死了源站还在监听，用 --resolve/Host 直打 IP，重点是不再受边缘鉴权保护的那一面
---

# 孤儿后端（Origin-Direct）

业务下线时运维通常只做了一半：把 **DNS 名字摘了 / CDN 关了 / 证书撤了 / 管理面入口关了**，
但**源站 IP 还在监听**，而且经常忘了关鉴权。结果是一个"公网看不见、但直连还在"的后端。

常规子域爆破和浏览器访问都找不到它 —— 对攻击方和防守方**同样隐形**，所以里面往往还是几年前的
状态。资产清单要以**可达后端**为准，不是以"当前能解析的域名"为准。

## 五步

**1. 资产扩面 —— 先有名字。** 证书透明度（crt.sh）、历史解析记录、CDN 回源配置、移动端 APK /
H5 bundle / source map 里的 API baseURL、错误页、内部服务名、邮件/下载/回调链接里露出的域和内网记录。

高价值名字，出现即加重测：`*-admin`、`*-api`、`*-gateway`、`*-manager`、`hweb-*`、
`*-portal`、`workflow`、`conductor`、`job`、`xxl`；以及环境前缀 `test-` / `pre-` / `gray-` / `uat-`。

**2. 源站定位。** 维护一张表：域名 → 公网解析 / CDN / 边缘 IP / 疑似源站 IP / 响应指纹 / 备注。
解析不通的也先留在"待验证"池里，别直接删。

**3. 虚机枚举 + 4. 指纹分层。** 探针分三档：

| 档 | 路径 | 目的 |
|---|---|---|
| 通用 | `/favicon.ico`、`/robots.txt` | 是不是虚机 |
| 框架 | `/actuator/health`、`/swagger-ui.html`、`/v3/api-docs` | 组件识别 |
| 高危 | `/api/workflow/search`、`/druid`、`/nacos`、`/graphql` | 管理探针 |

同 IP 上挂多个业务是常态 —— 分层记成"基础设施（nginx/openresty/APISIX/WAF）× 应用（Spring/
Conductor/XXL-JOB/Nacos/Druid）× 安全控制层（鉴权在哪）"，输出"这是什么系统、最可能的洞型"，
而不是一上来丢漏洞库。

## 直打姿势

```bash
# 域名强制指到源站 IP
curl -sk --noproxy '*' --resolve app.example.com:443:$IP \
  -H 'Host: app.example.com' -H 'Origin: https://app.example.com' \
  'https://app.example.com/path'

# 等价的最小形式
curl -sk --noproxy '*' -H 'Host: app.example.com' 'https://$IP/path'
```

**`--noproxy '*'` 不是可选项** —— 本地代理没走通会造成假超时，把活的源站误判成死的。

## 响应语义矩阵（决定要不要继续）

| 现象 | 解读 |
|---|---|
| 401 / 403 + 统一错误页 | **活后端，有鉴权** —— 不是死，是还没进门 |
| 报错里出现字段路径（`updateXxx.arg0`、Bean Validation） | 已**过了鉴权过滤器**，进业务方法了 —— 离洞最近 |
| 纯 HTML 403 / 访问日志无记录 | 可能还在边缘（WAF/CDN），换 IP 或换 Host 再试 |
| 200 + 业务 body / 组件 JSON | 到手 |

很多所谓"漏洞"其实是**鉴权位置问题**：网关挡在解析前（统一 401），应用层没挡（500 进了解析器）。
把"鉴权在哪一层"单独写出来，比多报一个点值钱。

## 利用加深（按危害递增，且守授权范围）

读（配置、历史任务、凭据）→ 写（改定义/改任务，默认要能还原）→ 执行（授权且可证明时，最小命令回显）
→ 横向（内网）。编排引擎那类不是普通 JSON 接口，它**本体就是脚本能力**，所以"能写"到"能执行"很短。

## 纪律

- **一个 IP 上多系统、多组件时，一根因一份报告**，不要合并；修复动作和复测计划都按洞拆开。
- 别高频扫管理路径 —— 会触发封锁，把自己的会话丢掉。
- 例子里两个同 IP 的案例根因不同（一个编排引擎未授权、一个 Fastjson 反序列化），
  报告里必须分开写，否则复测和整改都会错系统。

> 来源：SRC 报告集（孤儿后端 / Origin-Direct 专项）。原始报告在 `E:\Study\SRC`。
