---
description: 资产面侦察：子域、端点、JS 提取、指纹
---

# 侦察

## 目标
把"一个域名"扩成"一张端点图"，为后续挖掘提供候选。

## 只读手段
- 子域：`subfinder -d target.com`（被动源）、证书透明度日志。
- 端点/URL：从 HTML/JS 提取 `grep -oE '(href|src|fetch\()\s*["'\''][^"'\'']+'`
- 历史 URL：`gau` / `waybackurls`（公开归档，不触目标）。
- 指纹：`whatweb`、响应头、错误页特征、favicon hash。
- 常见路径：`/robots.txt` `/sitemap.xml` `/.well-known/` `/api/` `/swagger` `/openapi.json`

## 记录格式
每条候选写成：`{url, method, 来源, 参数, 为什么值得看}`。
把"值得看的原因"写清楚——它是后续优先级排序的依据。

## 纪律
- 目录爆破用**小字典 + 低速率**，且只在 scope 内；不做全量字典。
- 归档/第三方源优先（不触目标），直接对目标发请求放最后。
