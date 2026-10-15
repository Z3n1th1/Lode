---
description: 信息收集：ARL 风格指纹、导出导入、CDN 过滤；产出精确 host 再交给猎场。不爆破、不 Nuclei 全量、不跑 PoC。
---

# 资产测绘（ARL 蒸馏进 Lode）

先有**精确 host**，再 engagement。不要对着 `*.example.com` 或 CDN 边沿开打。

Lode 不跑 ARL 全家桶（Mongo / 爆破 / Nuclei / NPoC）。蒸进来的是：

1. **被动扩面**：crt.sh、seed、操作员丢进来的 ARL 导出
2. **指纹 GET**：Nacos / XXL-JOB / Harbor / Actuator health / Grafana / WebLogic / 泛微
3. **WIH**：已经拿到的 HTML/JS 里认云钥形状、JWT 形状、内部 host（当线索，不当低危主洞）
4. **去废**：CDN CNAME、黑资产后缀丢掉

## 产出

每条候选：`{host 或 url, 来源, 指纹标签, 为什么值得看}`。同一资产来自多个来源时保留 `evidence_refs`，不要只看一条出处。
猎场只吃 **in-scope 的精确 host**。Console 开「ARL 资产」时，表面发现会多打一档指纹探针。

自定义 200 错误页和 SPA fallback 先做一次随机不存在路径基线；与基线一致的响应只记为
`soft-404 fallback`，不算真实路径。基线请求也计入同一个 scope 速率和请求预算。

命令：

```
python lode.py recon --scope scope.json --out-dir out --arl-export dump.json
```

`--arl-export` 吃 ARL 任务导出（`data.items[].site` / `domain` / `ip`）或普通 JSON/CSV 主机表。
导入后仍走 IntelScope，越界的扔掉。

## 指纹怎么读

| 现象 | 解读 |
|------|------|
| `/nacos/` 标题 Nacos | 配置中心，加重测 |
| `/xxl-job-admin/toLogin` 含 XXL JOB | 调度控制台 |
| `/api/systeminfo` 含 harbor_version | 制品库 |
| `/actuator/health` 返回 UP | Actuator 服务存活指纹 |
| 401/403 + 业务 JSON | **活后端**，不是死 |

## 纪律

- 只 GET/HEAD。不端口爆破、不目录爆破、不 Nuclei 全模板、不服务弱口令。
- CDN / 第三方静态域不进猎场。
- JS 里的云钥形状记 hint，接到存储/鉴权链再打；单独 JS key 不当主洞。
- 收集完把精确 host 写成 `allowed_hosts`（空 `allowed_domains`）再开猎。

> 来源：ARL-Friend v2 识别插件与 WIH 规则蒸馏。原始发行包 `E:\Study\SRC\v2.tar.gz`。
