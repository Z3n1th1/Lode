---
description: src_blackboard 的事实/意图/死路/提示与租约协调
---

# SRC 黑板

`core/src_blackboard.py` 是跨进程的 SRC 协调层：**只协调，不执行网络，不保存原始证据**。

## 记录类型

| 类型 | 含义 |
|---|---|
| fact | 已确认的观测（端点、指纹、参数） |
| intent | 待办：需要 runner 或人工确认的动作 |
| dead_end | 已验证走不通的方向（防止原地重复） |
| hint | 线索/猜测（未验证，供后续优先排序） |
| claim | 对某个 intent 的租约占用 |

## 生命周期

1. worker 读取黑板，挑一个 intent。
2. `claim_next` → 拿到租约（带 heartbeat 续期）。
3. 执行；把结果作为 fact / dead_end 写回。
4. `finish` 释放；租约过期会被回收，允许别的 worker 接手。

## 并发语义

- 跨进程锁 + 原子写；不要绕过封装自己写状态文件。
- 租约 + 幂等保证同一 intent 不被重复执行；重复执行是 bug，不是"多跑一次也无所谓"。
- 状态文件拒绝符号链接（防劫持）。

## 与任务层的关系

intent 由 `intent_router` 产生，映射成 `job_registry` 里的任务，由 `job_runner` 消费。
`depends_on` 就是 DAG 边；链条要有依赖顺序，不要并行打同一目标。

## 纪律

- 只协调候选，**不自动执行利用链**；真实执行依赖外部授权的 runner。
- 原始请求/响应、cookie、token、证据文件留在本机，不进黑板、不进通知。
- 停止条件要写进状态：覆盖够了/风险够了就停，不做无界扫描。
