---
description: APIRouter 拆分规范、路由契约冻结、依赖注入与校验
---

# 路由

## 结构

- 应用装配在 `console/app.py`（`create_app`）。
- 业务路由在 `console/routers/*.py`（`base`/`chat`/`dashboard`/`jobs`/`llm`/`meta`/`projects`）。
- 只读投影在 `console/projections.py`；认证/依赖在 `console/auth.py`、`console/deps.py`。
- `console/control_plane.py` 是历史巨石拆分后的残壳，不要往里加东西。

## 加一个路由

1. 选对 router 模块（或新建一个并注册进 `create_app`）。
2. 用 `deps` 里的依赖做认证/取状态，不自己解析 token。
3. 入参校验放边界：类型、范围、枚举；越界直接 4xx，**不吞异常**。
4. 加测试（正常 + 至少一个拒绝路径）。
5. 同步 `tests/test_route_contract.py` 的 (method, path) 集合。

## 契约冻结

路由全集是**故意**冻结的：它挡住"幽灵路由"（文档有、代码没）和意外新增。
新增/删除都要在同一个提交里更新契约测试，评审时一眼可见。

## 纪律

- 一个 router 别塞跨域逻辑；共享逻辑下沉到 `core/`。
- 别在路由里直接跑长任务 → 交给 job runner（见 `jobs.md`）。
- 错误响应结构保持一致，不要每个接口一种形状。
