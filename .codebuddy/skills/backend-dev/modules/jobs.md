---
description: 持久化任务、租约幂等与 SSE 事件流
---

# 任务与事件流

任务必须**扛得住进程重启**：状态落盘，不是线程内存。

## 组件

- `core/job_registry.py`：任务的创建/查询与状态持久化。
- `core/job_runner.py`：执行器（`JobRunner` / `JobContext`），在应用 lifespan 里启动。
- `core/event_log.py`：统一事件日志，SSE 的读侧来源。
- `console/jobs.py`：各 kind 的 handler 注册表（如 `src_loop`、`surface_scan`、`chat_turn`）。

## 加一种任务

1. 定义 `kind` 与 `payload` 形状（payload 要能 JSON 序列化）。
2. 在 `console/jobs.HANDLERS` 注册 handler；handler 只编排，不做 I/O 细节。
3. 通过 `ctx.emit(...)` 发事件，让前端有进度可看（`subtask_started` / `assistant_message` 等）。
4. 幂等：同一次执行重复触发不能产生重复副作用（**租约 + 去重**）。
5. 退出/重启要能恢复：不依赖进程内内存做唯一真相。

## SSE

- 端点：`/chat/sessions/{id}/stream`，按 `since` 游标续传。
- 断线重连由客户端带 `since` 重放；服务端不做"全量重发"。
- 事件要小而稳：类型 + 最小载荷；大对象存本机，事件里只带引用。

## 回退开关

历史上保留了 `LODE_JOBS_V2=0` 回退线程路径的镜像一版。改动任务层时确认两条路径都不炸，
或在确认无回头需求后，随迁移一并删掉镜像（别长期双轨）。

## 纪律

- 长任务不阻塞请求线程。
- 失败要落到事件/状态里，能被 Console 看到，不是只打日志。
- 每个新任务 kind 都要有"重复执行"与"中途重启"的测试。
