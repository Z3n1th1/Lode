---
name: backend-dev
description: |
  Lode 后端开发（Python + FastAPI）。改路由、任务、LLM 客户端或黑板时加载。
  触发场景：改 .py、加接口、调任务调度、接模型、改持久化状态。
  触发词：后端、FastAPI、路由、router、任务、job、SSE、llm_client、黑板、blackboard
---

# 后端开发 — 调度器

**保持 Python + FastAPI**（已定：工作负载是 LLM/网络 I/O 密集，GIL 不是瓶颈）。
启动方式：`python -m console.server`。

## 0. 铁律

1. **导入规范**：统一 `from core.x import ...`；混用裸 import 在 `python -m console.server` 下会炸。
2. **路由契约冻结**：`tests/test_route_contract.py` 断言 `create_app` 的 (method, path) 全集。
   改路由就必须**显式**同步它，而不是让测试变红后随便改。
3. **fail-closed**：校验失败就拒绝，不猜、不降级成"放行"。
4. **副作用要人管**：任何写操作/对外请求都要有明确的授权与边界检查。
5. **测试用 py310**：`PA_PYTHON`。提交前 pytest 全绿。

## 1. 命令

```bash
python -m pytest -q          # 全量
python -m console.server     # 起服务
```

## 2. 模块索引（按需加载）

| 主题 | 模块 |
|---|---|
| 路由拆分与契约 | `modules/routers.md` |
| 持久化任务与事件流 | `modules/jobs.md` |
| 统一 LLM 客户端 | `modules/llm-client.md` |
| SRC 黑板 | `modules/blackboard.md` |

## 3. 输出要求

- 说明改动的接口/行为、对调用方的影响、兼容性处理。
- 附 pytest 结果；新增接口要有测试；改了路由契约要说明为什么。
