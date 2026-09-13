---
description: core.llm_client 单一工具调用客户端的用法与裁剪语义
---

# LLM 客户端

全产品只有**一个** LLM 客户端：`core/llm_client.py`。历史上有重复客户端与 `model_client.py`，都已删除 —— 不要再造第二个。

## 用法

- 工具调用走统一的 `complete_messages`（带 tools 的对话补全）。
- 模型分层在 `core/llm_pool.py` / `core/llm_settings.py`：按模式选 tier（`explorer` / `reasoner`）。
- 排障看 `core/test_log.py` 相关的测试日志旁路。

## 消息裁剪

- 发送前会做 `_sanitize_messages` 与裁剪：**保序**、保最后的用户轮次，超限丢最老的。
- 改裁剪逻辑要格外小心：轮次顺序错会导致模型行为突变。
- 有专门的截断轮次测试，改完必须过。

## 加调用点

1. 复用 `core.llm_client`，不要在业务模块里直接打 HTTP。
2. 明确超时与失败行为：LLM 挂了要**降级**（回一条可读的失败信息），不能让整个任务崩。
3. 需要结构化输出时：要求 JSON + 解析失败 fail-safe（如意图路由默认 `reply`）。
4. 加测试，用假客户端注入，不打真实网络。

## 纪律

- 不把密钥写进代码/日志/事件；走配置。
- 不在循环里无节制重试（会烧配额）；重试要有上限和退避。
- 提示词属于 `core/skills` + `config/modes.yaml`，不要把大段提示词硬编码进业务函数。
