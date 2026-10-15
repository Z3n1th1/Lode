---
description: 工作流/代码节点/共享解释器隔离失效：vm2 external、可写 PYTHONPATH sitecustomize、跨租户同一执行器
---

# 沙箱逃逸（代码节点 / 共享解释器）

认的是「用户代码进了**共享执行器**，隔离只是配置没配上」。
和 `agent-tool-exec-test`（对话口工具真跑命令）不同：这边是**工作流画布 / Playground
代码节点**把脚本转发到 Node/Python 执行器。和 `llm-security-test`（越狱）无关，不要开那张。

Lode 只**认形状、取存在性证据**。真正跑逃逸 payload / 钻石命令给人验证。

## 认什么

像下面任一摊：

1. 工作流/自动化有「代码节点」「runJS」「runSingleNode」「code_execute」
2. 回包或源码里出现 `vm2`、`NodeVM`、`external: true`、`require.external`
3. 任务环境有 `PYTHONPATH=` 指向可写目录（`/python3/pkg` 一类），Python 会自动 import
   `sitecustomize`
4. 不同租户/不同账号的任务打到**同一台**执行器（hostname / 内网 IP / cwd 相同）
5. 无效 `project_id` 仍创建并执行任务

## 打哪（存在性，不落地）

1. 找到执行口（保存图再跑；有的口**只跑已保存图**，请求体里的 `content` 是摆设）。
2. GET 能拿到的配置：`package.json`、`/actuator/env`、错误栈、回包里的 `cwd`/`hostname`。
3. 无害对照：让节点打官方 SSRF 靶场或 `id`/`echo` 标记——**闸门允许的存在性探针**。
   嵌套 `require('vm2')` 再开 `child_process`、写 `sitecustomize.py` 到共享盘，留给人。
4. 跨租户：两个受控号各跑一次，比 hostname / cwd / 能否读到对方刚写的启动文件。
   读到即隔离失效；不要在共享盘留文件。

## 出什么算成

- 执行器在核心网段 / 官方内网靶场 HTML 回显
- 配置里 `vm2` + `external: true`，或 `PYTHONPATH` 指向任务可写目录
- 两个租户打到同一解释器启动路径

沙箱 `uid=` 只证明代码跑了，**不算跨租户**。口头「模型说执行了」不算。

## 假点

- 本地 iframe / 浏览器里跑的 JS，没有服务端执行器
- 每租户独立容器、写不进对方启动路径
- 对话口工具（走 `agent-tool-exec-test`）
- 越狱话术没有代码节点（不是这枪）

## 停

认出执行器隔离失效就记 finding，**证明存在即停**。不写 webshell、不横向、不改生产工作流
（每次自己新建）。ByteSRC / 明确禁 LLM 面时只记地址给人测。

> 来源：SRC 报告集（工作流代码节点沙箱、开放平台共享 Python 启动路径）。原始报告在 `E:\Study\SRC`。
