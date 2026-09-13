---
name: frontend-dev
description: |
  Lode Console 前端开发（Vue 3 + TypeScript + Vite）。改组件、状态、样式或加页面时加载。
  触发场景：改 .vue/.ts、调 UI、修前端 bug、加交互。
  触发词：前端、组件、Vue、naive-ui、store、样式、vite、vitest、界面
---

# 前端开发 — 调度器

技术栈固定：**Vue 3.5 + TypeScript + Vite + naive-ui + vue-tsc + vitest**，代码在 `console/`。

## 0. 铁律

1. **单一设计系统**：只用 `naive-ui`（版本锁定）。不要引入第二套 UI 库（`element-plus` 正在移除）。
2. **状态只有一处**：`store.ts` 是模块级单例，面板组件只 import，不各持状态。
3. **类型是门槛**：`npm run typecheck`（`vue-tsc --noEmit`）必须过；不写 `any` 逃逸。
4. **改动必须并存测试**：改行为就补/改 `*.test.ts`，`npm run test` 必须绿。
5. **不夹带**：一次改动只做一件事；不顺手重排无关代码。

## 1. 命令

```bash
cd console
npm run test        # vitest run
npm run typecheck   # vue-tsc --noEmit
npm run build       # typecheck + vite build
npm run dev         # 127.0.0.1:5174
```

## 2. 模块索引（按需加载）

| 主题 | 模块 |
|---|---|
| 组件拆分与契约 | `modules/components.md` |
| 状态与数据流 | `modules/store.md` |
| UI 库与样式 token | `modules/ui-lib.md` |
| 测试与类型检查 | `modules/testing.md` |

## 3. 输出要求

- 说清改了哪些文件、行为有什么变化、为什么这么改。
- 附上跑过的命令与结果；没跑过的不说"应该没问题"。
