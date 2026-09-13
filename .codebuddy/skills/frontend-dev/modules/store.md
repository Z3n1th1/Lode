---
description: store.ts 模块级单例的状态组织、派发与收敛
---

# 状态

`console/src/store.ts` 是**模块级单例**（`ref` / `computed` / 动作函数），不是 Pinia。
面板组件从它 import 状态与动作，保证行为一致。

## 加状态的判据

先问三遍：
1. 这个值是**派生**的吗？→ 用 `computed`，不要存两份。
2. 只有**一个组件**用吗？→ 放组件本地 `ref`，别进 store。
3. 它是**跨面板共享**或需要跨刷新保留的吗？→ 才进 store。

## 加动作的规范

- 动作负责：调 `api.ts` → 处理 `ApiError` → 写回状态。
- 网络层错误在动作里统一收口，组件只处理"成功后的展示"。
- 轮询/加载派发保持在 `loadPageData` 一处，不要在多个组件里各起定时器。

## 收敛（P5 方向）

- 删掉死字段、死动作、死分支；store 的目标规模约 350 行。
- 面板移除后，把只服务它的状态与动作一并删干净，不留"以防万一"。
- 每次收敛前后跑 `npm run typecheck` + `npm run test`。

## 反例

- 组件里 `const local = ref(store.someValue)` 做影子状态 → 双源不同步。
- store 里塞 DOM/UI 细节（颜色、列定义）→ 属于展示层。
