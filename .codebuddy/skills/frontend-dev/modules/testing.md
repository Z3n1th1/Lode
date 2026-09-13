---
description: vitest 组件测试与 vue-tsc 类型门槛
---

# 测试与类型

## 门槛（每次改动都要过）

```bash
cd console
npm run typecheck   # vue-tsc --noEmit
npm run test        # vitest run
npm run build       # 提交前
```

## 测试写法

- 测试文件与被测模块**同目录同名**（`chatTools.test.ts`、`dashboard.test.ts`）。
- 测**行为**，不测实现细节：输入 → 期望输出/期望渲染，别断言内部变量名。
- 纯逻辑（格式化、过滤、事件归并）优先抽到 `.ts` 里测，比挂载组件更稳。
- 需要挂载时用 `@vue/test-utils`；只断言用户能看到的东西。
- SSE/流式：把事件序列喂给归并逻辑单测，不要依赖真实网络。

## 反例

- 快照测试当唯一断言（改样式就全红，且没人看）。
- 测私有函数名。
- 用 `setTimeout` 等真实时间 → 用假定时器。

## 报告

跑完把命令与结果贴出来；有 skip 或警告要说清。失败不掩饰、不改成"通过"。
