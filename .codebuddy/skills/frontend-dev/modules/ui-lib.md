---
description: naive-ui 单一设计系统、token 与样式规则
---

# UI 库与样式

## 设计系统

- **只认 `naive-ui`**（版本锁定在 `package.json`，升级要单独评估）。
- `element-plus` / `vue-element-plus-x` 是待移除的遗留：新代码**不要**用它们；
  迁移时把对应组件换成 naive-ui 等价物（表格 `NDataTable`、按钮 `NButton`、弹层 `NModal`/`NDrawer`…）。
- 图标用 `@lucide/vue`，不引第二套图标库。

## 样式规则

- 优先用 naive-ui 的组件 props 与 `n-*` token 表达主题，不硬编码颜色。
- 组件样式用 `<style scoped>`；全局样式只在 `styles.css` 里维护。
- 删除面板/组件时，同步删掉它专属的 CSS 规则（避免死规则堆积）。
- 不做 pixel-perfect 的魔法数微调；用间距/字号阶梯。

## 类型尺度（保持一致）

- 标题层级、正文、辅助文字各固定一档；不因"看起来小"临时加字号。
- 信息密度优先：控制台是工作界面，不是营销页。

## 检查

- `grep -n "element-plus" console/src` 应逐步归零。
- 新增样式后确认没有引入第二套色板。
