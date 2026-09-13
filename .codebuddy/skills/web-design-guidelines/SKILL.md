---
name: web-design-guidelines
description: |
  按 Vercel《Web Interface Guidelines》审查并修复前端代码的可用性与交互质量。
  不是"好不好看"的主观评审,而是一份可逐条核对的硬清单:焦点态、动效降级、
  表单语义、排版细节、暗色模式、触控、破坏性操作、反模式。
  触发场景:改了 UI、被说"丑"、要做可用性/可访问性审查。
  触发词:UI 审查、好看、可用性、a11y、可访问性、设计规范、界面、样式
---

# Web Interface Guidelines 审查器

来源:`vercel-labs/agent-skills/web-design-guidelines`(Vercel)。规则本体不在这个文件里,
**每次审查前重新拉取**,避免用过期清单:

```
https://raw.githubusercontent.com/vercel-labs/web-interface-guidelines/main/command.md
```

## 工作流

1. WebFetch 上面那个 URL,拿到当次的最新规则。
2. 读被审的文件(或问用户要给哪个 pattern)。
3. 逐条核对,输出 `file:line` 形式的简短结论(该 skill 规定的格式),不要长篇解释。
4. **然后改**。只报不改等于没做。

## 本项目的落地约定(重要,原版没有)

- 技术栈是 **Vue 3 + naive-ui**,不是 React/Tailwind。原清单里的 `focus-visible:ring-*`
  这类写法要翻成本项目的等价物。
- **颜色一律走 `--pa-*` token**,写死 hex 直接算不通过 —— 两套主题(暗色默认 / 浅色)靠
  `:root` 与 `:root[data-theme="light"]` 覆盖同名 token 实现,写死颜色会在另一套主题下花掉。
- 组件库层面的主题由 `App.vue` 的 naive-ui `darkTheme` + `themeOverrides` 承担;
  自绘样式由 `styles.css` 的 token 承担,两者必须对齐,否则组件库和自绘部分两种风格。
- 全局可访问性/动效/触控基线已经写在 `styles.css` 的「交互质量」段:
  `focus-visible` 焦点环、`prefers-reduced-motion` 降级、`touch-action`、
  `tabular-nums`(正文再关掉)、`overscroll-behavior`、skip link 样式。
  加新动画前先确认它已经落在降级范围内。

## 检查时最常命中的几条

- 图标按钮没有 `aria-label`;异步更新区没有 `aria-live`。
- 加动画了但没有 `prefers-reduced-motion` 降级,或用了 `transition: all`。
- `outline: none` 去掉了焦点环却没给替代。
- 破坏性操作点了就执行,没有确认框。
- 数字列没用 `tabular-nums`,刷新时整列跳动。
- 文案:`...` 而非 `…`;加载态不以 `…` 结尾;错误信息只说问题不给下一步。
- 长内容(URL/hash/手机号)没兜底,把布局撑破;flex 子元素缺 `min-w-0`。

## 输出格式

```text
## console/src/components/AppHeader.vue

console/src/components/AppHeader.vue:41 - 图标按钮缺 aria-label
console/src/components/AppHeader.vue:88 - 动画未覆盖 prefers-reduced-motion

## console/src/styles.css

console/src/styles.css:120 - transition: all → 列出具体属性
```

没问题的文件写 `✓ pass`,不要凑字数。
