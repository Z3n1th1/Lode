---
description: 排序参数注入（order/sort/sortOrder/orderByColumn）：ORDER BY 拼字符串、报错语义判列、JSON 上下文 \u 转义绕过、elt/decode 构造 bool
---

# 排序参数注入

`ORDER BY` 后面**没法参数化** —— 占位符不能当列名 —— 所以开发者只能拼字符串或做白名单，
一偷懒就成注入点。它常在 **JSON body** 里而不是 query 里，别只在 URL 上找。

## 定位

- 功能：列表 / 搜索 / 排序（`/xxx/list`、`/xxx/search`、`getXxxList`）
- 参数名：`order`、`sort`、`sortOrder`、`order_by`、`orderByColumn`、`sortField`、`order_direct`
- 名字不确定就先 fuzz 参数名（见 `no-param-target-test.md`），`order_by` 优先

## 报错语义就是免费的探针

不用猜列存不存在，报错会告诉你：

| 回显 | 含义 |
|---|---|
| `Unknown column 'xxx' in 'order clause'` | 这个参数/列不存在 |
| `Column 'xxx' in order clause is ambiguous` | **列存在**，只是要指定表 —— 有效的"存在性"证据 |
| 返回长度等于默认值（先跑一遍记下来） | 没生效，别当成功 |
| 返回长度/排序结果明显变了 | 生效 |

先跑一遍正常包，把**默认返回长度**记成基线（有站点默认长度是 1986，小于 1000 的也都是无效），
后面靠长度差判生效。

## 过滤探测（一个符号一个符号试）

`'`、`/**/`、`%0a`、`%09`、空格、`()`、`,`、`;`、`select`、`from`。

结果分三种，必须分清：**拦截**（报错/拦死）、**被替换成空格**（`/**/`、`%0a`、`%09` 常是这种
—— 那它就是你的空格）、**原样通过**。

## 绕过

- **JSON / JS 上下文里用 `\u` 转义。** 这是最容易被忽略的一层：`'` 被拦，但参数值是 JSON
  字符串时 `\u0027` 能过（`%27` 被拦、`%u0027` 直接 404，只有 `\u0027` 通）。原理是
  **WAF 看的是转义后的文本，JSON 解析器之后才把它还原成 `'`** —— 编码层级错位。
  关键字同理：`selec\u00741`、`fro\u006d`。
- **两个排序参数就拆两半。** 有 `orderByColumn` + `isASC`（或 `order` + `order_direct`）时，
  把一句 payload 拆开分别塞进两个参数，拼起来才成句 —— 单个参数看着无害，能过关键字匹配。
- **双写**：被过滤的函数写成重叠形式，`cast`→`castast`、`user`→`userser`、
  `varchar`→`varchararchar`。
- **十六进制 + 通配符**：先 `len(user())=12` 拿到宽度，再在 payload 里填 12 个 `5F`（`_`）
  逐位爆，配合 `like 0x25...`。

## 构造 bool（盲注时怎么看出真假）

- MySQL：`elt(n,a,b,c,...)` 按 n 返回第 n 个值 —— 让**排序结果或返回内容**在两组值之间跳。
  比 `case when` / `if()` 好用，因为它不是非黑即白，可以多值。
- `elt` 还有个副产品：n 超过后面参数个数时返回 **NULL**。于是
  `ifnull(elt(ord(user()),1,1,1,1,1), content)` 可以通过**数几个 1 才变**反推 ASCII。
- Oracle 系：`exp(710)` 必报错，用 `exp(decode(substr(user,1,1),'1',710,1))` 造 bool。
- 取子串：`right()` / `mid()` / `substr()` / `substring()` 挨个试，**哪个没被拦用哪个**
  （常见是被拦掉两个、剩一个）。`right(user(),n)` 是从右往左，超长会一直返回完整的。

判库：`user()` / `current_user` / `database()` 谁通谁不通能区分 MySQL 与原样衍生库（有些
库不是原生 MySQL，Oracle 系还得配 `DUAL`）。

## 纪律

- 头一发只取**一个字符**证明可读，不 dump。
- 报错原文和默认长度基线一起进报告，它们同时解释"是什么"和"凭什么说是"。
- 有 WAF 时记录**每一层**谁是拦、谁是归一（替换成空格），下次换站直接套。

> 来源：SRC 报告集（排序参数注入多例：Oracle 衍生库、参数拆分绕拦截、elt/right 差异法）——原始报告在 `E:\Study\SRC`。
