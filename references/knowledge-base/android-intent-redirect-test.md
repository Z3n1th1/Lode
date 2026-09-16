---
description: 外部 Intent 被应用转发：嵌套 Intent 绕过 exported=false，外部 extra 决定请求发往哪台服务器
---

# Intent 重定向与权限重委托

导出组件里凡是"把收到的 Intent 再转一手"的代码，都要单独看一眼 —— 这是外部把手伸进
**未导出组件**、以及借应用身份对外发请求的两条路。

## 形态一：嵌套 Intent（Intent Redirection）

入口是导出的 Activity / Service，它从一个 Parcelable extra 里取出**另一个 Intent** 再
`startActivity` / `startService`，中间不校验目的组件。

- 先找一个 `android:exported="false"` 但内部敏感的组件（改配置、显示凭证、调内部 API）。
- 外层 Intent 打导出的入口，内层 Intent 指向那个私有组件。
- 结果：外部 App 自己启动不了它，却能借入口组件启动它 —— 绕的是 exported 边界。

可疑点：`getParcelableExtra("target_intent")`、`Intent.parseUri(...)`（带
`URI_ALLOW_UNSAFE` 时尤其）、`startActivity(getIntent().getParcelableExtra(...))`。

## 形态二：参数决定"发给谁"（权限重委托）

外部 Intent 的 extra 控制了应用内部网络请求的**目标地址**（`server` / `host` / `endpoint`），
应用拿自己的 `INTERNET` 权限把它发出去。

- 危害不在"能发请求"，而在**请求里带着应用的凭证**：自有 token、内网可达、签名头。
- 证据用自己控制的一个地址收下请求，列出**实际收到了什么**；不要顺手去打内网或第三方。

## 形态三：PendingIntent 可变

交给别人的 `PendingIntent` 没带 `FLAG_IMMUTABLE`，对方就能替换里面的 Intent，而
**执行身份仍然是原来那个 App 的 uid** —— 等价于把"以本应用身份启动任意组件"借了出去。
（API 31 起新建时 `FLAG_IMMUTABLE` 才是默认，老代码里的 mutable 要专门找。）

## 判据

- 能启动未导出组件 → 成立，但必须说明**启动之后发生了什么**（是否真的到达敏感操作）。
- 能读回内容 / 收到带凭证的回调 → 更硬。
- 只是"存在转发代码" → 不算，得证明目的地可控。

## 纪律

- 用例先在**自己**的组件上跑通，再对未导出组件做单次只读验证。
- 不借重委托出来的能力去打内网；收到回调即止，不做二次利用。
- 负控：把内层 Intent 指向一个正常公开组件，必须正常工作 —— 证明关键是"目的地可控"，
  不是那条代码路径本身。

> 来源：SRC 报告集（Android Intent 重定向 / 权限重委托多例）——原始报告在 `E:\Study\SRC`。
