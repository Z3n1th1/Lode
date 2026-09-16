---
description: 广播当数据出口：隐式/粘性广播携带 token·cookie·路径，任意 App 注册同 action 就能收走
---

# 广播：应用内通信被写成了全局广播

组件之间传敏感数据最省事的写法就是 `sendBroadcast(intent)`，把 `access_token` /
`admin_cookie` / 服务器地址 / 本地文件路径塞进 extras。问题是它**没有"应用内"这个语义** ——
设备上任何 App 注册同名 action 就能收走。

## 建面

反编译后 grep 三样：`sendBroadcast(`、`sendStickyBroadcast(`、`setPackage(`，
看 extras 里放的到底是什么。

目标 action 常长得像"内部事件"：`<包名>.service.requestComplete`、
`<包名>.action.NOTIFY`、`FileUploader.UPLOAD_FINISH`。命名越像内部的，越容易漏掉这一层。

## 收

```xml
<receiver android:exported="true">
  <intent-filter android:priority="999">
    <action android:name="<target.action>"/>
  </intent-filter>
</receiver>
```

`onReceive` 里 dump extras（或 `adb logcat -s <TAG>:V` 收）。

## 一个必须写对的点

`priority` **只对有序广播（`sendOrderedBroadcast`）和粘性广播决定先后**。普通
`sendBroadcast` 是无序的 —— 所有匹配的接收器都会收到，priority 既不影响谁能拿到，
也不存在"抢先截断"。

所以报告里不要写"因为优先级高所以拦截了"：

- 普通广播：写"任意 App 注册同 action 即可收到"，**不需要** priority 任何论证。
- 有序广播：priority 决定顺序，且先到的可以 `abortBroadcast()`。
- 粘性广播：还多一层 —— 后注册的 App 直接 `registerReceiver` 就能把**最后一条**读走，
  根本不用等下一次发送。（自 API 21 起发送粘性广播需要 `BROADCAST_STICKY` 权限。）

## 判据

- 收到的 extras 里**有凭据或用户数据** → 成立，把收到的字段名列出来。
- 只收到一个状态枚举（"上传中" / "已完成"）→ 信息价值接近零，别硬报。
- 光证明"能注册同名 receiver"不算 —— 那是所有 Android App 的常态，不是发现。
- 用 `setPackage()` 限制接收方的广播：它只约束**后半段**（谁能收），不认证**最初调用者**
  —— 恶意 App 照样能发一条伪造的进来。

## 纪律

- 只在自己账号上触发；收到的凭据不落盘、不外发，报告里只引字段名。
- 负控：换一个不存在的 action 必须收不到，证明是 action 匹配而不是在全局监听。

> 来源：SRC 报告集（Android 广播信息泄露多例）——原始报告在 `E:\Study\SRC`。
