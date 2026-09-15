---
description: 匿名总线吐 id，详情接口不校验归属 —— 外加坐席 JS 里的后台接口
---

# 匿名总线 → 对象 id → 详情

## 形状

客服 / IM / 工单这类系统通常有一个**实时总线**接口给访客拉自己的消息。若它不绑定会话：

```
匿名 GET /chat-msg/user/msg.action   →  一批他人的 {cid, uid, msgId, adminName}
```

拿到 `cid` 之后，详情接口往往**只按 id 查、不校验归属**：

```
匿名 GET /chat-web/user/getChatDetailByCid.action?cid=<上面那条>  →  完整聊天记录
```

再顺一层，`uid` 还能反查出该用户的**全部** cid：

```
匿名 GET /chat-web/user/queryUserCids.action?uid=<总线里的 uid>  →  {"cids":[...7 条...]}
```

## 三个放大器

1. **坐席/管理端 JS 是金矿。** 报告里那条 `/chat-kwb/admin/queryCids.action` 是从
   `/online/agent/static/js/main.<hash>.chunk.js` 挖出来的 —— 用户端页面不引用它，所以
   只爬用户端 JS 永远发现不了。**把坐席端/管理端的前端包也拉下来跑一遍。**
2. **写接口可能也不绑对象。** 把总线泄露的 `cid` 拿去 POST 发消息，若服务端不校验归属，
   就是"以他人身份说话"。
3. **附属路径跟着看。** 有了 cid 之后，`isComment` / `getStatusNow` /
   `satisfactionMessage` 这类接口常顺手泄露状态、内部 companyId、评分档位。

## 负控（必须做，否则会被判成"接口设计如此"）

| 负控 | 期望 |
|---|---|
| `cid=1` 或 cid 缺省 | 空体 / `[]` / 500 —— 证明不是"任何输入都返回数据" |
| `uid` 缺省 | `cids: []` |
| 用**自己的**会话 id 走同一接口 | 只拿到自己的（基线 H0） |

报告里还做了**写对照**：自有 init+connect 后回读 msg 长度=1，他人 cid connect 500、详情
仍是 21 条 —— 两个方向夹住"读能读、写不能注入"。

## 影响边界

明确写"未主张坐席后台接管、未批量拉取其余 cid"。定级只认已观察事实：抓到一条他人 cid
能读，不等于 7 条全读了；全读了也不等于能登录后台。

## 修复要点

- 总线必须绑定**当前访客会话**，禁止返回其他 cid 的事件。
- 详情 / 离线消息 / 状态 / 坐席列表一律校验请求方是否为该 cid/uid 的访客或已登录坐席；
  配置里的登录开关（如 `consultLoginEnable`）要在**读接口**上真正生效。
- 已暴露的 cid 做失效/归档。
- **别只修读接口** —— 同源的 `postMsg` / `chatsend` 一起查。

> 来源：SRC 报告集（客服/IM 未授权类）。原始报告在 `E:\Study\SRC`。
