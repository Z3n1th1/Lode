---
description: Android Content Provider 面：导出无权限、projection/sortOrder 直接拼 SQL、openFile 缺规范化 → 读私有目录
---

# Content Provider 面

Provider 是客户端里唯一一个**直接给外部返回数据**的组件 —— 另外三件套最多让外部"触发一次"，
Provider 能把 `shared_prefs` / 数据库 / 私有文件交出去。同一条线上它定级最高。

## 建面

`AndroidManifest.xml` 里 `<provider android:exported="true">` 且**没有** `android:permission`：

- 没有 `grantUriPermissions` → 全 URI 任意 App 可读。
- 有 `grantUriPermissions` → 授权只落在**被授予的那一个 URI** 上，别当成整个 Provider 关着。
- 重点看自定义 `ContentProvider` 子类里重写了的 `openFile` / `query` / `getType`。

不打 APK 也能看到 authorities：

```bash
adb shell dumpsys package <pkg> | grep -A3 Provider
```

## 两个出口

### query() → SQL 拼接

危险参数是 `projection` / `selection` / `sortOrder` —— 它们常被直接摞进 SQL 串。
先用 `projection` 打一个**不完整的 SQL 片段**（一个 `"`），看回显：

```bash
adb shell content query --uri content://<authority>/ --projection '""'
# Drozer 同义：run app.provider.query content://<authority>/ --projection '""'
```

返回 `SqliteException` / `unrecognized token` / 半条 `SELECT` 语句 = 证据到手。
**报错原文比"存在注入"有力得多**：它同时给出了拼接位置和原始 SQL 形状，直接进报告根因链。

### openFile() → 路径穿越

危险写法是把 `uri.getPathSegments()` / `getLastPathSegment()` / `getPath()` 直接
`new File(base, seg)`，**不调** `getCanonicalPath()` 比对前缀。注意
`getLastPathSegment()` 内部会做一次 URL 解码，所以 `..%2F` 也能到。

```
content://<authority>/files/../../../../../../data/data/<pkg>/shared_prefs/<file>.xml
```

读回**内容**（哪怕一条 token）才算成立；只拿到 fd、只抛错，都不够。

## 判据

| 现象 | 算不算 |
|---|---|
| "Provider 导出且无权限" | 不算 —— 导出本身不是漏洞 |
| `openInputStream` 没抛异常 | 不算，要读到内容 |
| 报错里出现原始 SQL | 算，附原文 |
| 读回他人 token / 私有文件内容 | 算，写清读到了什么 |

## 纪律

- 只读。取证用 `projection` / `LIMIT`，不做 `UPDATE` / `DELETE` 验证。
- 报告写"读到了哪些字段"，不写"可以读"。
- 负控：同一 URI 去掉 `../` 必须正常返回，证明穿越序列是因果而不是巧合。

> 来源：SRC 报告集（Android Provider 多例，含 HackerOne 公开报告分析件）——原始报告在 `E:\Study\SRC`。
