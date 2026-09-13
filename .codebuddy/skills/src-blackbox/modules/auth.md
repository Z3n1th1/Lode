---
description: 认证与会话：JWT、OAuth、找回密码、会话固定
---

# 认证与会话

## JWT
- 解码看 `alg`/`kid`/`exp`；检查是否接受 `alg:none`。
- HS/RS 混淆：用公钥当 HMAC 密钥伪装签名。
- `kid` 注入（路径穿越 / SQL）、`jku`/`x5u` 指向可控地址。

## OAuth / SSO
- `redirect_uri` 校验：是否允许任意子域、路径穿越、`@` 绕过。
- `state` 缺失 → CSRF 绑定风险。

## 找回密码 / 验证码
- 响应差异（用户存在性）、token 可预测、有效期过长、可重放。
- 验证码无频率限制 → 只记录，**不做**暴力破解（违反纪律）。

## 会话
- Cookie 属性（HttpOnly/Secure/SameSite）、登录后是否固定、登出是否失效。
- 权限提升：普通用户 token 能否访问管理端点（GET 探）。

## 纪律
认证缺陷通常高危，证据要精确到请求响应；不要改动他人账号状态。
