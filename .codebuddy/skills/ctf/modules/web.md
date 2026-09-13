---
description: Web 题型作业规范：注入、包含、上传、SSRF、SSTI、XXE、反序列化、JWT、PHP 特性
---

# Web 题规范

## 侦察清单（先做完再动手）
- 响应头 `curl -I`、技术栈 `whatweb`、目录 `ffuf/dirsearch`
- 敏感文件：`/robots.txt` `/.git/HEAD` `/.svn/entries` `www.zip` `backup.sql`
- JS 里找隐藏接口：`grep -oE '"/api/[^"]+"' *.js`

## 分类检查表
- **SQLi**：注入点/闭合方式 → 库类型 → 注入类型（联合/报错/盲/堆叠）→ WAF 关键字 → 取数
- **XSS**：回显位置 → 上下文（HTML/JS/属性/URL）→ 过滤 → payload → CSP 绕过
- **命令执行**：拼接点 → 执行函数 → 空格/关键字/管道符绕过 → 反弹 shell
- **文件包含**：LFI/RFI → `php://filter` `php://input` `data://` → 日志/session 包含
- **文件上传**：前端校验 → MIME → 后缀（双写/大小写/特殊）→ 文件头 → 解析漏洞
- **SSRF**：协议（gopher/dict/file）→ 内网 → 绕过（短链/DNS/进制）→ 云元数据 `169.254.169.254`
- **SSTI**：引擎判别 `{{7*7}}`/`${7*7}`/`#{7*7}`/`<%=7*7%>` → 沙箱逃逸 → RCE
- **XXE**：XML 解析点 → `file:///etc/passwd` → OOB 外带 → 编码绕过（UTF-16/7）
- **反序列化**：格式 → 入口 → POP chain → 魔术方法 → `ysoserial`/`phpggc`
- **JWT**：算法（HS/RS/None）→ 弱密钥爆破 → RS→HS 混淆 → `kid`/`jku` 注入
- **PHP 特性**：弱类型 `==`、`extract`/`parse_str` 变量覆盖、`preg_replace /e`、伪协议

## 常用 payload 片段
```sql
' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--
' AND extractvalue(1,concat(0x7e,(SELECT database())))--
' AND IF(1=1,SLEEP(5),0)--
```
```bash
# 命令执行：空格/关键字绕过
cat${IFS}/etc/passwd ; c'a't /etc/passwd ; /???/c?t /etc/passwd
```
```php
php://filter/read=convert.base64-encode/resource=index.php
```

## 反套路
信息泄露（源码/配置/注释）→ 逻辑漏洞（越权/业务）→ 组合利用（多漏洞串联）。
