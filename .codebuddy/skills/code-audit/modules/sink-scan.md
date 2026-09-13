---
description: 危险操作（sink）枚举：按语言列出命令执行、反序列化、模板、SQL、文件、SSRF
---

# Sink 枚举

先建立"危险点"清单，作为后续污点追踪的目标集合。

## 通用高危 sink

| 类别 | 关键词 |
|---|---|
| 命令执行 | `os.system` `subprocess.*` `exec` `eval` `popen` `Runtime.exec` `child_process.exec` `sh -c` |
| 代码/表达式 | `eval` `exec` `Function(` `vm.runInContext` `compile` `ExpressionLanguage` |
| 反序列化 | `pickle.loads` `yaml.load`(非 safe) `ObjectInputStream` `unserialize` `node-serialize` `marshal` |
| 模板 | Jinja2 `from_string`/`Template` `Twig` `Freemarker` `Velocity` `Handlebars.compile` |
| SQL | 字符串拼接进 `execute`/`query`；`text()` 拼串；ORM `raw`/`extra` |
| 文件 | `open` `readFile` `send_file` `download` `include` `require` `File(`+路径拼接 |
| SSRF | 用请求参数拼 URL 的 `requests.*` `axios` `fetch` `HttpClient` `urlopen` |
| 路径穿越 | 拼接后未 `realpath` 校验前缀的路径操作 |
| XXE | 开启外部实体的 XML 解析器（`etree.parse` 未禁 DTD 等） |

## 排优先级

候选 sink 按"离入口的距离 + 参数可控性"排序：
- 直接接收请求参数 → 最高优先。
- 经一层封装/工具函数 → 次高（可能是全站共用入口）。
- 常量或内部生成 → 最低，除非能证明可控。

## 注意

- 框架的"安全封装"要先确认是不是真的安全（很多是 thin wrapper）。
- 同一 sink 可能有多条入口，先挑最短路径验证可达性。
