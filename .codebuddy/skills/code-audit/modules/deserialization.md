---
description: 不安全反序列化 / 对象注入：按语言看 gadget 与触发点
---

# 反序列化

反序列化 = 用不可信字节流重建对象，常在重建过程中就执行了代码。

## 各语言触发点

| 语言 | 危险 API | 可用性 |
|---|---|---|
| Python | `pickle.loads` `yaml.load` `marshal.loads` `dill` | pickle 直接可 RCE |
| Java | `ObjectInputStream.readObject`、Fastjson/Jackson `enableDefaultTyping`、XStream、SnakeYAML | 依赖 gadget 链 |
| PHP | `unserialize` + `__wakeup`/`__destruct`/`__toString` | POP 链 |
| Node | `node-serialize` `unserialize`、`vm` 配合 | `_$$ND_FUNC$$_` 直接执行 |
| .NET | `BinaryFormatter`、`LosFormatter`、`TypeNameHandling.All` | gadget 链 |

## 判定顺序

1. **入口**：反序列化的数据是否外部可控（cookie、session、缓存、MQ、文件）。
2. **类型控制**：能不能在字节流里指定类名 / 类型（多态开启是关键）。
3. **gadget**：目标 classpath / 依赖里有没有可用链（`commons-collections`、`ysoserial` 思路）。
4. **触发**：链上的 `readObject`/`__wakeup`/`__destruct` 是否真的会被调用。

## 纪律

- 只做到"证明可控数据类型 / 存在可用链"；**不实际执行**反弹、不写文件。
- 把需要外部条件（依赖版本、需先构造某对象）写清楚，标注置信度。
