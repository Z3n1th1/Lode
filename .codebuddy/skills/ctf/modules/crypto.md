---
description: Crypto 题型规范：古典密码、RSA 各类攻击、椭圆曲线、分组模式
---

# Crypto 规范

## 先分类
拿到就三问：**对称？非对称？编码？**
- 大整数 + `n e c` → RSA
- 椭圆曲线参数 → ECC
- 定长二进制块 → AES/DES（看模式 ECB/CBC/CTR）
- 可打印字符集 → 编码/古典

## RSA 检查顺序
1. 分解 `n`：太小 → `factordb`/`sympy.factorint`；`p≈q` → Fermat；多组 `n` 共享素因子 → GCD。
2. 小指数：`e=3` 且 `m^e<n` → 直接开方；否则 Hastad 广播攻击。
3. 共模：同 `n` 不同 `e` → 扩展欧几里得。
4. 低私钥指数（Wiener）、`d` 泄露、`phi` 泄露。
5. 填充/预言机：Bleichenbacher、CBC padding oracle。

```python
from Crypto.Util.number import long_to_bytes, inverse
from sympy import factorint
```

## 分组模式
- ECB：相同明文块 → 相同密文块（找重复块 → 逐字节爆破）。
- CBC：字节翻转改明文；固定 IV 时做块重排。
- CTR：nonce 重用 → 明文异或破解。

## 纪律
所有变换写成脚本并保留中间量；结论必须能被脚本复现，不靠猜。
