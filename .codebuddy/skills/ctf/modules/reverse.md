---
description: 逆向题型规范：静态分析、动态调试、算法还原
---

# 逆向规范

## 侦察
```bash
file ./chall ; checksec ./chall            # 架构 / 保护
strings -n 6 ./chall | head -50            # 明文字符串线索
rabin2 -zz ./chall ; nm -C ./chall
```
识别语言/框架：Go（`Go build ID`）、Rust（panic 串）、.NET（`mscoree`）、
Python 打包（`PyInstaller` → `pyinstxtractor`）。

## 静态
- 反编译主流程：`main` → 输入读取 → 校验函数 → 成功/失败分支。
- 把校验逻辑翻译成伪代码，**标注每个常量与比较**。
- 常见形态：逐字符比较、异或/加减变换、查表置换、CRC/哈希校验、魔改 base64。

## 动态
```bash
gdb -q ./chall -ex 'b *main' -ex run
ltrace -f ./chall ; strace -f ./chall
```
用 `LD_PRELOAD` 钩住 `strcmp`/`memcmp` 直接打印期望值，往往一步出答案。

## 算法还原
1. 把变换写成可运行的 Python（输入 → 输出）。
2. 用已知输入/输出对验证。
3. 求逆（逐字符，或 z3 求解）：`z3.Solver()` 建模每个字节。
4. 输出 flag。

## 交付
还原脚本 + 关键变换说明 + 验证过的 flag。
