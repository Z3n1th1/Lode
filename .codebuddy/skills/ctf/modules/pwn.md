---
description: Pwn 题型规范：栈/堆、格式化字符串、ROP、沙箱逃逸
---

# Pwn 规范

## 必做前置
```bash
checksec ./chall       # RELRO / Canary / NX / PIE
```
决定一切：Canary（能否泄露出）→ NX（shellcode vs ROP）→ PIE（是否需先泄露基址）。

## 常见类型
- **栈溢出**：算偏移（`cyclic(200)` → 崩溃地址反查 `cyclic_find`）→ 覆盖 ret → ROP。
- **ret2libc**：泄露 `puts@got` → libc 基址 → `system("/bin/sh")`。
- **格式化字符串**：定位偏移（`%p` 序列）→ 任意读（泄露）→ 任意写（改写 GOT/返回地址）。
- **堆**：识别 tcache/fastbin 行为 → UAF / double free → 改写 fd 指针。

## 模板
```python
from pwn import *
elf = ELF('./chall'); libc = ELF('./libc.so.6')
p = process('./chall')            # or remote('host', 1234)
rop = ROP(elf)
# 两段式：先泄露，再二次利用
p.recvuntil(b'>')
leak = int(p.recvline().strip(), 16)
libc.address = leak - libc.symbols['puts']
```

## 纪律
- 每次交互 `recvuntil` 到确定锚点再发送，不要 `sleep` 赌时序。
- 本地先跑通再打远程；保留 `context.log_level='debug'` 开关。
- 沙箱：`seccomp-tools dump ./chall`，确认可用 syscall 再选 ORW。
