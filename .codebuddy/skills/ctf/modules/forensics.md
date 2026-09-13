---
description: 取证题型规范：文件指纹、隐写、流量分析、内存/磁盘取证
---

# 取证规范

## 文件指纹（永远第一步）
```bash
file target ; binwalk target ; exiftool target
strings -n 8 target | less ; xxd target | head
```
- 熵异常高 → 加密/压缩嵌套；`binwalk -e` 解嵌套。
- 图片：查尾部附加数据、`zsteg`/`steghide`/`pngcheck`、LSB（`stegsolve`）。
- 压缩包：`zip2john` 爆破，或伪加密（改 flag 位）。

## 流量分析
```bash
tshark -r cap.pcap -Y http -T fields -e http.request.uri
tshark -r cap.pcap -qz follow,tcp,ascii,0
```
- 提取对象：Wireshark `File → Export Objects`，或 `tcpflow`。
- 常见：HTTP 传文件、DNS 隧道（看超长子域）、ICMP 载荷、明文凭据。

## 内存/磁盘
- 内存：`volatility3 -f mem.raw windows.info` → `pslist`/`filescan`/`dumpfiles`。
- 磁盘：`mmls`/`fls`/`icat`（Sleuth Kit），或挂载后看浏览器历史/回收站。

## 交付
提取链（哪一步拿到什么）+ 复现命令 + flag。
