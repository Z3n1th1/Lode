# Lode 使用说明

AI 驱动的 SRC 漏洞挖掘平台。三种使用方式：Console 对话、命令行、后台常驻。

---

## 0. Python 环境（重要）

本项目需要 **Python 3.10+**。你的机器上有 miniforge 多环境：

| 环境 | 版本 | 状态 |
|------|------|------|
| `D:\Environment\Python\miniforge\envs\py310` | 3.10.17 | ✅ 推荐（依赖齐全） |
| `D:\Environment\Python\miniforge\envs\py313` | 3.13.3 | ✅ 可用 |
| `D:\Environment\Python\miniforge\envs\py38` | 3.8.20 | ⚠️ 过旧，部分功能报错 |

**设置默认 Python**（Windows）：
```powershell
# 永久生效
setx PA_PYTHON "D:\Environment\Python\miniforge\envs\py310\python.exe"
```
或者只对当前终端生效：
```powershell
$env:PA_PYTHON = "D:\Environment\Python\miniforge\envs\py310\python.exe"
```

所有启动脚本会自动优先用 `PA_PYTHON`。

---

## 1. Console 方式（推荐日常用）

### 启动

**Windows:**
```powershell
cd E:\LLM\pentest-agent
$env:PA_PYTHON = "D:\Environment\Python\miniforge\envs\py310\python.exe"
.\run-console.ps1
```

**Linux / macOS:**
```bash
cd /path/to/pentest-agent
export PA_PYTHON=python3
./run-console.sh
```

**通用（三平台一致）:**
```bash
python lode.py console
```

### 访问

浏览器打开 `http://127.0.0.1:8088`
- 密码在 `.env` 的 `LODE_ADMIN_PASSWORD`
- 只监听本地，不暴露公网

### 对话流程

在 Console 里跟 agent 对话，例如：

```
你: 帮我测 www.zomato.com，H1 Eternal 项目，scope 是 zomato.com 和 blinkit.com
Agent: [调用 scan_target] 发现 4 个候选端点...
       要不要继续深度分析？
你: 继续
Agent: [调用 run_agent_analysis] 分析完成，结果...
```

也可以直接说：
```
你: 全自动跑一遍 www.zomato.com
Agent: [调用 auto_scan] 扫描→分析→报告，一条龙
```

---

## 2. 命令行方式（适合脚本/批量）

### 环境检查
```bash
python lode.py doctor
```
输出 Python 版本、平台、API key 状态、模块加载状态。

### 单站扫描
```bash
python lode.py scan https://www.zomato.com --scope scope-eternal.json --out-dir ./out
```

### 全自动
```bash
python lode.py auto https://www.zomato.com --scope scope-eternal.json --out-dir ./out
```
依次执行：表面发现 → 候选分诊 → LLM 分析 → 输出结果。

### LLM agent 循环
```bash
python lode.py agent ./out/src-blackboard.json --scope scope-eternal.json --max-cycles 20
```

### 查看进度
```bash
python lode.py progress --state-dir ./lode-state
```

### 列出会话
```bash
python lode.py sessions
```

### 继续上次会话（中断后续跑）
```bash
python lode.py resume src-c55cac7edd68 --scope scope-eternal.json
```
黑板状态持久化，进程挂了也能接着跑。

---

## 3. 后台常驻方式（VPS 长跑）

### Linux systemd
```ini
# /etc/systemd/system/lode.service
[Unit]
Description=Lode Console
After=network.target

[Service]
Type=simple
User=lode
WorkingDirectory=/opt/lode
EnvironmentFile=/opt/lode/.env
Environment=PA_PYTHON=/usr/bin/python3
ExecStart=/usr/bin/python3 lode.py console
Restart=on-failure
RestartSec=10
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/opt/lode/lode-state /opt/lode/projects
MemoryMax=2G

[Install]
WantedBy=multi-user.target
```
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now lode
sudo journalctl -u lode -f
```

### macOS launchd
见 `deploy/multi-platform.md`。

### Windows NSSM
```powershell
nssm install Lode "D:\Environment\Python\miniforge\envs\py310\python.exe" "E:\LLM\pentest-agent\lode.py console"
nssm set Lode AppDirectory "E:\LLM\pentest-agent"
nssm start Lode
```

---

## 4. 配置（.env）

所有配置集中在项目根目录 `.env`：

```ini
# LLM
LLM_API_KEY=sk-xxxxx
LLM_BASE_URL=https://api.deepseek.com
LLM_MODEL=deepseek-flash

# Console
LODE_ADMIN_PASSWORD=至少16字符
LODE_SESSION_SECRET=至少32字符
LODE_PORT=8088

# SRC agent 默认值
SRC_MAX_CYCLES=20
SRC_MAX_EXPLORE=3
SRC_DELAY_SECONDS=1.0
```

**无需每次手动设环境变量**，启动时自动加载。

---

## 5. 项目目录约定

每个 H1 项目一个文件夹：
```
projects/
  eternal-h1/
    project.json             项目配置（scope、赏金、campaign）
    www.zomato.com.md        站点测试记录
    www.blinkit.com.md       另一个站点
    runs/                    每次运行输出
```

**站点 md 记录什么**：
- 测试进度（哪个阶段完成）
- 已发现端点（status、结果）
- Findings（漏洞、证据、置信度）
- 待测试项
- 阻塞项和笔记

---

## 6. 常见问题

**Q: Console 打不开？**
检查 `http://127.0.0.1:8088/healthz` 是否返回 `{"status":"ok"}`。端口被占用改 `.env` 的 `LODE_PORT`。

**Q: Agent 说 "LLM unavailable"？**
检查 `.env` 的 `LLM_API_KEY` 是否正确，`python lode.py doctor` 看 `llm_api_key_set`。

**Q: 扫描没结果？**
目标可能有 WAF（如 Cloudflare），基础 fetcher 会 403。需要更强 HTTP client 或手工加候选。

**Q: 能直接上 VPS 跑吗？**
可以，但注意安全边界。执行机不要放主控源码/私钥。详见 `docs/security-boundary.md`。

**Q: 会不会改目标数据？**
不会。只发 GET/HEAD，语义写操作（delete/update/pay/send）在发送前拦截。无 shell 工具。
