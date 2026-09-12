# 多平台部署指南

SurfaceForge 支持 Windows / Linux / macOS 三平台部署。所有平台共用同一套 Python 代码，
通过统一入口 `surfaceforge.py` 调用。

## 快速开始（三平台通用）

```bash
# 1. 配置
cp .env.example .env
# 编辑 .env，填入 LLM_API_KEY 和 WebUI 密码

# 2. 环境检查
python surfaceforge.py doctor

# 3. 启动 WebUI
python surfaceforge.py webui

# 或一键完整扫描
python surfaceforge.py auto https://target.com --scope scope.json
```

---

## Windows

前置：Python 3.10+（推荐 3.11/3.12）

```powershell
# 方式 A：统一入口（推荐）
python surfaceforge.py webui

# 方式 B：PowerShell 脚本
.\run-webui.ps1
.\run-src-agent.ps1 -Scope scope.json -Blackboard out/src-blackboard.json
```

**启动脚本**：`run-webui.ps1`, `run-src-agent.ps1`, `run-src-autopilot.ps1`

**后台常驻**（Windows 服务）：
```powershell
# 用 NSSM 或任务计划程序
nssm install SurfaceForge "C:\Python311\python.exe" "E:\LLM\pentest-agent\surfaceforge.py webui"
```

---

## Linux

前置：Python 3.10+

```bash
# 方式 A：统一入口
python3 surfaceforge.py webui

# 方式 B：Shell 脚本
chmod +x run-webui.sh run-src-agent.sh
./run-webui.sh
./run-src-agent.sh --scope scope.json --blackboard out/src-blackboard.json
```

**systemd 常驻服务**：

```ini
# /etc/systemd/system/surfaceforge.service
[Unit]
Description=SurfaceForge WebUI
After=network.target

[Service]
Type=simple
User=surfaceforge
WorkingDirectory=/opt/surfaceforge
EnvironmentFile=/opt/surfaceforge/.env
ExecStart=/usr/bin/python3 surfaceforge.py webui
Restart=on-failure
RestartSec=10
# 安全加固
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/surfaceforge/webui-state /opt/surfaceforge/projects
MemoryMax=2G

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now surfaceforge
sudo journalctl -u surfaceforge -f
```

**Docker**（可选，隔离性最好）：

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd -m -u 1000 forge && chown -R forge:forge /app
USER forge
EXPOSE 8088
CMD ["python", "surfaceforge.py", "webui"]
```

```yaml
# docker-compose.yml
services:
  surfaceforge:
    build: .
    env_file: .env
    ports:
      - "127.0.0.1:8088:8088"
    volumes:
      - ./webui-state:/app/webui-state
      - ./projects:/app/projects
    mem_limit: 2g
    security_opt:
      - no-new-privileges:true
    read_only: false
```

---

## macOS

前置：Python 3.10+（`brew install python@3.12`）

```bash
python3 surfaceforge.py webui
./run-webui.sh
```

**launchd 常驻服务**：

```xml
<!-- ~/Library/LaunchAgents/com.surfaceforge.webui.plist -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.surfaceforge.webui</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/python3</string>
    <string>/path/to/surfaceforge.py</string>
    <string>webui</string>
  </array>
  <key>WorkingDirectory</key><string>/path/to/pentest-agent</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/tmp/surfaceforge.log</string>
  <key>StandardErrorPath</key><string>/tmp/surfaceforge.err</string>
</dict>
</plist>
```

```bash
launchctl load ~/Library/LaunchAgents/com.surfaceforge.webui.plist
```

---

## 多机部署架构

推荐演进路线（从简单到复杂）：

### 阶段 1：单机
```
一台机器跑全部：WebUI + SRC agent + SignalHarbor
```
适合自己用，最简单。

### 阶段 2：主控 + 执行分离（推荐）
```
主控机（本地/管理VM）
  ├─ WebUI（管理入口，SSH 隧道访问）
  ├─ 授权配置、私有 skill、完整报告
  └─ 审批服务
        ↓ 内网安全通道
执行机（VPS）
  ├─ SRC agent worker
  ├─ 短期任务、脱敏结果
  └─ 专用测试凭据（无主控密钥）
```

**关键**：执行机不放完整源码仓库、私有 skill、审批私钥、宿主 SSH 密钥、Docker socket。

### 阶段 3：多执行机
```
主控机 → 黑板（共享状态）→ N 个执行机
```
黑板通过 `core/src_blackboard.py` 的 claim/lease 机制协调，多 worker 消费不同 intent。

---

## 平台差异处理

| 项目 | Windows | Linux/macOS |
|------|---------|-------------|
| 路径分隔符 | 自动处理（`pathlib`） | 自动处理 |
| Python 命令 | `python` / `py -3` | `python3` |
| 后台服务 | NSSM / 任务计划 | systemd / launchd |
| 进程隔离 | 有限 | systemd 沙箱 / Docker |
| 文件权限 | ACL | chmod + 独立用户 |
| 出站控制 | Windows 防火墙 | iptables / nftables / netns |

代码层面对平台差异做了抽象：
- `core/config.py` 自动加载 `.env`（三平台一致）
- `core/model_client.py` 的 `exec_workdir()` 区分 `os.name == "nt"`
- `surfaceforge.py` 统一入口（三平台一致）

---

## 安全边界（所有平台适用）

1. 服务只监听 loopback（`127.0.0.1`），通过 SSH 隧道访问
2. 运行用户无 sudo、不在 docker 组
3. 状态目录独立可写，代码目录只读
4. 内存和任务时间有上限
5. 管理入口不暴露公网

详见 `docs/security-boundary.md`。
