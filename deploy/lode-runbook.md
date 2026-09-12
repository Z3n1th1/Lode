# Lode / SignalHarbor VPS 运行手册

面向使用者的名字是 **Lode（Lode）** 和 **SignalHarbor（信号舱）**；源码兼容名仍是 `pentest-agent`、`intel`、`news`。

这里提供的是本地部署模板，不是已在你的 VPS 上完成的安全验收。systemd 配置、网络出口与实际运行效果还需要在目标服务器验证；不能承诺零漏洞、不会被反制或运行时可读源码绝不泄漏。

## SignalHarbor 长期采集

创建独立用户和目录，不要用 root 跑，也不要与 SRC 执行器共用 UID：

```bash
sudo useradd --system --home /opt/signalharbor --shell /usr/sbin/nologin signalharbor
sudo install -d -o root -g signalharbor -m 0750 /opt/signalharbor /etc/signalharbor
sudo install -d -o signalharbor -g signalharbor -m 0750 /var/lib/signalharbor
```

将独立运行代码安装到 `/opt/signalharbor`，不复制 SRC 的私有 skill、报告、审批私钥、SSH key 或现有 `.env`。安装固定版本依赖到 `/opt/signalharbor/.venv`，代码和虚拟环境保持 root 所有、服务账号只读。把 `sources.news.example.json` 复制为 `/etc/signalharbor/sources.news.json`，并设为 `root:signalharbor`、`0640`。独立资讯入口仅按这份公开 RSS/Atom 白名单采集，不再需要 SRC scope。不要把 API key 写进 registry 或 git。

安装 [signalharbor.service](./signalharbor.service) 和定时器：

```bash
sudo install -m 0644 deploy/signalharbor.service /etc/systemd/system/signalharbor.service
sudo install -m 0644 deploy/signalharbor.timer /etc/systemd/system/signalharbor.timer
sudo install -m 0600 deploy/signalharbor.env.example /etc/signalharbor/signalharbor.env
sudo systemctl daemon-reload
sudo systemctl enable --now signalharbor.timer
sudo systemctl start signalharbor.service  # 首次安装立即跑一轮
systemctl status signalharbor.timer
journalctl -u signalharbor.service -n 100 --no-pager
```

`signalharbor.service` 每 30 分钟执行一轮、有 10 分钟超时和 256 MiB 内存上限。没有 `DEEPSEEK_API_KEY` 时自动保留来源摘要，配置 key 后才调用 DeepSeek；key 只放 root 可读的 `EnvironmentFile` 或 systemd credential，不放命令行。只提交公开标题和摘要。飞书只用单向 notifier，默认不启用入站 Bot。需要通知时配置独立机器人凭据，并用 systemd override 在原 `ExecStart` 末尾明确增加 `--feishu`。

## Lode 自动 SRC

不要把所有域名交给 worker。每个项目先写书面授权 scope，明确 `allowed_domains/allowed_hosts`、速率、超时和禁止项；再由 `src_surface.py` 做低频 GET，`src_autopilot.py` 只做候选分诊。多个 worker 通过 `src-blackboard.json` 的 claim/heartbeat/finish 协调，单个 intent 只有一个租约。

真正的验证 runner 必须在执行前再次检查 TargetCard digest、scope digest、action policy 和物理 egress allowlist。没有 runner、没有物理出站确认或 guardrail 返回 `need_human/forbid` 时必须停止。

## VPS 安全基线

- SSH 只开放密钥登录、禁用 root 密码登录；Console 和 webhook 只绑定 loopback，通过固定 upstream 的 TLS 反代和 IP allowlist访问。
- `signalharbor` 和 SRC worker 使用不同的非 sudo UID，各自独立状态目录；不要把宿主 SSH key、Docker socket、云平台凭据或整个宿主文件系统挂进 worker。
- 用 UFW/nftables 或云安全组限制出站；SRC 目标必须是授权清单，不能用 `0.0.0.0/0` 代替白名单。
- 每周检查 `systemctl status`、磁盘占用、journal 大小、失败 provider、watch state 和 runner blocked 记录；配置 logrotate，避免无限日志。
- 备份 scope、黑板和审计索引，不备份 token、cookie、完整报告到第三方云盘。

## 反制与源码边界

只读挂载防止代码被篡改，不阻止进程读取代码。运行时可读源码、模型上下文里的私有 skill 和凭据都不能靠提示词保证不外泄。保密逻辑应留在主控侧，执行 worker 仅获得当前任务所需的最小授权资料，不挂载完整 skill 库或历史报告。

建议 SRC 执行 worker 与主控、私有 skill、报告和审批签名私钥分机。worker 视为可能被恶意响应、文档或第三方工具攻陷：不用 root、不授予 sudo、禁用 Docker socket、限制资源、任务结束可重建；审批签名只能由隔离的主控签发。

应用 URL 检查是第一道门，不替代物理出站隔离。需要在宿主防火墙或独立出口网关验收：只允许登记来源/授权目标，阻断私网、loopback、云 metadata 和未授权 DNS/协议，并检查重定向和 DNS 变化。Clash Fake-IP 不应通过放宽私网校验解决。信号舱的 RSS、DeepSeek 和飞书出口与 SRC 目标出口分开管理；没有完成这项验收，不宣称已具备防外发能力。

在 VPS 上先运行 `systemd-analyze verify /etc/systemd/system/signalharbor.service /etc/systemd/system/signalharbor.timer`，再验证采集、摘要、通知及出站拒绝日志。`systemd-analyze security signalharbor.service` 的评分只代表配置检查，不能代替渗透/逃逸或业务数据保护测试。

## 写操作规则

当前默认策略是只读。DELETE、语义 delete/update、支付/短信/邮件/权限/回调、跨租户和未知 POST 都会升级到人工门；自建对象的可逆 modify 也必须有签名 ledger。自动化只证明影响，不修改他人业务数据，不注销、不登出、不爆破。
