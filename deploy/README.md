# deploy/ 部署区

- docker-compose（容器化、restart:always、healthcheck）
- wireguard/ mesh 配置（agent/console 仅 mesh 可达）
- self-check.sh 基线检查：公网暴露端口/容器权限/依赖CVE/秘钥泄露/日志权限
- 纪律：一切服务 bind 127.0.0.1；Console 仅 bind mesh 接口

## 监听与管理约束

- 业务服务默认使用 `127.0.0.1`、`::1` 或 Unix socket。loopback 不替代认证：每个管理接口仍需要独立的强凭据、最小权限服务用户和审计。
- SSH 是唯一默认公网例外。新增任何 `0.0.0.0`/`::` listener 前必须有 ChangeCard、端口验收、告警和可恢复发布记录。
- 需要远程管理时，使用成熟 HTTPS reverse proxy 将**登记的单个** loopback upstream 暴露为固定 route。禁止把它配置为可访问任意主机/端口的 forward proxy。
- 管理反代上线最低要求：TLS、bcrypt/Argon2 password hash、独立强账号、source IP allowlist、速率限制、访问审计和固定 upstream allowlist。无已登记 upstream 时不部署反代。
- 2026-08-11 已验证 `pa-feishu-reply.service` 使用 `pa-agent`、systemd hardening、512 MiB memory cap、50% CPU cap 和 120 秒 watchdog；具体证据见 `../../docs/Agent运行与VPS验收快照_2026-08-11.md`。
