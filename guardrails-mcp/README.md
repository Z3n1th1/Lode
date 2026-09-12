# guardrails-mcp

护栏只此一份。**包壳(wrap)现有 `skills/ai-pentest-matrix/scripts` + 红队加固的动作策略层**，作为渗透 agent 唯一的 L7 策略大脑。基座无关(Strix/pentestagent 都调它)，纯 Python，本机可开发+跑单测。

## 5 个 tool（`guardrails/tools.py` = 单一实现，`server.py` 只做 MCP 适配）
| tool | 状态 | 说明 |
|---|---|---|
| `policy_grade` | ✅ 全实现+单测 | base `evaluate_action`(A0..F0) + 红队加固 `action_policy.refine` |
| `human_gate` | ✅ 全实现(fail-closed) | 无外部审批权威 → HARD-BLOCK(不是"可确认")；对应 approval_decision fail-closed |
| `gateway_request` | ⚙️ 委托 | policy_grade 预门 + 委托 `request_gateway.gateway_run`；物理出站由部署层保证 |
| `record_evidence` | ⚙️ 委托 | 委托复用的证据层(gateway 产 request-response pair) |
| `verify_finding` | ⚙️ 委托 | 委托 `verify_finding.verify`；生产必须换不同模型(model_policy) |

## 动作门策略（红队后收紧，`action_policy.refine`）
- **base 分级永不被削弱**：F0/forbid 保持；危险信号/共享态只能**升**到 need_human。
- **唯一放松是窄口子**：把 base 的 `need_human` 转 `allow_limited`，且仅当 operator 证明：
  - 新增(POST)：endpoint 在 **operator 只读白名单**(`config/inert_surface_allowlist.yaml`) + 写入**预置测试 principal**；
  - 修改(PUT/PATCH)：`hardened_ledger.is_owned_strict` 五条件全过(server-minted+MAC+租户/集合一致+指纹 read-before-write 匹配) 且不触共享态。
- **一律 need_human**：DELETE；body 含 URL/webhook/callback(SSRF/exfil，逃逸 netns)；role/token/admin(提权/发凭据)；payment/sms/email/bind 等 MUST_CLEANUP 关键词(不可逆副作用)。
- **"良性/自建"绝不读 agent 自称字段**（否则 = `_approval_verified` 后门重生）。

## 信任模型（agent 只读，operator 拥有）
- `config/inert_surface_allowlist.yaml`、hardened ledger 都是 **operator-owned、agent read-only**。
- 生产:HMAC 签名(`GUARDRAILS_CONFIG_HMAC_KEY` / `GUARDRAILS_LEDGER_HMAC_KEY`，密钥容器外)+ 独立 uid 只读挂载。缺/伪造/未签名(prod) → 什么都不 auto(fail-closed 到人工门)。

## 本机 vs VPS（诚实边界）
- **本机(此包)**：L7 策略大脑 —— policy_grade/ledger/scanners，纯 Python，`pytest tests/` 全绿。
- **VPS/部署层(不在此包)**：**物理强制**——容器 `--network none` + nftables DROP、本包作为 L7 MITM 代理的**唯一出站**、mihomo 在其后独立 netns、operator 签名只读配置的独立 uid、真实外部审批签发者。**这些不物理成立，策略大脑只是"被调用时才生效"，仍可被绕**(见 `docs/agent策略修订_物理强制与动作门放松安全落地_红队后_2026-08-07.md`)。

## 运行
```
python -m pytest tests/ -q          # go/no-go 验收(红队场景必须被拦)
python server.py                    # stdio MCP server(需已装 mcp SDK)
# 可选: export PENTEST_MATRIX_SCRIPTS=<path> 显式指定被包壳的 scripts 目录
```

## go/no-go 验收含义（`tests/test_guardrails_acceptance.py`）
create-webshell→forbid；create-admin/webhook/payment→need_human(即便自称 benign)；仅 allowlist+预置 principal 的良性 create→allow_limited；modify 仅证明自建→allow_limited，否则(不在 ledger/指纹不符/共享态/伪造 MAC)→need_human；delete→need_human；GET→allow；human_gate→hard_blocked。
