"""guardrails-mcp — the single guardrails layer for pentest-agent.

WRAP, don't rewrite: this package reuses the battle-tested gates already in
``skills/ai-pentest-matrix/scripts`` (policy_engine / request_gateway /
verify_finding / created_resources / cleanup_plan / trust_chain) and layers on
top the red-team-hardened action policy (2026-08-07 策略修订):

- "benign / self-created" is NEVER an agent-asserted field — only proven by an
  operator-owned inert-surface allowlist + a MAC-bound created-resource ledger.
- deterministic body/value scanners force URL/webhook, role/token, and
  payment/sms/state-change creates to the human gate regardless of intent prose.
- ownership only ever ADDS need_human; it never downgrades a base F0/H2.

Physical enforcement (netns / L7 MITM egress / operator-signed read-only config)
is a VPS/Linux deploy concern — see ../README.md and
docs/agent策略修订_物理强制与动作门放松安全落地_红队后_2026-08-07.md. This package
is the L7 policy brain that the MITM proxy calls; it is developed and unit-tested
here (pure Python), but is only *physically* enforced once it is the sole egress.
"""
