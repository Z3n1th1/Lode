# Lode Architecture

Lode is organized around one execution boundary and several read-only projections.
The boundary is deliberately small: a target request must pass scope, method/body
authorization, semantic action admission, request budget, rate limiting, and audit
logging before it can leave the process.

## Runtime Layers

```text
lode.py / Console API
        |
        v
job_registry + job_runner        durable lifecycle, stop, retry
        |
        v
agents.surface_discovery         low-frequency surface collection
agents.src_agent                 bounded analysis and route reflow
        |
        v
core.action_admission            semantic request gate
core.rate_limit + RequestBudget  speed and count limits
        |
        v
HTTP requester                   the only target egress
```

`intel/` is a separate public-information pipeline. It imports seeds, crt.sh,
ARL exports, feeds and optional platform providers; it does not share the active
SRC worker or silently turn an asset into a scan target. `console/projections.py`
reads durable files and never owns network execution.

## One Entry Point

Use `python lode.py` for CLI work and `python lode.py console` for the local UI.
The root `src_agent.py` and `src_autopilot.py` files are compatibility wrappers;
new features belong under `agents/`, `core/`, `intel/` or `console/`.

The normal flows are:

1. `scan`: surface discovery only.
2. `auto`: surface discovery, candidate triage, then bounded analysis.
3. `recon`: offline/public asset import and optional safe fingerprints.
4. Console: the same durable jobs and event log, with a read-only projection.

## Finding Workflow

Findings have stable IDs. Reports and retests are separate artifacts under the
same state/output roots. A retest can be `recorded`, `queued`, `running`, or
completed with `reproduced`, `fixed`, or `inconclusive`.

Automatic retests replay only a request that was already captured with its original
scope and response oracle. Missing material creates a manual record instead of a
guessed request. POST is allowed when the route/body proves a read operation; delete,
truncate, remove, drop, update, upload, credential, exfiltration and bulk-scan
semantics are rejected regardless of HTTP verb.

Only manual evidence can produce `fixed`, and it requires three distinct local
artifacts: original reproduction, current non-reproduction, and a passing normal
control. The original finding is never silently closed by a retest.

## State And Artifacts

Runtime state belongs under the selected state directory. A run keeps its scope,
blackboard, audit log and report references together. The repository contains code,
fixtures and docs; `node_modules`, build output, `tmp`, target outputs and local
state stay ignored.

This keeps the system understandable without weakening discovery: the same worker
can still extract routes, replay safe query POSTs, run ARL-derived fingerprints,
and analyze high-value findings while every request follows one policy path.
