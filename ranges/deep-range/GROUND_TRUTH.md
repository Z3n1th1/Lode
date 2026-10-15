# Deep range — ground truth

A **narrow and deep** fixture: the crawl surface is a single link, every seed probe
404s, and the reportable finding sits behind a four-step, response-dependent chain.

Why it exists: on `ranges/lode-range` the JSON explorer beat tool mode, and the
mechanism was *breadth* — it visited 18 intents against 6. That says nothing about a
target where breadth is unavailable. Here the only variable left is **how many
adaptation rounds a run allows**: JSON mode gets two (`MAX_HTTP_ACTIONS` × 2 rounds),
tool mode gets one per fetch.

```bash
"D:/Environment/Python/miniforge/envs/py310/python.exe" ranges/deep-range/app.py --port 8792
```

## The chain

| step | request | what it gives you | needs the previous response? |
|---|---|---|---|
| 1 | `GET /api/invoice?id=1001` | an invoice, plus `links.recent` → `/api/invoices?limit=5` | no |
| 2 | `GET /api/invoices?limit=5` | a list; **id 1042 is `tenant=acme-corp`** and carries `docs[0].url = /api/export?token=AUDIT-7f3a` | **yes** — the token appears in no other record |
| 3 | `GET /api/export?token=AUDIT-7f3a` | `400 {"error":"tenant scope required","param":"tenant"}` | **yes** — needs the token from step 2 |
| 4 | `GET /api/export?token=AUDIT-7f3a&tenant=acme-corp` | **the finding**: settlement account + `api_key: ledger_sk_live_…` | **yes** — needs both the token and the named parameter |

Steps 2 and 4 cannot be planned from the first response, which is the whole point.

> **Design correction (2026-09-25).** The first cut had only `meta.from/to` (1000–1099)
> and no list endpoint, so the cross-tenant record at id 1042 was reachable solely by
> brute-forcing ~43 requests. Across 10 runs of json and tools modes, neither got past
> **10** ids and the chain was never entered — the fixture tested nothing. It now
> advertises the next hop through `links.recent`, which keeps every hop
> response-dependent without making any of them a guessing game.

## What counts, and how it is measured

Two separate metrics, because a binary pass/fail hides the difference:

- **Chain depth reached (0–4)** — was each hop requested? Read it straight off
  `http-actions.jsonl`: the presence of `/api/invoice?id=1042`, `/api/export?token=`,
  and an `/api/export?...&tenant=` on the same URL as the token.
- **Shallow finding** — every invoice carries `subject_ssn`, so the one-step
  unauthenticated PII read is reachable without any chain. It is there so a run that
  stops at step 1 still scores something and the comparison is not a floor effect.

## Deliberate design notes

- **The 400 names the missing parameter.** `{"error":"tenant scope required","param":"tenant"}`
  is the API being honest about its own contract, not a hint planted for the hunter —
  and it is the affordance that makes step 4 discoverable at all.
- **No `robots.txt`, no JS bundle, no API index.** Anything that helps discovery would
  reintroduce the breadth dimension this fixture exists to remove. The 16 seed probes
  all 404, which is itself part of the measurement (a real fixed cost on a target with
  nothing to find).
- **`X-Total-Count` and `meta.from/to`** are how a real list endpoint advertises an
  enumerable id space; without one of them, enumeration would be guessing rather than
  reading.
- **The ids are not a simple increment.** Only 1000–1099 exist and only one of them is
  cross-tenant, so a run has to actually walk the space rather than assume `1042`.
