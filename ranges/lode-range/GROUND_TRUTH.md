# Lode range — ground truth

A local, self-owned target with **12 deliberately planted bugs**. The point is to
grade a Lode run against a known list instead of guessing whether "0 findings"
means a broken tool or a barren target.

Run it, then check each item by hand:

```bash
"D:/Environment/Python/miniforge/envs/py310/python.exe" ranges/lode-range/app.py --port 8791
curl -s http://127.0.0.1:8791/.env | head
```

Every bug below is reachable **unauthenticated with GET** — the same posture the
Lode hunter has (`agents/src_agent.py:644` gates each request through
`scope.check_url`, and the default scope permits only GET/HEAD).

| # | Bug class | Request | Expected evidence | Severity |
|---|---|---|---|---|
| 1 | Exposed VCS metadata | `GET /.git/config` | `remote url` with embedded `deployer:S3cretDeploy@` credentials | high |
| 2 | Exposed secrets file | `GET /.env` | `DATABASE_URL`, `STRIPE_SECRET_KEY`, `AWS_*` in plaintext | high |
| 3 | Exposed DB dump (autoindex) | `GET /backup` → listing → `GET /backup/users.sql` | `password_hash` values for 3 users | high |
| 4 | Unauthenticated admin console | `GET /admin` | 200 + "Admin console", links to user records | medium |
| 5 | Reflected XSS | `GET /search?q=<script>alert(1)</script>` | payload echoed unescaped into the HTML | medium |
| 6 | SQL injection | `GET /api/v1/products?q='` | 500 + `sqlite3.OperationalError` + `[db] <path>` — injection error with a filesystem path in it | high |
| 7 | IDOR / broken access control | `GET /api/v1/users/1` | `password_hash`, `api_key`, `ssn` for an admin, **no auth required**; `/2`, `/3` enumerate | high |
| 8 | IDOR on orders | `GET /api/v1/orders?user_id=2` | another user's shipping address + `card_last4` | high |
| 9 | SSRF | `GET /api/v1/fetch?url=http://127.0.0.1:8791/internal/credentials` | server-side fetch returns `billing` DB DSN + AWS keys from an internal-only endpoint | high |
| 10 | Path traversal | `GET /api/v1/files?name=../../../../etc/passwd` | returns `/etc/passwd` contents | high |
| 11 | Debug endpoint exposure | `GET /api/v1/debug/config` | `secret_key`, `stripe_key`, `internal_hosts` | high |
| 12 | CORS misconfiguration + secret leak | `GET /api/v1/internal/metrics` | `Access-Control-Allow-Origin: *` together with `Allow-Credentials: true`, and the DB DSN + AWS keys in the body | medium |

## Discovery chain (what makes this findable, not just vulnerable)

The range is built so the hunter can actually *reach* the bugs — the failure mode
that wasted the NBA runs was an unreachable surface, not a missing bug:

- `/robots.txt` disallows `/admin`, `/backup`, `/api/internal`, `/.git` — so a
  crawler that reads robots is handed the interesting paths. `/backup` answers
  with an autoindex listing, so the dump is one hop away rather than a guess at a
  filename. `/.env` is deliberately **not** in robots: nothing links to it, which
  is why it has to come from the seed-probe list instead of from extraction.
- `/static/app.js` declares `const API_BASE = "/api/v1";` **and** contains
  literals that already start with it (`/api/v1/users/`, `/api/v1/fetch?url=`,
  `/api/v1/files?name=`, `/api/v1/debug/config`, `/api/v1/internal/metrics`) —
  which is what the base-join rule in `agents/surface_discovery.py` requires, so
  the JS yields real endpoints instead of a manufactured 404 family.
- `/api` self-describes the endpoint list.
- The landing page carries a real search form (`action="/search"`) **and** two
  parameterised links (`/search?q=jersey`, `/search?q=cap`). Both matter: without
  a link there is no signal to extract, and without a visible `?q=` there is no
  parameter shape for the hunter to inject into. Before 2026-09-25 the page had
  neither, so bug 5 was unreachable by construction and read as a tool miss —
  the same shape as `/.env`, and a fixture bug rather than a product one.
- `/api/v1/debug/config` and `/api/v1/internal/metrics` name `10.0.3.14` —
  a live host is never mentioned, so no request ever leaves this machine.

## Two honest caveats

- **Bug 9 is a real forgery, bug 9's metadata path is not.** `/api/v1/fetch`
  genuinely calls `urllib.request.urlopen()` server-side and the
  `/internal/credentials` endpoint it can reach is a real internal-only route on
  the same app. But the `169.254.169.254` branch returns a canned IMDS response,
  because that address is unreachable from a sandbox — the stub is labelled as
  such in `app.py` so nobody mistakes it for a live cloud call.
- **Missing security headers are not listed as a bug.** Every response omits
  `X-Content-Type-Options` / `X-Frame-Options` / `HSTS` / CSP. A hunter will
  probably report it as informational; it does not count toward the 12 above,
  since most programs accept it only with a demonstrated impact.
