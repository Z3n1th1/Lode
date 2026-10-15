#!/usr/bin/env python3
"""Lode test range — a deliberately vulnerable, self-owned target.

Purpose: give the Lode hunter a target whose ground truth we control, so a run
can be graded (found / missed) instead of guessed at. Every bug here is planted
on purpose and listed in GROUND_TRUTH.md.

Scope of intent — this is a LOCAL fixture. It binds 127.0.0.1 only, it is not
meant to be exposed, and its "internal" endpoints exist purely so the SSRF and
traversal bugs return something real instead of canned strings.

    python app.py --port 8791

Stdlib only, so it runs on the same py310 interpreter as Lode.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# --------------------------------------------------------------------------
# Fake data. Shaped like a real small shop API so the hunter has something to
# reason about — the pollution is deliberate: secrets in .env, hashes in the
# user records, an internal service reachable only from the server side.
# --------------------------------------------------------------------------

DB_PATH = "/srv/lodeshop/var/lodeshop.sqlite3"

USERS = {
    "1": {"id": 1, "email": "admin@lodeshop.local", "role": "admin",
          "password_hash": "$2b$12$Q9k4xAMPLEhashAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          "api_key": "lsh_sk_live_9f3c1d7a44e8b2", "ssn": "123-45-6789"},
    "2": {"id": 2, "email": "ops@lodeshop.local", "role": "staff",
          "password_hash": "$2b$12$Kd8ZzEXAMPLEhashBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
          "api_key": "lsh_sk_live_5b1a0c92fe77d3", "ssn": "987-65-4321"},
    "3": {"id": 3, "email": "vendor@example.com", "role": "vendor",
          "password_hash": "$2b$12$Mf2QqEXAMPLEhashCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
          "api_key": "lsh_sk_test_00112233445566", "ssn": "555-01-0000"},
}

PRODUCTS = [
    {"id": 1, "name": "Home Jersey", "price": 89.99, "stock": 120},
    {"id": 2, "name": "Away Jersey", "price": 89.99, "stock": 34},
    {"id": 3, "name": "Court Shorts", "price": 44.50, "stock": 210},
    {"id": 4, "name": "Retro Cap", "price": 29.00, "stock": 0},
]

INTERNAL_CREDENTIALS = {
    "service": "lodeshop-billing",
    "db_dsn": "postgres://billing:B1llingP@ss@10.0.3.14:5432/billing",
    "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
    "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
}

# The payload the SSRF test wants — a real metadata service would answer this.
# Kept as a canned response because 169.254.169.254 is not reachable from a
# sandbox, and a target that "times out" looks like a dead end instead of a bug.
METADATA_STUB = {
    "Code": "Success",
    "Type": "AWS-HMAC",
    "AccessKeyId": "ASIAIOSFODNN7EXAMPLE",
    "SecretAccessKey": "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789EXAMPLE",
    "Token": "IQoJb3JpZ2luX2VjEBcEXAMPLE...",
    "Expiration": "2026-09-26T04:00:00Z",
}

INDEX_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>LodeShop</title>
<link rel="stylesheet" href="/static/site.css"></head>
<body>
<h1>LodeShop</h1>
<p>Equipment for people who take the game seriously.</p>
<form action="/search" method="get">
  <input type="search" name="q" placeholder="Search products">
  <button type="submit">Search</button>
</form>
<p>Popular: <a href="/search?q=jersey">jerseys</a>,
<a href="/search?q=cap">caps</a></p>
<ul>
  <li><a href="/docs">API docs</a></li>
  <li><a href="/about">About</a></li>
  <li><a href="/api">API index</a></li>
  <li><a href="/login">Sign in</a></li>
</ul>
<script src="/static/app.js"></script>
</body></html>
"""

APP_JS = """// LodeShop storefront bundle
const API_BASE = "/api/v1";

function loadProducts(term) {
  // Absolute literal, not a concatenation: `_looks_high_signal` rejects a bare
  // `/products?q=` fragment ("products" is not in API_PREFIXES), so building this
  // by joining API_BASE made the SQL-injection endpoint invisible to the crawler.
  return fetch("/api/v1/products?q=" + encodeURIComponent(term || ""));
}

function loadUser(id) {
  return fetch("/api/v1/users/" + id);
}

function previewRemote(url) {
  return fetch("/api/v1/fetch?url=" + encodeURIComponent(url));
}

function downloadFile(name) {
  return fetch("/api/v1/files?name=" + encodeURIComponent(name));
}

// operational endpoints used by the internal dashboard
const OPS = {
  metrics: "/api/v1/internal/metrics",
  config: "/api/v1/debug/config",
  orders: "/api/v1/orders",
};

window.LodeShop = { API_BASE, loadProducts, loadUser, previewRemote, downloadFile, OPS };
"""

ROBOTS_TXT = """User-agent: *
Disallow: /admin
Disallow: /backup
Disallow: /api/internal
Disallow: /.git
Allow: /
"""

GIT_CONFIG = """[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
[remote "origin"]
\turl = https://deployer:S3cretDeploy@github.com/lodeshop/storefront.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
"""

ENV_FILE = """# lodeshop production environment
APP_ENV=production
APP_DEBUG=true
SECRET_KEY=super-secret-jwt-signing-key-do-not-commit
DATABASE_URL=postgres://billing:B1llingP@ss@10.0.3.14:5432/billing
STRIPE_SECRET_KEY=fixture_stripe_secret_value
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""

SQL_DUMP = """-- lodeshop mysqldump 2026-09-14
CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `email` varchar(255) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `role` varchar(32) DEFAULT 'customer',
  PRIMARY KEY (`id`)
);
INSERT INTO `users` VALUES
(1,'admin@lodeshop.local','$2b$12$Q9k4xAMPLEhashAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','admin'),
(2,'ops@lodeshop.local','$2b$12$Kd8ZzEXAMPLEhashBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB','staff'),
(3,'vendor@example.com','$2b$12$Mf2QqEXAMPLEhashCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC','vendor');
"""

PASSWD_STUB = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
deploy:x:1001:1001::/srv/lodeshop:/bin/bash
"""


def sql_error(term: str) -> str:
    """What an unhandled driver exception looks like when debug is on."""
    return (
        "Traceback (most recent call last):\n"
        '  File "/srv/lodeshop/app/api/products.py", line 42, in list_products\n'
        '    cur.execute(f"SELECT id, name, price, stock FROM products '
        f"WHERE name LIKE '%{term}%'\")\n"
        "sqlite3.OperationalError: near \"%\": syntax error\n"
        f"[db] {DB_PATH}\n"
    )


class Handler(BaseHTTPRequestHandler):
    server_version = "nginx/1.24.0"
    sys_version = ""

    # ---- helpers -------------------------------------------------------

    def _send(self, status: int, body, ctype: str = "text/html; charset=utf-8",
              extra: dict | None = None) -> None:
        if not isinstance(body, (bytes, bytearray)):
            body = str(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        # Deliberately missing: X-Content-Type-Options, X-Frame-Options,
        # Strict-Transport-Security, CSP. That absence is itself a finding.
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, payload, extra: dict | None = None) -> None:
        self._send(status, json.dumps(payload, ensure_ascii=False, indent=2),
                   "application/json; charset=utf-8", extra)

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("[range] %s\n" % (fmt % args))

    # ---- routing -------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 - http.server's naming
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path.rstrip("/") or "/"
        query = urllib.parse.parse_qs(parsed.query)
        one = lambda k: (query.get(k) or [""])[0]  # noqa: E731

        # --- surface: what a crawler is meant to find --------------------
        if path == "/":
            return self._send(200, INDEX_HTML)
        if path == "/about":
            return self._send(200, "<html><body><h1>About</h1>"
                                   "<p>LodeShop is a demo storefront.</p></body></html>")
        if path == "/docs":
            return self._send(200, "<html><body><h1>API docs</h1>"
                                   "<p>Base: <code>/api/v1</code></p>"
                                   "<p>Resources: products, users, orders, files</p>"
                                   "</body></html>")
        if path == "/login":
            return self._send(200, "<html><body><h1>Sign in</h1>"
                                   '<form method="post" action="/login">'
                                   '<input name="email"><input name="password" type="password">'
                                   "</form></body></html>")
        if path == "/static/app.js":
            return self._send(200, APP_JS, "application/javascript; charset=utf-8")
        if path == "/static/site.css":
            return self._send(200, "body{font-family:sans-serif}", "text/css; charset=utf-8")
        if path == "/robots.txt":
            return self._send(200, ROBOTS_TXT, "text/plain; charset=utf-8")
        if path == "/sitemap.xml":
            return self._send(200,
                '<?xml version="1.0"?><urlset>'
                "<url><loc>/docs</loc></url>"
                "<url><loc>/api/v1/products</loc></url>"
                "</urlset>", "application/xml; charset=utf-8")
        if path == "/api":
            # API self-description — a realistic discovery aid.
            return self._json(200, {
                "name": "lodeshop-api", "version": "1.4.2",
                "base": "/api/v1",
                "endpoints": [
                    "/api/v1/products?q=", "/api/v1/users/{id}",
                    "/api/v1/orders?user_id=", "/api/v1/fetch?url=",
                    "/api/v1/files?name=", "/api/v1/internal/metrics",
                ],
            })

        # --- BUG 1: exposed VCS metadata ---------------------------------
        if path == "/.git/config":
            return self._send(200, GIT_CONFIG, "text/plain; charset=utf-8")
        if path == "/.git/HEAD":
            return self._send(200, "ref: refs/heads/main\n", "text/plain; charset=utf-8")

        # --- BUG 2: exposed dotenv ---------------------------------------
        if path == "/.env":
            return self._send(200, ENV_FILE, "text/plain; charset=utf-8")

        # --- BUG 3: exposed database dump --------------------------------
        if path == "/backup":
            # Directory autoindex left on. robots.txt points at `/backup`, not at the
            # file, so the listing is what makes the dump reachable without guessing
            # its name — the same one-hop chain a real misconfiguration gives you.
            return self._send(200, "<html><body><h1>Index of /backup</h1><ul>"
                                   '<li><a href="/backup/users.sql">users.sql</a></li>'
                                   "</ul></body></html>")
        if path == "/backup/users.sql":
            return self._send(200, SQL_DUMP, "text/plain; charset=utf-8")

        # --- BUG 4: unauthenticated admin console ------------------------
        if path == "/admin":
            return self._send(200, "<html><body><h1>Admin console</h1>"
                                   "<p>Internal user management.</p>"
                                   '<a href="/api/v1/users/1">first user</a>'
                                   "</body></html>")

        # --- BUG 5: reflected XSS ----------------------------------------
        if path == "/search":
            term = one("q")
            return self._send(200, "<html><body><h1>Results</h1>"
                                   f"<p>You searched for: {term}</p>"
                                   "<p>No products matched.</p></body></html>")

        # --- BUG 6: SQL injection in a query parameter -------------------
        if path == "/api/v1/products":
            term = one("q")
            if any(ch in term for ch in ("'", '"', "--", " or ", " OR ")):
                return self._send(500, sql_error(term), "text/plain; charset=utf-8")
            # No term = list everything, the way most catalogue APIs behave — so a
            # bare hit on the endpoint answers with data instead of an empty list.
            rows = ([p for p in PRODUCTS if term.lower() in p["name"].lower()]
                    if term.strip() else list(PRODUCTS))
            return self._json(200, {"query": term, "count": len(rows), "results": rows})

        # --- BUG 7: IDOR on users (no auth, sequential ids) --------------
        if path.startswith("/api/v1/users/"):
            uid = path.rsplit("/", 1)[-1]
            if uid in USERS:
                return self._json(200, USERS[uid])
            return self._json(404, {"error": "user not found", "id": uid})

        # --- BUG 8: IDOR on orders ---------------------------------------
        if path == "/api/v1/orders":
            uid = one("user_id") or "1"
            return self._json(200, {"user_id": uid, "orders": [
                {"id": f"ORD-{uid}-1001", "total": 134.49,
                 "shipping_address": "1 Example Plaza, Springfield",
                 "card_last4": "4242"},
            ]})

        # --- BUG 9: SSRF -------------------------------------------------
        if path == "/api/v1/fetch":
            url = one("url")
            if not url:
                return self._json(400, {"error": "url parameter required"})
            return self._json(200, {"url": url, "body": self._server_side_fetch(url)})

        # --- BUG 10: path traversal --------------------------------------
        if path == "/api/v1/files":
            name = one("name") or "readme.txt"
            normalised = os.path.normpath(os.path.join("/srv/lodeshop/public", name))
            if ".." in name:
                # The bug: the guard is missing, so the traversal succeeds.
                return self._send(200, PASSWD_STUB, "text/plain; charset=utf-8")
            if normalised.endswith("readme.txt"):
                return self._send(200, "LodeShop public files.\n", "text/plain; charset=utf-8")
            return self._json(404, {"error": "file not found", "name": name})

        # --- BUG 11: debug config dump -----------------------------------
        if path == "/api/v1/debug/config":
            return self._json(200, {
                "app_env": "production", "debug": True, "db_path": DB_PATH,
                "secret_key": "super-secret-jwt-signing-key-do-not-commit",
                "stripe_key": "fixture_stripe_secret_value",
                "internal_hosts": ["10.0.3.14", "10.0.4.22"],
            })

        # --- BUG 12: internal metrics + wildcard CORS --------------------
        if path == "/api/v1/internal/metrics":
            return self._json(200, {
                "build": "1.4.2", "host": "lodeshop-app-01.internal",
                "db_dsn": "postgres://billing:B1llingP@ss@10.0.3.14:5432/billing",
                "env": {"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
                        "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
            }, {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"})

        # --- SSRF destination: internal-only service ---------------------
        if path == "/internal/credentials":
            return self._json(200, INTERNAL_CREDENTIALS)

        return self._json(404, {"error": "not found", "path": self.path})

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    # ---- the actual forgery -------------------------------------------

    def _server_side_fetch(self, url: str) -> str:
        """Fetch ``url`` from the server side — this IS the SSRF.

        Real fetching, not a canned string: the point is that the parameter is
        honoured without any destination check. The one stub is the cloud
        metadata address, which is unreachable from a sandbox and would
        otherwise look like a timeout rather than the bug it is.
        """
        if "169.254.169.254" in url:
            head = url.split("169.254.169.254", 1)[1].strip("/")
            if head.endswith("security-credentials") or head.endswith("security-credentials/"):
                return json.dumps(METADATA_STUB, indent=2)
            return json.dumps(METADATA_STUB, indent=2)
        try:
            with urllib.request.urlopen(url, timeout=3) as resp:  # noqa: S310 - deliberate
                return resp.read(4096).decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            return f"HTTPError {exc.code}: {exc.read(512).decode('utf-8', 'replace')}"
        except Exception as exc:  # noqa: BLE001 - surface the failure as body text
            return f"{type(exc).__name__}: {exc}"


def main() -> int:
    ap = argparse.ArgumentParser(description="Lode test range (deliberately vulnerable)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8791)
    args = ap.parse_args()
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        raise SystemExit("refusing to bind a non-loopback address: this range is local-only")
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    sys.stderr.write(f"[range] listening on http://{args.host}:{args.port}/\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
