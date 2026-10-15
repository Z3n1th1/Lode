"""Restricted news configuration and one-way Discord delivery."""
from __future__ import annotations

import json
import os
import re
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .summarizer import _NoRedirects

NEWS_ENV_KEYS = frozenset({
    "FEISHU_WEBHOOK", "FEISHU_SECRET", "DISCORD_WEBHOOK", "DISCORD_WEBHOOK_URL",
    "DEEPSEEK_API_KEY", "DEEPSEEK_BASE_URL", "DEEPSEEK_MODEL", "X_BEARER_TOKEN",
})


def load_news_environment(path: Path, *, optional: bool = False) -> list[str]:
    """Read literal values from an isolated file; never source shell code."""
    if path.is_symlink():
        raise ValueError("news_env_symlink_rejected")
    if optional and not path.exists():
        return []
    with path.open("rb") as stream:
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise ValueError("news_env_too_large")
    values: dict[str, str] = {}
    for line in raw.decode("utf-8-sig").splitlines():
        match = re.fullmatch(r"\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*", line)
        if not match or match[1] not in NEWS_ENV_KEYS:
            continue
        key, value = match[1], match[2]
        if value[:1] in {"'", '"'}:
            quote = value[0]
            end = value.find(quote, 1)
            if end < 0 or (value[end + 1:].strip() and not value[end + 1:].lstrip().startswith("#")):
                raise ValueError("news_env_invalid_quoted_value")
            value = value[1:end]
        else:
            value = re.split(r"\s+#", value, maxsplit=1)[0].strip()
        values.setdefault(key, value)
    loaded = []
    for key, value in values.items():
        if key not in os.environ:
            os.environ[key] = value
            loaded.append(key)
    return loaded


def discord_webhook() -> str:
    value = (os.environ.get("DISCORD_WEBHOOK", "").strip()
             or os.environ.get("DISCORD_WEBHOOK_URL", "").strip())
    url = urlsplit(value)
    if (url.scheme != "https" or url.netloc not in {"discord.com", "discordapp.com"}
            or not re.fullmatch(r"/api(?:/v[0-9]+)?/webhooks/[0-9]{1,20}/[A-Za-z0-9._-]{1,200}", url.path)
            or url.query not in {"", "wait=true", "wait=false"} or url.fragment):
        raise ValueError("official_discord_webhook_required")
    # Asking for confirmation makes API rejection distinguishable from success.
    return urlunsplit((url.scheme, url.netloc, url.path, "wait=true", ""))


def send_discord_article(row: dict[str, Any]) -> bool:
    payload = {
        "allowed_mentions": {"parse": [], "users": [], "roles": [], "replied_user": False},
        "embeds": [{
            "title": "Pulse | " + row["title"][:160],
            "description": row["ai_summary"][:500],
            "url": row["url"],
            "footer": {"text": row["source"][:100]},
        }],
    }
    request = urllib.request.Request(
        discord_webhook(), data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "Pulse/1.0"}, method="POST",
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirects())
    with opener.open(request, timeout=10) as response:
        status = response.status
        raw = response.read(65537)
    if len(raw) > 65536:
        raise ValueError("discord_response_too_large")
    if status == 204:
        return True
    if status != 200:
        return False
    body = json.loads(raw)
    return (isinstance(body, dict) and isinstance(body.get("id"), str)
            and body["id"].isdigit() and "code" not in body and "retry_after" not in body)
