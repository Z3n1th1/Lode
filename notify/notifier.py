#!/usr/bin/env python3
"""Category -> Feishu group routing for pentest-agent alerts (OUTBOUND).

Loads notify/feishu_routes.yaml (category -> chat_id) and sends a message to the
right group by category. Credentials come from env (FEISHU_APP_ID /
FEISHU_APP_SECRET) — never from the routes file.

    FEISHU_APP_ID=cli_xxx FEISHU_APP_SECRET=xxx \
        python notifier.py security_alert "new login from 1.2.3.4"

Categories: security_alert | human_approval | finding | ops_selfcheck
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import feishu_client  # same dir

try:
    from core.confidentiality import sanitize_external_text
except ModuleNotFoundError:
    _CORE_DIR = Path(__file__).resolve().parents[1] / "core"
    if str(_CORE_DIR) not in sys.path:
        sys.path.insert(0, str(_CORE_DIR))
    from confidentiality import sanitize_external_text  # type: ignore

try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None

_ROUTES_PATH = Path(__file__).with_name("feishu_routes.yaml")
_ROUTE_SCHEMA = "FeishuRoutes/v1"
_CHAT_ID = re.compile(r"^oc_[A-Za-z0-9]{16,}$")


def _validate_routes(document: Any) -> Dict[str, Any]:
    if not isinstance(document, dict) or document.get("schema") != _ROUTE_SCHEMA:
        raise RuntimeError("invalid_feishu_routes_schema")
    table = document.get("routes")
    if not isinstance(table, dict) or not table:
        raise RuntimeError("invalid_feishu_routes_table")
    for category, entry in table.items():
        if not isinstance(category, str) or not category.strip() or not isinstance(entry, dict):
            raise RuntimeError("invalid_feishu_route_entry")
        chat_id = entry.get("chat_id")
        if not isinstance(chat_id, str) or _CHAT_ID.fullmatch(chat_id) is None:
            raise RuntimeError(f"invalid_feishu_chat_id:{category}")
    default = document.get("default")
    if default is not None and default not in table:
        raise RuntimeError("invalid_feishu_default_route")
    return document


def load_routes(path: Optional[str] = None) -> Dict[str, Any]:
    if yaml is None:
        raise RuntimeError("pyyaml_required")
    p = Path(path) if path else _ROUTES_PATH
    return _validate_routes(yaml.safe_load(p.read_text(encoding="utf-8")) or {})


def _token() -> str:
    app_id = os.environ.get("FEISHU_APP_ID", "")
    secret = os.environ.get("FEISHU_APP_SECRET", "")
    if not app_id or not secret:
        raise RuntimeError("FEISHU_APP_ID/FEISHU_APP_SECRET missing in env")
    return feishu_client.get_tenant_access_token(app_id, secret)


def resolve_chat_id(category: str, routes: Optional[Dict[str, Any]] = None) -> str:
    routes = load_routes() if routes is None else _validate_routes(routes)
    table = routes["routes"]
    entry = table.get(category)
    if not entry or not entry.get("chat_id"):
        raise RuntimeError(f"no_route_for_category:{category}")
    return str(entry["chat_id"])


def send_by_category(category: str, text: str, *,
                     routes: Optional[Dict[str, Any]] = None,
                     token: Optional[str] = None) -> str:
    routes = load_routes() if routes is None else _validate_routes(routes)
    chat_id = resolve_chat_id(category, routes)
    return feishu_client.send_text(token or _token(), chat_id, sanitize_external_text(text))


if __name__ == "__main__":
    cat = sys.argv[1] if len(sys.argv) > 1 else "ops_selfcheck"
    msg = sys.argv[2] if len(sys.argv) > 2 else f"【pentest-agent】路由自测:分类={cat}"
    print("sent message_id=", send_by_category(cat, msg))
