#!/usr/bin/env python3
"""Minimal Feishu (Lark) app client for the notify layer — OUTBOUND only.

Capabilities: fetch a tenant_access_token, list the chats/groups the bot is in,
and send a text or interactive-card message. This is the push path used for
security alerts / approval cards / periodic-task pre-notice + results.

Credentials come from the environment (FEISHU_APP_ID / FEISHU_APP_SECRET) — never
hardcode a secret in this file or commit one. No third-party deps (stdlib urllib).

Two-way auto-reply is NOT handled here: that requires a long-running event
consumer subscribed to im.message.receive_v1 (WebSocket long-connection or an
HTTP webhook) — a separate runtime piece. Without that consumer, a bot cannot
reply to messages, by design.

Run as a probe:
    FEISHU_APP_ID=cli_xxx FEISHU_APP_SECRET=xxx python feishu_client.py
    # add FEISHU_TEST_SEND=1 to send a connectivity test to the first group
    # (or FEISHU_CHAT_ID=oc_xxx to target a specific chat)
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

_CORE_DIR = Path(__file__).resolve().parents[1] / "core"
if str(_CORE_DIR) not in sys.path:
    sys.path.insert(0, str(_CORE_DIR))
from confidentiality import sanitize_external_payload, sanitize_external_text

# open.feishu.cn = 飞书(中国/全球版); open.larksuite.com = Lark(国际版).
BASE = os.environ.get("FEISHU_BASE", "https://open.feishu.cn").rstrip("/")
_TIMEOUT = float(os.environ.get("FEISHU_TIMEOUT", "15"))


class FeishuError(Exception):
    def __init__(self, code: Any, msg: str, *, http: Optional[int] = None) -> None:
        super().__init__(f"feishu_error code={code} http={http}: {msg}")
        self.code = code
        self.msg = msg
        self.http = http


def _request(method: str, path: str, *, token: Optional[str] = None,
             body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    url = BASE + path
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json; charset=utf-8")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            payload = json.loads(resp.read().decode("utf-8") or "{}")
            http = resp.getcode()
    except urllib.error.HTTPError as exc:
        # Feishu returns a JSON body with code/msg even on 4xx.
        try:
            payload = json.loads(exc.read().decode("utf-8") or "{}")
        except Exception:
            payload = {}
        http = exc.code
    except urllib.error.URLError as exc:
        raise FeishuError("network", f"{type(exc).__name__}: {exc.reason}") from exc
    if payload.get("code") not in (0, None):
        raise FeishuError(payload.get("code"), str(payload.get("msg") or "unknown"), http=http)
    return payload


def get_tenant_access_token(app_id: str, app_secret: str) -> str:
    payload = _request(
        "POST", "/open-apis/auth/v3/tenant_access_token/internal",
        body={"app_id": app_id, "app_secret": app_secret},
    )
    token = payload.get("tenant_access_token")
    if not token:
        raise FeishuError(payload.get("code"), "no tenant_access_token in response")
    return str(token)


def list_chats(token: str, *, page_size: int = 100) -> List[Dict[str, Any]]:
    """Groups the bot is a member of. Requires im:chat (or readonly) scope."""
    items: List[Dict[str, Any]] = []
    page_token = ""
    while True:
        q = f"?page_size={int(page_size)}" + (f"&page_token={page_token}" if page_token else "")
        payload = _request("GET", "/open-apis/im/v1/chats" + q, token=token)
        data = payload.get("data") or {}
        items.extend(data.get("items") or [])
        page_token = data.get("page_token") or ""
        if not data.get("has_more") or not page_token:
            break
    return items


def send_text(token: str, receive_id: str, text: str, *,
              receive_id_type: str = "chat_id") -> str:
    """Send a plain-text message. content must be a JSON-encoded string."""
    payload = _request(
        "POST", f"/open-apis/im/v1/messages?receive_id_type={receive_id_type}",
        token=token,
        body={"receive_id": receive_id, "msg_type": "text",
              "content": json.dumps({"text": sanitize_external_text(text)}, ensure_ascii=False)},
    )
    return str((payload.get("data") or {}).get("message_id") or "")


def reply_text(token: str, message_id: str, text: str) -> str:
    """Reply to one inbound message with a plain-text message."""
    message_id = message_id.strip()
    if not message_id:
        raise ValueError("message_id_required")
    payload = _request(
        "POST",
        "/open-apis/im/v1/messages/"
        + urllib.parse.quote(message_id, safe="")
        + "/reply",
        token=token,
        body={"msg_type": "text", "content": json.dumps({"text": sanitize_external_text(text)}, ensure_ascii=False)},
    )
    return str((payload.get("data") or {}).get("message_id") or "")


def send_card(token: str, receive_id: str, card: Dict[str, Any], *,
              receive_id_type: str = "chat_id") -> str:
    """Send an interactive card (for later approval cards)."""
    payload = _request(
        "POST", f"/open-apis/im/v1/messages?receive_id_type={receive_id_type}",
        token=token,
        body={"receive_id": receive_id, "msg_type": "interactive",
              "content": json.dumps(sanitize_external_payload(card), ensure_ascii=False)},
    )
    return str((payload.get("data") or {}).get("message_id") or "")


def add_reaction(token: str, message_id: str, *, emoji_type: str = "THUMBSUP") -> str:
    """Acknowledge one inbound message through the Feishu IM reactions API."""
    message_id = message_id.strip()
    emoji_type = emoji_type.strip().upper()
    if not message_id:
        raise ValueError("message_id_required")
    if not emoji_type:
        raise ValueError("emoji_type_required")
    payload = _request(
        "POST",
        "/open-apis/im/v1/messages/"
        + urllib.parse.quote(message_id, safe="")
        + "/reactions",
        token=token,
        body={"reaction_type": {"emoji_type": emoji_type}},
    )
    return str((payload.get("data") or {}).get("reaction_id") or "")


def _probe() -> int:
    app_id = os.environ.get("FEISHU_APP_ID", "")
    app_secret = os.environ.get("FEISHU_APP_SECRET", "")
    if not app_id or not app_secret:
        print("MISSING FEISHU_APP_ID / FEISHU_APP_SECRET in env")
        return 2
    print(f"[1/3] base={BASE} app_id={app_id[:10]}… getting tenant_access_token …")
    try:
        token = get_tenant_access_token(app_id, app_secret)
    except FeishuError as exc:
        print(f"  TOKEN FAILED: {exc}")
        return 1
    print(f"  TOKEN OK (len={len(token)})")

    print("[2/3] listing chats the bot is in …")
    try:
        chats = list_chats(token)
    except FeishuError as exc:
        print(f"  LIST CHATS FAILED: {exc}")
        print("  -> usually means the app lacks im:chat scope or is not published.")
        chats = []
    for c in chats:
        print(f"    chat_id={c.get('chat_id')}  name={c.get('name')!r}")
    if not chats:
        print("    (bot is in 0 groups the API can see — add it to a group and/or grant im:chat)")

    if os.environ.get("FEISHU_TEST_SEND") == "1":
        target = os.environ.get("FEISHU_CHAT_ID") or (chats[0].get("chat_id") if chats else "")
        if not target:
            print("[3/3] no chat to send to (set FEISHU_CHAT_ID)")
            return 1
        print(f"[3/3] sending connectivity test to {target} …")
        try:
            mid = send_text(token, target,
                            "【pentest-agent】飞书连通性自测 ✅ 你能看到这条=出站告警通道 OK。"
                            "(这是机器人主动 push,不是回复;自动回复需要事件消费进程)")
            print(f"  SENT OK message_id={mid}")
        except FeishuError as exc:
            print(f"  SEND FAILED: {exc}")
            return 1
    else:
        print("[3/3] skipped send (set FEISHU_TEST_SEND=1 to send a test message)")
    return 0


if __name__ == "__main__":
    raise SystemExit(_probe())
