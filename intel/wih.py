"""Web Info Hunter rules distilled from ARL ``wih_rules.yml``.

Tags shapes in already-fetched HTML/JS. Does not dump secret values onto the
blackboard — JS keys stay a hint unless a later card chains them.
"""
from __future__ import annotations

import re
from typing import Iterable


# id_card / phone stay off: those are PII samples, not recon fingerprints.
_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("jwt-shape", re.compile(r"eyJ[A-Za-z0-9_/+-]{10,}={0,2}\.[A-Za-z0-9_/+-]{15,}")),
    ("aliyun-ak-shape", re.compile(r"\bLTAI[A-Za-z\d]{12,30}\b")),
    ("qcloud-ak-shape", re.compile(r"\bAKID[A-Za-z\d]{13,40}\b")),
    ("jdcloud-ak-shape", re.compile(r"\bJDC_[0-9A-Z]{25,40}\b")),
    ("aws-ak-shape", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("volc-ak-shape", re.compile(r"\b(?:AKLT|AKTP)[a-zA-Z0-9]{35,50}\b")),
    ("github-token-shape", re.compile(r"\b(?:ghp|gho|github_pat)_[A-Za-z0-9_]{20,}\b")),
    ("gitlab-token-shape", re.compile(r"\bglpat-[A-Za-z0-9_=-]{20,}\b")),
    ("private-key-shape", re.compile(r"-----BEGIN[ A-Z0-9_-]*PRIVATE KEY-----")),
    ("wechat-appid-shape", re.compile(r'["\']wx[a-z0-9]{15,18}["\']')),
    ("webhook-shape", re.compile(r"qyapi\.weixin\.qq\.com/cgi-bin/webhook|oapi\.dingtalk\.com/robot/send")),
)


def tag_text(text: str, *, limit: int = 8) -> set[str]:
    """Return fingerprint names present in ``text``. Values themselves are dropped."""
    blob = str(text or "")
    if not blob:
        return set()
    found: list[str] = []
    for name, pattern in _RULES:
        if pattern.search(blob):
            found.append(name)
        if len(found) >= limit:
            break
    return set(found)


def tag_many(chunks: Iterable[str], *, limit: int = 8) -> set[str]:
    found: set[str] = set()
    for chunk in chunks:
        found.update(tag_text(chunk, limit=limit))
        if len(found) >= limit:
            break
    return found
