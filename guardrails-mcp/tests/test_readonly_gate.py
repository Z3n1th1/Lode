"""Read-looking requests must not bypass semantic write protection."""
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from guardrails.action_policy import refine


@pytest.mark.parametrize("action", [
    {"method": "GET", "url": "https://example.test/reset"},
    {"method": "GET", "url": "https://example.test/logout"},
    {"method": "GET", "url": "https://example.test/rpc?op=update"},
    {"method": "GET", "url": "https://example.test/rpc", "headers": {"X-HTTP-Method-Override": "PATCH"}},
    {"method": "POST", "url": "https://example.test/notes"},
    {"method": "TRACE", "url": "https://example.test/"},
])
def test_base_allow_does_not_override_semantic_write(action):
    result = refine(action, "A0", "allow")
    assert result["decision"] == "need_human"


def test_plain_read_still_defers_to_base():
    assert refine({"method": "GET", "url": "https://example.test/app.js"}, "A0", "allow")["decision"] == "allow"
