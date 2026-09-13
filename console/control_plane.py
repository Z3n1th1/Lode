"""Compatibility shim.

The Console control plane was split (P2b) into:

* :mod:`console.deps`         - constants + validation/intake helpers
* :mod:`console.models`       - pydantic request bodies
* :mod:`console.projections`  - read-only state projections
* :mod:`console.auth`         - session authentication
* :mod:`console.app`          - the ``create_app`` factory + routes

This module re-exports the historical names so existing callers and tests keep
importing ``console.control_plane`` unchanged. New code should import from the
specific module.
"""
from __future__ import annotations

from console.app import create_app
from console.auth import _password_matches, _require_session
from console.deps import (  # noqa: F401 - re-exported for callers/tests
    ALLOWED_BLOCK_REASONS,
    ALLOWED_TASK_STATUSES,
    MAX_CARD_BYTES,
    MAX_STATE_EVENTS,
    MAX_STATE_FILE_BYTES,
    MAX_VISIBLE_ITEMS,
    MIN_PASSWORD_LENGTH,
    MIN_SESSION_SECRET_LENGTH,
    PROJECT_ID_RE,
    RUN_ID_RE,
    SESSION_ID_RE,
    TASK_ID_RE,
    _bounded_profiles,
    _extract_scope,
    _fetch_public_page,
    _http_get_once,
    _normalize_domain,
    _normalize_domain_list,
    _normalize_scope,
    _normalize_url_list,
    _number,
    _sanitize_toggles,
    _text,
    _url_inside_scope,
    _valid_profile,
    _valid_public_target,
    _write_guidance,
    _write_intake,
)
from console.models import (  # noqa: F401 - re-exported for callers/tests
    LlmProviderInput,
    LlmSettingsRequest,
    LlmTestRequest,
    LoginRequest,
    ModelActiveRequest,
    ProjectIntakeRequest,
    SessionGuidanceRequest,
    SrcAgentChatRequest,
    SrcAgentStartRequest,
    SrcIntakeRequest,
    SrcSessionPatchRequest,
)
from console.projections import ConsoleStaticFiles, ReadOnlyControlPlane  # noqa: F401

__all__ = [
    "create_app", "ReadOnlyControlPlane", "ConsoleStaticFiles",
    "MIN_PASSWORD_LENGTH", "MIN_SESSION_SECRET_LENGTH",
    "_password_matches", "_require_session", "_sanitize_toggles",
    "_valid_public_target", "_normalize_scope",
]
