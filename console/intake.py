"""Console side of the intake gate: preview → confirm → TargetCard → job.

The Console used to write a ``ProjectIntakeRequest/v1`` file that **nothing ever
read**, so a submitted target sat at ``pending_review`` forever, and the real gate
(``core.intake_state``: digest-bound preview, then an immutable TargetCard) was
unreachable from the UI.  This module is the one bridge between the two, so the
route layer stays thin and the ordering is testable without a browser.

Ordering matters and is deliberate:

1. ``start_preview`` mints the preview and its digests.  Nothing is executed.
2. the operator confirms by echoing ``intake_id`` + ``options_digest`` back.
3. ``confirm`` validates that binding and writes the receipt.
4. only then is the TargetCard materialized and only then may a job start.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from console.deps import _brute_requested, _sanitize_toggles
from core.intake_state import (
    DEFAULT_INTAKE_TTL_SECONDS,
    IntakePreview,
    IntakeState,
    IntakeStateError,
    TargetCardStore,
    default_options,
    target_card_from_preview,
)

# The Console has no chat identity of its own; GoalControl (the Feishu path) keys
# previews by (user, chat).  One fixed pair means "one pending preview per console",
# which is what the UI shows as the 提交队列.
CONSOLE_USER = "console"
CONSOLE_CHAT = "console"

INTAKE_LEDGER = "target_intakes.jsonl"

# Every switch the Console offers, mapped onto the gate's option key.  A switch
# that is not in here does not exist as far as the confirmation is concerned, so
# adding one to the UI means adding it here in the same commit.
TOGGLE_OPTIONS: Dict[str, str] = {
    "asset_inventory": "asset_inventory",
    "subdomain_enum": "subdomain_enum",
    "fingerprint_precise": "fingerprint",
    "scan_enabled": "active_scan",
    "nuclei": "nuclei",
    "tscan": "tscan",
    "intel": "intelligence",
    "poc_research": "poc_research",
    "proxy_route": "proxy_route",
    "network_gate": "network_gate",
    "edge_human_gate": "edge_human_gate",
}


def intake_state(state_dir: Path | str) -> IntakeState:
    return IntakeState(Path(state_dir) / INTAKE_LEDGER)


def project_root() -> Path:
    """Where TargetCards land — the repo root, matching the Feishu path's choice.

    Both callers must agree on this: a card the Console wrote has to be the same
    object the agent side later resolves by ``target_id``.
    """
    return Path(__file__).resolve().parents[1]


def target_cards(state_dir: Path | str | None = None) -> TargetCardStore:
    del state_dir  # cards live under the repo's ai-pentest-evidence/, not the state dir
    return TargetCardStore(project_root())


def intake_options(toggles: Any) -> Dict[str, Any]:
    """Turn the dialog's switches into the gate's options object.

    Starts from :func:`core.intake_state.default_options` and only flips
    ``enabled``, so the modes stay whatever the canonical contract says they are
    instead of being re-invented per caller.

    Raises ``IntakeStateError("brute_force_out_of_scope")`` if the payload asks
    for brute force.  The passive contract this project runs under has no
    brute-force mode, and a switch that silently does nothing is worse than a
    refusal.
    """
    raw = toggles if isinstance(toggles, dict) else {}
    if _brute_requested(raw):
        raise IntakeStateError("brute_force_out_of_scope")
    sanitized = _sanitize_toggles(raw)
    options = default_options()
    for toggle_key, option_key in TOGGLE_OPTIONS.items():
        group = options.get(option_key)
        if not isinstance(group, dict):
            # The dialog offers a switch the gate has no key for.  Refuse loudly:
            # recording the rest and dropping this one is the exact bug the
            # preview/confirm binding exists to prevent.
            raise IntakeStateError(f"intake_option_unknown:{option_key}")
        group["enabled"] = sanitized.get(toggle_key) is True
        if group["enabled"] and group.get("mode") == "not_requested":
            group["mode"] = "requested"
    # Explicit disabled shape, same reason `_sanitize_toggles` keeps one: the
    # durable options object must never leave a brute flag open to interpretation.
    options["brute"] = sanitized["brute"]
    return options


def pending_preview(state_dir: Path | str) -> Optional[IntakePreview]:
    return intake_state(state_dir).pending(user_id=CONSOLE_USER, chat_id=CONSOLE_CHAT)


def start_preview(
    state_dir: Path | str,
    *,
    target: str,
    profile_name: str,
    instruction: str,
    toggles: Any = None,
) -> IntakePreview:
    """Mint the preview.  Raises IntakeStateError (see the module it comes from)."""
    return intake_state(state_dir).create_preview(
        target=target,
        instruction=instruction,
        profile_name=profile_name,
        # The Console has no external goal concept; the preview carries its own id so
        # the Feishu consumer's "which goal asked for this" field stays populated.
        goal_id="console-intake",
        user_id=CONSOLE_USER,
        chat_id=CONSOLE_CHAT,
        message_id=f"console-{profile_name}",
        options=intake_options(toggles),
    )


def discard(state_dir: Path | str) -> bool:
    return intake_state(state_dir).discard_pending(user_id=CONSOLE_USER, chat_id=CONSOLE_CHAT)


def _canonical_host(target_card: Dict[str, Any]) -> str:
    """The scope host the card was built around — the card is the authority post-confirm."""
    scope = target_card.get("scope") if isinstance(target_card.get("scope"), dict) else {}
    hosts = scope.get("allowed_hosts") if isinstance(scope.get("allowed_hosts"), list) else []
    return str(hosts[0]) if hosts else ""


def _result(source: Dict[str, Any], materialized: Dict[str, Any]) -> Dict[str, Any]:
    """One shape for both a fresh confirm and a replayed one."""
    profile = source.get("profile_name") or source.get("profile") or ""
    return {
        "intake_id": str(source.get("intake_id", "")),
        "target": str(source.get("target", "")),
        "canonical_host": _canonical_host(materialized["target_card"]),
        "profile_name": str(profile),
        "instruction": str(source.get("instruction", "")),
        "options_digest": str(source.get("options_digest", "")),
        "target_id": materialized["target_id"],
        "target_card_digest": materialized["target_card_digest"],
        "target_card_ref": materialized["target_card_ref"],
    }


def confirm(
    state_dir: Path | str,
    *,
    intake_id: str,
    options_digest: str,
) -> Dict[str, Any]:
    """Consume the confirmation, materialize the TargetCard, return everything a job needs.

    Raises IntakeStateError for a stale/mismatched/absent preview; the route maps
    those to status codes.
    """
    state = intake_state(state_dir)
    # A retry (double click, a proxy replaying the POST) must land on the receipt
    # that already exists instead of a confusing "nothing pending" — the card is
    # already on disk by then, and re-materializing it is a digest-checked no-op.
    replay = state.confirmed_intake(
        user_id=CONSOLE_USER, chat_id=CONSOLE_CHAT,
        intake_id=intake_id, options_digest=options_digest,
    )
    if replay is not None:
        return _result(replay, target_cards(state_dir).materialize(replay["target_card"]))

    preview = state.pending(user_id=CONSOLE_USER, chat_id=CONSOLE_CHAT)
    if preview is None:
        raise IntakeStateError("no_pending_intake_preview")
    if preview.intake_id != intake_id:
        raise IntakeStateError("intake_confirmation_binding_mismatch")

    card = target_card_from_preview(preview)
    receipt = state.consume_confirmation(
        user_id=CONSOLE_USER,
        chat_id=CONSOLE_CHAT,
        # message_id is the preview's own id, so the replay lookup above and the
        # receipt agree on one key for this confirmation.
        message_id=preview.intake_id,
        intake_id=preview.intake_id,
        options_digest=options_digest,
        target_card=card,
    )
    return _result(receipt, target_cards(state_dir).materialize(receipt["target_card"]))


def preview_view(preview: IntakePreview) -> Dict[str, Any]:
    """The review-safe preview object the API returns, and the UI echoes back.

    ``intake_id`` + ``options_digest`` are the confirmation binding: the operator
    confirms the digest of the switches they were just shown, so a preview that
    changed underneath them (another tab, an edited dialog) fails to confirm
    instead of running something else.
    """
    return {
        "intake_id": preview.intake_id,
        "target": preview.target,
        "canonical_host": preview.canonical_host,
        "entrypoint": preview.entrypoint,
        "instruction": preview.instruction,
        "instruction_digest": preview.instruction_digest,
        "profile_name": preview.profile_name,
        "goal_id": preview.goal_id,
        "options": preview.options,
        "options_digest": preview.options_digest,
        "preview_digest": preview.preview_digest,
        "scope_digest": preview.scope_digest,
        "created_at": preview.created_at,
        "expires_at": preview.expires_at,
    }


def default_ttl_seconds() -> int:
    return DEFAULT_INTAKE_TTL_SECONDS
