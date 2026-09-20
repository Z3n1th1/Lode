"""Loopback-only process launcher for the ControlPlane Console."""
from __future__ import annotations

import argparse
import os
from pathlib import Path

import uvicorn

from console.app import create_app
from console.deps import MIN_PASSWORD_LENGTH, MIN_SESSION_SECRET_LENGTH

# Load .env + the Console-managed LLM settings into os.environ. Importing
# core.config already runs both; the explicit call below re-runs it with the
# Console's own --state-dir so the settings file is found there too.
try:
    from core import llm_settings

    import core.config  # noqa: F401
except Exception:  # noqa: BLE001 - console still runs, just without saved settings
    llm_settings = None


DEFAULT_PORT = 8088


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="本地 ControlPlane Console（仅 127.0.0.1）")
    parser.add_argument("--state-dir", required=True, help="Goal/Task durable state directory")
    parser.add_argument("--static-dir", default=str(Path(__file__).with_name("dist")))
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args(argv)

    state_dir = Path(args.state_dir)
    if llm_settings is not None:
        try:
            llm_settings.load_llm_settings(state_dir=state_dir)
        except Exception:  # noqa: BLE001 - settings are advisory
            pass
    # Keep the header's active-model switch and the agent's provider pool on the
    # same file (core.llm_pool otherwise defaults to a non-existent /opt path).
    os.environ.setdefault("LLM_ACTIVE_PROVIDER_FILE", str(state_dir / "model_active_provider.json"))
    # One request budget per engagement, in a file under this state dir — so a
    # CLI run and a Console run against the same program share it instead of each
    # holding to the stated rate on its own.
    from core.rate_limit import configure_persistence

    configure_persistence(state_dir)

    password = os.environ.get("LODE_ADMIN_PASSWORD", "")
    session_secret = os.environ.get("LODE_SESSION_SECRET", "")
    if len(password) < MIN_PASSWORD_LENGTH:
        parser.error(f"LODE_ADMIN_PASSWORD must be at least {MIN_PASSWORD_LENGTH} characters")
    if len(session_secret) < MIN_SESSION_SECRET_LENGTH:
        parser.error(f"LODE_SESSION_SECRET must be at least {MIN_SESSION_SECRET_LENGTH} characters")
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")

    app = create_app(
        state_dir=state_dir,
        password=password,
        session_secret=session_secret,
        static_dir=Path(args.static_dir),
    )
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
