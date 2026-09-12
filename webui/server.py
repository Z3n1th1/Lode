"""Loopback-only process launcher for the ControlPlane WebUI."""
from __future__ import annotations

import argparse
import os
from pathlib import Path

import uvicorn

from webui.control_plane import MIN_PASSWORD_LENGTH, MIN_SESSION_SECRET_LENGTH, create_app


DEFAULT_PORT = 8088


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="本地 ControlPlane WebUI（仅 127.0.0.1）")
    parser.add_argument("--state-dir", required=True, help="Goal/Task durable state directory")
    parser.add_argument("--static-dir", default=str(Path(__file__).with_name("dist")))
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args(argv)

    password = os.environ.get("WEBUI_ADMIN_PASSWORD", "")
    session_secret = os.environ.get("WEBUI_SESSION_SECRET", "")
    if len(password) < MIN_PASSWORD_LENGTH:
        parser.error(f"WEBUI_ADMIN_PASSWORD must be at least {MIN_PASSWORD_LENGTH} characters")
    if len(session_secret) < MIN_SESSION_SECRET_LENGTH:
        parser.error(f"WEBUI_SESSION_SECRET must be at least {MIN_SESSION_SECRET_LENGTH} characters")
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")

    app = create_app(
        state_dir=Path(args.state_dir),
        password=password,
        session_secret=session_secret,
        static_dir=Path(args.static_dir),
    )
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
