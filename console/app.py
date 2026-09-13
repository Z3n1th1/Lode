"""Console application factory: middleware, routers and the static SPA."""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException, status
from fastapi.responses import FileResponse
from starlette.middleware.sessions import SessionMiddleware

from console.deps import MIN_PASSWORD_LENGTH, MIN_SESSION_SECRET_LENGTH
from console.projections import ConsoleStaticFiles, ReadOnlyControlPlane
from console.routers import dashboard, intake, llm, meta, projects, src_agent
from console.routers.base import Ctx

def create_app(
    *,
    state_dir: Path | str,
    password: str,
    session_secret: str,
    static_dir: Path | str | None = None,
) -> FastAPI:
    """Create the same-origin local dashboard service without a public listener."""
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError("console_password_too_short")
    if len(session_secret) < MIN_SESSION_SECRET_LENGTH:
        raise ValueError("console_session_secret_too_short")

    app = FastAPI(title="Pentest Agent ControlPlane", docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(
        SessionMiddleware,
        secret_key=session_secret,
        session_cookie="pentest_agent_control_plane",
        max_age=12 * 60 * 60,
        same_site="strict",
        https_only=False,
    )
    control_plane = ReadOnlyControlPlane(state_dir)

    ctx = Ctx(
        state_dir=Path(state_dir),
        control_plane=control_plane,
        password=password,
        session_secret=session_secret,
        static_dir=Path(static_dir) if static_dir is not None else None,
    )
    for module in (meta, src_agent, dashboard, llm, intake, projects):
        app.include_router(module.build(ctx))

    resolved_static_dir = Path(static_dir) if static_dir is not None else None

    # ---- Standalone SRC Agent page (no build required) ----
    _src_agent_page = Path(__file__).resolve().parent / "src_agent_page.html"
    if _src_agent_page.is_file():
        @app.get("/src-agent", include_in_schema=False)
        def src_agent_page() -> FileResponse:
            return FileResponse(_src_agent_page)

    if resolved_static_dir is not None and (resolved_static_dir / "index.html").is_file():
        assets_dir = resolved_static_dir / "assets"
        if assets_dir.is_dir():
            app.mount("/assets", ConsoleStaticFiles(directory=str(assets_dir)), name="assets")

        @app.get("/", include_in_schema=False)
        def index() -> FileResponse:
            return FileResponse(resolved_static_dir / "index.html")

        @app.get("/{path:path}", include_in_schema=False)
        def spa_fallback(path: str) -> FileResponse:
            if path.startswith("api/"):
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
            return FileResponse(resolved_static_dir / "index.html")

    return app

