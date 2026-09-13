"""Durable job lifecycle endpoints (list / get / stop)."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import JSONResponse

from console.auth import _require_session
from console.routers.base import Ctx, _NOSTORE


def build(ctx: Ctx) -> APIRouter:
    router = APIRouter()

    @router.get("/api/v1/jobs")
    def jobs_list(request: Request, session_id: str = "", limit: int = 50) -> JSONResponse:
        """List jobs (newest first), optionally scoped to one session."""
        _require_session(request)
        from console import jobs as _jobs

        rows = _jobs.get_registry(ctx.state_dir).list(
            session_id=session_id, limit=max(1, min(200, int(limit))))
        return JSONResponse(content={"jobs": [r.to_dict() for r in rows]}, headers=_NOSTORE)

    @router.get("/api/v1/jobs/{job_id}")
    def jobs_get(job_id: str, request: Request) -> JSONResponse:
        _require_session(request)
        from console import jobs as _jobs

        job = _jobs.get_registry(ctx.state_dir).get(job_id)
        if job is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not_found")
        return JSONResponse(content=job.to_dict(), headers=_NOSTORE)

    @router.post("/api/v1/jobs/{job_id}/stop")
    def jobs_stop(job_id: str, request: Request) -> JSONResponse:
        """Request a cooperative stop (durable flag; the worker ends at a boundary)."""
        _require_session(request)
        from console import jobs as _jobs

        registry = _jobs.get_registry(ctx.state_dir)
        if registry.get(job_id) is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not_found")
        _jobs.get_runner(ctx.state_dir).stop(job_id)
        return JSONResponse(content={"ok": True, "job_id": job_id, "status": "stop_requested"},
                            headers=_NOSTORE)

    return router
