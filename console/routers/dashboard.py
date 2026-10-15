"""Flask-style router builder: ``build(ctx) -> APIRouter``."""
from __future__ import annotations

import hmac
import ipaddress
import json
import math
import os
import re
import secrets
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import httpx
from fastapi import APIRouter, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware

from core.file_lock import AdvisoryFileLock
from core.operation_profile import list_profiles
from core.src_blackboard import SrcBlackboard

try:
    from core import llm_settings  # type: ignore
except Exception:  # noqa: BLE001
    llm_settings = None  # type: ignore

try:
    from core import llm_pool  # type: ignore
except Exception:  # noqa: BLE001
    llm_pool = None  # type: ignore

from console import deps as _deps
from console.auth import _password_matches, _require_session
from console.models import (
    FindingReportRequest,
    FindingRetestBatchRequest,
    FindingRetestRequest,
    FindingRetestResultRequest,
    ModelActiveRequest,
)
from console.projections import ReadOnlyControlPlane
from console.routers.base import _NOSTORE, Ctx
from core.finding_workflow import FindingRetestStore



def build(ctx: Ctx) -> APIRouter:
    router = APIRouter()

    @router.get("/api/v1/findings")
    def findings(request: Request) -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=ctx.control_plane.findings(), headers=_NOSTORE)

    @router.get("/api/v1/findings/{finding_id}")
    def finding_detail(finding_id: str, request: Request) -> JSONResponse:
        _require_session(request)
        detail = ctx.control_plane.finding_detail(finding_id)
        if not detail:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding_not_found")
        return JSONResponse(content=detail, headers=_NOSTORE)

    @router.post("/api/v1/findings/{finding_id}/report")
    def save_finding_report(finding_id: str, payload: FindingReportRequest, request: Request) -> JSONResponse:
        _require_session(request)
        detail = ctx.control_plane.finding_detail(finding_id)
        if not detail:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding_not_found")
        from console.deps import replace_with_retry
        from pathlib import Path
        import hashlib

        report = str(payload.report or "")
        if not report.strip() or len(report.encode("utf-8")) > 200_000:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="report_invalid_or_too_large")
        current_digest = str(detail.get("evidence_digest") or "")
        if payload.expected_digest != current_digest:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="finding_evidence_changed")
        task_id = str(detail["finding"].get("task") or "")
        output_dir = ctx.control_plane._task_dirs().get(task_id)
        if not output_dir or output_dir.is_symlink() or not output_dir.is_dir():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding_output_not_found")
        report_dir = output_dir / "reports"
        if report_dir.is_symlink():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="report_path_invalid")
        report_dir.mkdir(parents=True, exist_ok=True)
        try:
            if not report_dir.resolve().is_relative_to(output_dir.resolve()):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="report_path_invalid")
        except OSError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="report_path_invalid") from exc
        path = report_dir / f"{finding_id}.md"
        staged = path.with_name("." + path.name + ".tmp")
        staged.write_text(report, encoding="utf-8")
        replace_with_retry(staged, path)
        return JSONResponse(content={"saved": True, "report": report, "evidence_digest": current_digest}, headers=_NOSTORE)

    @router.get("/api/v1/findings/{finding_id}/retests")
    def finding_retests(finding_id: str, request: Request) -> JSONResponse:
        _require_session(request)
        detail = ctx.control_plane.finding_detail(finding_id)
        if not detail:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding_not_found")
        return JSONResponse(content={"finding_id": finding_id, "retests": detail.get("retests", [])}, headers=_NOSTORE)

    @router.post("/api/v1/findings/{finding_id}/retests")
    def start_finding_retest(finding_id: str, payload: FindingRetestRequest, request: Request) -> JSONResponse:
        _require_session(request)
        detail = ctx.control_plane.finding_detail(finding_id)
        if not detail:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding_not_found")
        finding = dict(detail["finding"])
        mode = str(payload.mode or "automatic").strip().lower()
        if mode not in {"automatic", "manual"}:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_retest_mode")
        session_id = str(payload.session_id or finding.get("task") or "").strip()
        store = FindingRetestStore(ctx.state_dir / "finding-retests.jsonl")
        plan, plan_reason = ctx.control_plane.finding_retest_plan(finding_id) if mode == "automatic" else ({}, "")
        if mode == "automatic" and not plan:
            finding["review_reason"] = plan_reason
        review_reason = "" if mode == "automatic" and plan else (plan_reason or "operator_requested_manual_retest")
        record, created = store.create(finding, notes=payload.notes, session_id=session_id, review_reason=review_reason)
        enqueued = False
        # Automatic mode creates exactly one durable bounded replay job. The job
        # still runs through _fetch_for_analysis, so scope, semantic method
        # checks, deletion refusal, rate limiting and request budget remain in
        # force. Manual mode only creates a record for a human to fill in.
        if mode == "automatic" and plan and created and session_id and re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", session_id) and finding.get("target"):
            try:
                from console import jobs as job_service
                job = job_service.get_registry(ctx.state_dir).create(
                    session_id=session_id,
                    turn_id=f"RT-{secrets.token_hex(4)}",
                    kind=job_service.FINDING_RETEST_KIND,
                    target=str(finding.get("target") or ""),
                    payload={
                        "_state_dir": str(ctx.state_dir),
                        "run_id": f"RT-{int(time.time())}-{secrets.token_hex(3)}",
                        "retest_id": record["retest_id"],
                        "finding_id": finding_id,
                        "target": str(finding.get("target") or ""), "request_url": plan["url"],
                        "method": plan["method"], "body": plan["body"], "content_type": plan["content_type"],
                        "original_status": plan.get("expected_status"),
                        "expected_sha256_12": plan.get("expected_sha256_12", ""),
                        "response_markers": plan.get("response_markers", []),
                        "scope_document": plan["scope_document"],
                        "title": f"复测 {finding.get('title') or finding_id}",
                    },
                )
                record = store.bind_job(record["retest_id"], job.job_id, session_id)
                job_service.get_runner(ctx.state_dir).submit(job)
                enqueued = True
            except Exception as exc:
                try:
                    store.set_status(record["retest_id"], "failed", error=f"queue_failed:{str(exc)[:300]}")
                    record = next((row for row in store.list(finding_id) if row.get("retest_id") == record["retest_id"]), record)
                except Exception:
                    pass
        return JSONResponse(content={"created": created, "enqueued": enqueued, "retest": record}, headers=_NOSTORE)

    @router.post("/api/v1/findings/retests/batch")
    def start_finding_retest_batch(payload: FindingRetestBatchRequest, request: Request) -> JSONResponse:
        _require_session(request)
        ids = list(dict.fromkeys(str(value or "").strip() for value in payload.finding_ids if str(value or "").strip()))[:20]
        results: list[dict[str, Any]] = []
        for finding_id in ids:
            try:
                detail = ctx.control_plane.finding_detail(finding_id)
                if not detail:
                    raise ValueError("finding_not_found")
                finding = dict(detail["finding"])
                store = FindingRetestStore(ctx.state_dir / "finding-retests.jsonl")
                plan, plan_reason = ctx.control_plane.finding_retest_plan(finding_id)
                if not plan:
                    finding["review_reason"] = plan_reason
                record, created = store.create(finding, notes=payload.notes, session_id=str(finding.get("task") or ""), review_reason=plan_reason)
                enqueued = False
                session_id = str(record.get("session_id") or "")
                if created and plan and session_id and finding.get("target"):
                    from console import jobs as job_service
                    job = job_service.get_registry(ctx.state_dir).create(
                        session_id=session_id, turn_id=f"RT-{secrets.token_hex(4)}",
                        kind=job_service.FINDING_RETEST_KIND, target=str(finding.get("target") or ""),
                        payload={"_state_dir": str(ctx.state_dir), "run_id": f"RT-{int(time.time())}-{secrets.token_hex(3)}",
                                 "retest_id": record["retest_id"], "finding_id": finding_id,
                                 "target": str(finding.get("target") or ""), "request_url": plan["url"],
                                 "method": plan["method"], "body": plan["body"], "content_type": plan["content_type"],
                                 "original_status": plan.get("expected_status"),
                                 "expected_sha256_12": plan.get("expected_sha256_12", ""),
                                 "response_markers": plan.get("response_markers", []), "scope_document": plan["scope_document"],
                                 "title": f"复测 {finding.get('title') or finding_id}"},
                    )
                    record = store.bind_job(record["retest_id"], job.job_id, session_id)
                    job_service.get_runner(ctx.state_dir).submit(job)
                    enqueued = True
                results.append({"finding_id": finding_id, "created": created, "enqueued": enqueued, "retest": record})
            except Exception as exc:  # bounded per-item failure
                results.append({"finding_id": finding_id, "created": False, "enqueued": False, "error": str(exc)[:200]})
        return JSONResponse(content={"results": results}, headers=_NOSTORE)

    @router.post("/api/v1/findings/{finding_id}/retests/{retest_id}/result")
    def record_finding_retest_result(finding_id: str, retest_id: str, payload: FindingRetestResultRequest, request: Request) -> JSONResponse:
        _require_session(request)
        detail = ctx.control_plane.finding_detail(finding_id)
        if not detail:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding_not_found")
        store = FindingRetestStore(ctx.state_dir / "finding-retests.jsonl")
        row = next((item for item in store.list(finding_id) if item.get("retest_id") == retest_id), None)
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="retest_not_found")
        try:
            result = store.record_result(retest_id, verdict=payload.verdict, summary=payload.summary,
                                         evidence=payload.evidence, checks=payload.checks)
        except (KeyError, ValueError) as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        return JSONResponse(content={"saved": True, "retest": result}, headers=_NOSTORE)

    @router.get("/api/v1/system")
    def system(request: Request) -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=ctx.control_plane.system(), headers=_NOSTORE)

    @router.get("/api/v1/models")
    def models(request: Request) -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=ctx.control_plane.models(), headers=_NOSTORE)

    @router.post("/api/v1/model/active")
    def model_active(payload: ModelActiveRequest, request: Request) -> JSONResponse:
        """R2: 切换活跃 LLM provider(写运行时状态文件;core.llm_pool 下次调用即生效,无需重启)。"""
        _require_session(request)
        result = ctx.control_plane.set_active_model(str(payload.name or ""))
        if not result.get("ok"):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail=str(result.get("error", "invalid")))
        return JSONResponse(content=result, headers=_NOSTORE)

    return router
