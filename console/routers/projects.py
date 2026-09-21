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
from core.intake_state import IntakeStateError
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
from console import intake
from console.auth import _password_matches, _require_session
from console.models import (
    ProjectIntakeConfirmRequest,
    ProjectIntakeRequest,
    ScopeIntakePreviewRequest,
    SessionGuidanceRequest,
)
from console.projections import ReadOnlyControlPlane
from console.routers.base import _NOSTORE, Ctx
from console.deps import (
    MAX_VISIBLE_ITEMS,
    SESSION_ID_RE,
    _text,
    _valid_profile,
    _valid_public_target,
    _write_guidance,
)

# Gate reason → HTTP status.  Anything not listed is a broken assumption inside
# the gate itself (schema/digest machinery), which is a 500, not the operator's
# fault.  409 = the binding does not match or something is already pending;
# 410 = the preview is gone (TTL elapsed, or it was explicitly discarded).
_INTAKE_CLIENT_ERRORS = {
    "intake_target_required": status.HTTP_400_BAD_REQUEST,
    "intake_target_invalid": status.HTTP_400_BAD_REQUEST,
    "intake_profile_and_goal_required": status.HTTP_400_BAD_REQUEST,
    "brute_force_out_of_scope": status.HTTP_400_BAD_REQUEST,
    "no_pending_intake_preview": status.HTTP_409_CONFLICT,
    "pending_intake_exists": status.HTTP_409_CONFLICT,
    "intake_confirmation_binding_mismatch": status.HTTP_409_CONFLICT,
    "intake_preview_expired": status.HTTP_410_GONE,
    "intake_confirmation_expired": status.HTTP_410_GONE,
    # 授权文档那条路。每一个都是"这份文档不能开跑"的具体原因,所以是 400 而不是 500:
    # 出问题的是输入,不是门本身。
    "no_pending_scope_intake_preview": status.HTTP_409_CONFLICT,
    "scope_document_required": status.HTTP_400_BAD_REQUEST,
    "scope_document_not_recognised": status.HTTP_400_BAD_REQUEST,
    "scope_document_not_an_object": status.HTTP_400_BAD_REQUEST,
    "scope_document_no_hosts": status.HTTP_400_BAD_REQUEST,
    "scope_document_domains_not_allowed": status.HTTP_400_BAD_REQUEST,
    "scope_document_ip_range_not_allowed": status.HTTP_400_BAD_REQUEST,
    "surface_authorization_required": status.HTTP_400_BAD_REQUEST,
    "surface_scope_required": status.HTTP_400_BAD_REQUEST,
    "authorization_record_invalid": status.HTTP_400_BAD_REQUEST,
    "host_not_in_authorization": status.HTTP_400_BAD_REQUEST,
}


def _intake_error(reason: str, ctx: Ctx) -> JSONResponse:
    """Turn a gate refusal into the operator-facing response.

    The body always carries ``detail`` as a string (the frontend surfaces it
    verbatim).  A conflict over an existing preview is only actionable if the
    caller can see it, so that one also carries ``pending`` and the UI can offer
    放弃 instead of leaving the operator stuck.
    """
    code = _INTAKE_CLIENT_ERRORS.get(reason, status.HTTP_500_INTERNAL_SERVER_ERROR)
    if code == status.HTTP_500_INTERNAL_SERVER_ERROR:
        return JSONResponse(content={"detail": "intake_gate_failed"}, status_code=code, headers=_NOSTORE)
    body: Dict[str, Any] = {"detail": reason}
    if reason == "pending_intake_exists":
        # 一个槽能放两种东西,所以"挡路的是哪一张卡"必须说清楚 —— 只说"已经有一个
        # 待确认了",操作员不知道该放弃什么。``pending_kind`` 让 UI 用对应的渲染器,
        # 而不是靠猜字段。
        try:
            target_preview = intake.pending_preview(ctx.state_dir)
            scope_preview = intake.scope_pending_preview(ctx.state_dir)
        except OSError:
            target_preview = scope_preview = None
        if target_preview is not None:
            body["pending"] = intake.preview_view(target_preview)
            body["pending_kind"] = "target"
        elif scope_preview is not None:
            body["pending"] = intake.scope_preview_view(scope_preview)
            body["pending_kind"] = "document"
    return JSONResponse(content=body, status_code=code, headers=_NOSTORE)


def _scope_error(exc: Any) -> JSONResponse:
    """Turn a document refusal into the operator-facing response.

    ``items`` 带上被点名的域/网段 —— 只说"不行"而不说"哪个不行",操作员只能靠猜,
    而这几条拒绝恰恰是最容易让人以为产品坏了的地方。
    """
    reason = str(getattr(exc, "reason", "") or exc)
    code = _INTAKE_CLIENT_ERRORS.get(reason, status.HTTP_400_BAD_REQUEST)
    body: Dict[str, Any] = {"detail": reason}
    detail = str(getattr(exc, "detail", "") or "")
    if detail:
        body["items"] = detail
    return JSONResponse(content=body, status_code=code, headers=_NOSTORE)


def build(ctx: Ctx) -> APIRouter:
    router = APIRouter()

    @router.get("/api/v1/proxy")
    def proxy(request: Request) -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=ctx.control_plane.proxy(), headers=_NOSTORE)

    @router.get("/api/v1/report")
    def report(request: Request, task_id: str = "") -> Response:
        _require_session(request)
        return Response(content=ctx.control_plane.report(task_id), media_type="text/plain; charset=utf-8",
                        headers=_NOSTORE)

    @router.get("/api/v1/profiles")
    def profiles(request: Request) -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=ctx.control_plane.profiles_detail(), headers=_NOSTORE)

    @router.get("/api/v1/task")
    def task(request: Request, id: str = "") -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=ctx.control_plane.task_detail(id), headers=_NOSTORE)

    @router.get("/api/v1/projects")
    def projects(request: Request, offset: int = 0, limit: int = MAX_VISIBLE_ITEMS) -> JSONResponse:
        """分页的项目列表。响应体带 total,界面才能说"还有多少个"而不是假装到底了。"""
        _require_session(request)
        return JSONResponse(content=ctx.control_plane.projects(offset=offset, limit=limit),
                            headers=_NOSTORE)

    @router.get("/api/v1/project")
    def project(request: Request, id: str = "") -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=ctx.control_plane.project_detail(id), headers=_NOSTORE)

    @router.get("/api/v1/trajectory")
    def trajectory(request: Request, id: str = "") -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=ctx.control_plane.session_trajectory(id), headers=_NOSTORE)

    @router.post("/api/v1/session/guidance")
    def session_guidance(payload: SessionGuidanceRequest, request: Request) -> JSONResponse:
        """P5-e 受控写:对某会话追加"继续深挖"指导。console 直发=直接进处理队列;
        飞书侧只收提醒通知(不带审批要求)。若 agent 侧判定触发人工门,审批按钮在 console 就地支出。"""
        _require_session(request)
        if not SESSION_ID_RE.fullmatch(str(payload.session_id or "")):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_session_id")
        target = _valid_public_target(payload.target)
        if not target:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_target")
        guidance = _text(payload.guidance, limit=1000).strip()
        if not guidance:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="empty_guidance")
        gid = f"SG-{int(time.time())}-{secrets.token_hex(3)}"
        rec = {"schema": "SessionGuidanceRequest/v1", "id": gid,
               "session_id": _text(payload.session_id, limit=128), "target": target,
               "guidance": guidance, "status": "pending_review", "origin": "console",
               "created_at": time.time(), "created_by": "control_plane"}
        try:
            _write_guidance(ctx.control_plane.state_dir, rec)
        except OSError:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="write_failed")
        return JSONResponse(content={"ok": True, "id": gid, "status": "pending_review",
                                     "note": "已提交(console 直发,排队处理;若触发人工门会在本页就地支审批按钮)"},
                            headers=_NOSTORE)

    @router.get("/api/v1/session/guidance")
    def session_guidance_list(request: Request, id: str = "") -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=ctx.control_plane.session_guidance_list(id), headers=_NOSTORE)

    @router.post("/api/v1/project/intake")
    def project_intake(payload: ProjectIntakeRequest, request: Request) -> JSONResponse:
        """P5-b 第一步:铸一个 digest 绑定的预览。**不执行、不建卡**。

        以前这里写 ProjectIntakeRequest/v1 文件,而没有任何消费者会读它 —— 提交完
        永远停在 pending_review。现在它调的是真正的门(core.intake_state)。
        """
        _require_session(request)
        target = _valid_public_target(payload.target_url)
        if not target:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_target")
        profile = _valid_profile(payload.engagement_profile)
        if not profile:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_profile")
        # 空 instruction 的收据会被 agent 侧判为 intake_receipt_invalid,所以门在
        # 入口就要求它非空,而不是让它变成一个必然失败的预览。
        instruction = _text(payload.instruction, limit=1000).strip()
        if not instruction:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="empty_instruction")
        try:
            preview = intake.start_preview(
                ctx.state_dir, target=target, profile_name=profile,
                instruction=instruction, toggles=payload.toggles,
            )
        except IntakeStateError as exc:
            return _intake_error(str(exc), ctx)
        except OSError:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="intake_write_failed")
        return JSONResponse(content={"ok": True, "status": "preview", **intake.preview_view(preview)},
                            headers=_NOSTORE)

    @router.post("/api/v1/project/intake/confirm")
    def project_intake_confirm(payload: ProjectIntakeConfirmRequest, request: Request) -> JSONResponse:
        """P5-b 第二步:回显 intake_id + options_digest,验证绑定、写收据、落 TargetCard,
        然后开跑 —— 卡落盘之后才允许起任务,顺序就是这条链的全部意义。"""
        _require_session(request)
        try:
            result = intake.confirm(
                ctx.state_dir,
                intake_id=_text(payload.intake_id, limit=128),
                options_digest=_text(payload.options_digest, limit=64),
            )
        except IntakeStateError as exc:
            return _intake_error(str(exc), ctx)
        except OSError:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="target_card_write_failed")

        session_id = _text(payload.session_id, limit=128)
        if session_id and not SESSION_ID_RE.fullmatch(session_id):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_session_id")
        run: Optional[Dict[str, Any]] = None
        if payload.run:
            from console import jobs as _jobs

            try:
                run = _jobs.start_target_run(ctx.state_dir, confirmed=result, session_id=session_id)
            except OSError:
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="run_start_failed")
        return JSONResponse(content={
            "ok": True, "status": "confirmed",
            "intake_id": result["intake_id"],
            "target": result["target"],
            "canonical_host": result["canonical_host"],
            "profile_name": result["profile_name"],
            "instruction": result["instruction"],
            "options_digest": result["options_digest"],
            "target_id": result["target_id"],
            "target_card_digest": result["target_card_digest"],
            "target_card_ref": result["target_card_ref"],
            "run": run,
            # 没开跑就别假装跑起来了:这句话只在有 run 的时候说。
            "note": "卡已落盘,已按它起了一轮。" if run else "卡已落盘,未开跑(agent 侧可按 target_id 解析)。",
        }, headers=_NOSTORE)

    @router.post("/api/v1/project/intake/discard")
    def project_intake_discard(request: Request) -> JSONResponse:
        """放弃待确认的预览(与 TTL 到期写同一个 preview_expired 事件)。"""
        _require_session(request)
        try:
            discarded = intake.discard(ctx.state_dir)
        except OSError:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="intake_write_failed")
        return JSONResponse(content={"ok": True, "discarded": discarded}, headers=_NOSTORE)

    @router.get("/api/v1/project/intake/pending")
    def project_intake_pending(request: Request) -> JSONResponse:
        _require_session(request)
        try:
            preview = intake.pending_preview(ctx.state_dir)
            scope_preview = intake.scope_pending_preview(ctx.state_dir)
        except OSError:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="intake_read_failed")
        # 监听目录那些没被收下的文件:不说清楚,操作员只会看到"拖进去没反应"。
        try:
            from console import scope_inbox

            rejects = scope_inbox.ScopeInbox(ctx.state_dir).rejects()
        except Exception:  # noqa: BLE001 - 这一栏是附加信息,读不到不该让整条路失败
            rejects = []
        return JSONResponse(
            content={"preview": intake.preview_view(preview) if preview else None,
                     # 一个槽,两种形状:UI 按哪个非空决定渲染哪张确认卡。
                     "scope_preview": intake.scope_preview_view(scope_preview) if scope_preview else None,
                     "scope_rejects": rejects,
                     "ttl_seconds": intake.default_ttl_seconds()},
            headers=_NOSTORE,
        )

    @router.post("/api/v1/project/engagement/preview")
    def project_engagement_preview(payload: ScopeIntakePreviewRequest, request: Request) -> JSONResponse:
        """第一步:把一份授权文档读通,铸一个 digest 绑定的预览。**不建记录、不开跑**。

        粘贴、上传、监听目录三个入口都到这里 —— 一个判定、一道闸门。
        """
        _require_session(request)
        document = dict(payload.document) if isinstance(payload.document, dict) and payload.document else None
        if document is None and not _text(payload.text).strip():
            # 空的和"不是文档"是两回事:前者是操作员没给东西,后者是给错了东西。
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="scope_document_required")
        source = "upload" if _text(payload.filename) else "paste"
        try:
            preview = intake.start_scope_preview(
                ctx.state_dir, source=source,
                instruction=_text(payload.instruction, limit=1000).strip(),
                text=payload.text, document=document,
            )
        except IntakeStateError as exc:
            return _intake_error(str(exc), ctx)
        except ValueError as exc:  # ScopeDocumentError 是 ValueError,且带 reason
            return _scope_error(exc)
        except OSError:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="intake_write_failed")
        return JSONResponse(content={"ok": True, "status": "preview", **intake.scope_preview_view(preview)},
                            headers=_NOSTORE)

    @router.post("/api/v1/project/engagement/confirm")
    def project_engagement_confirm(payload: ProjectIntakeConfirmRequest, request: Request) -> JSONResponse:
        """第二步:回显绑定、铸授权记录,然后每台主机起一个 job。

        记录落盘之后才允许起任务 —— 顺序就是这条链的全部意义。超出文档自己写的
        ``max_fanout`` 的部分如实回报。
        """
        _require_session(request)
        try:
            result = intake.confirm_scope(
                ctx.state_dir,
                intake_id=_text(payload.intake_id, limit=128),
                options_digest=_text(payload.options_digest, limit=64),
            )
        except IntakeStateError as exc:
            return _intake_error(str(exc), ctx)
        except ValueError as exc:
            return _scope_error(exc)
        except OSError:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                detail="authorization_write_failed")

        session_id = _text(payload.session_id, limit=128)
        if session_id and not SESSION_ID_RE.fullmatch(session_id):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_session_id")
        run: Optional[Dict[str, Any]] = None
        if payload.run:
            from console import jobs as _jobs

            try:
                run = _jobs.start_engagement_run(ctx.state_dir, confirmed=result, session_id=session_id)
            except OSError:
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="run_start_failed")
            except ValueError as exc:
                return _scope_error(exc)
        note = (f"授权记录已落盘,已起 {run['launched']} 个任务。" if run
                else "授权记录已落盘,未开跑。")
        if run and run.get("skipped"):
            note += f"另有 {run['skipped']} 台超出文档写的上限,没起。"
        return JSONResponse(content={
            "ok": True, "status": "confirmed",
            "intake_id": result["intake_id"],
            "program": result["program"],
            "instruction": result["instruction"],
            "options_digest": result["options_digest"],
            "document_digest": result["document_digest"],
            "authorization_id": result["authorization_id"],
            "authorization_digest": result["authorization_digest"],
            "authorization_ref": result["authorization_ref"],
            "hosts": result["hosts"],
            "max_fanout": result["max_fanout"],
            # 确认之后操作员还要能看到"这次允许做什么"。预览页有「能力」那一行,
            # 确认响应以前把它丢了。
            "allowed_methods": result["allowed_methods"],
            "allow_request_body": result["allow_request_body"],
            "requests_per_second": result["requests_per_second"],
            "run": run,
            "note": note,
        }, headers=_NOSTORE)

    @router.post("/api/v1/project/engagement/discard")
    def project_engagement_discard(request: Request) -> JSONResponse:
        """放弃待确认的那份文档(与 TTL 到期写同一个 preview_expired 事件)。"""
        _require_session(request)
        try:
            discarded = intake.discard(ctx.state_dir)
        except OSError:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="intake_write_failed")
        return JSONResponse(content={"ok": True, "discarded": discarded}, headers=_NOSTORE)

    @router.get("/api/v1/project/intakes")
    def project_intakes(request: Request) -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=ctx.control_plane.pending_intakes(), headers=_NOSTORE)

    @router.get("/api/v1/project/results")
    def project_results(request: Request, id: str = "") -> JSONResponse:
        _require_session(request)
        return JSONResponse(content=ctx.control_plane.project_results(id), headers=_NOSTORE)

    return router
