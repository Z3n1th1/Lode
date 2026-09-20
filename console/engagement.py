"""The durable authorisation record for a run started from a whole scope document.

Everything that starts a run from a document — a paste, an upload, the watched
inbox — mints one of these on confirmation.  It is the only thing a reviewer can
read afterwards that says what the run was permitted to do, so it stores the
**verbatim document** next to the derived fields: every consumer re-parses the
document with ``SurfaceScope.from_mapping`` rather than trusting a re-statement of
it, and a re-statement is exactly what drifts.

Mirrors :class:`core.intake_state.TargetCardStore`: write-once with ``O_EXCL``,
canonical JSON bytes, digest drift is a mismatch and not a newer version.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Mapping

from agents.scope_document import ScopeDocument
from agents.surface_discovery import SurfaceScope
from core.file_lock import AdvisoryFileLock
from core.intake_state import canonical_digest

SCHEMA = "EngagementAuthorization/v1"
# ``from_mapping`` 给没写程序名的文档填的就是这个,所以它不是一个程序名。
DEFAULT_PROGRAM = "authorized-program"
_SAFE_ID_RE = re.compile(r"[^a-z0-9]+")
_AUTHORIZATION_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}")


class EngagementStateError(ValueError):
    """这份授权记录不能安全地被建立或复读。"""


def authorization_id_for(program: str, document_digest: str) -> str:
    """A stable, readable name for one authorisation.

    Content-derived on purpose: 程序文档是会更新的(NBA 那份明说"每次跑之前重读
    policy_scopes"),而同一份更新的文档是一份**新的**授权,不是同一份的漂移。
    按程序名取 id 会让"换了文档"变成"卡对不上" —— 于是操作员照政策更新了文档,
    产品却拒绝开跑。
    """
    slug = _SAFE_ID_RE.sub("-", str(program or "").lower()).strip("-")[:48] or "engagement"
    return f"{slug}-{str(document_digest)[:12]}"


def authorization_from_document(parsed: ScopeDocument, *, source: str) -> Dict[str, Any]:
    """Build the record for a document that has already been parsed and confirmed."""
    document = dict(parsed.document)
    document_digest = canonical_digest(document)
    declared = str(parsed.scope.program or "").strip()
    declared = "" if declared in ("", DEFAULT_PROGRAM) else declared
    authorization_id = authorization_id_for(declared or "engagement", document_digest)
    # 没有程序名的文档必须在这里拿到身份:``from_mapping`` 会把 engagement 回落成
    # program 的默认值,于是所有这类文档共用一个 "authorized-program" 桶
    # (见 core/rate_limit.bucket_key)。方向是安全的 —— 过度共享只会更慢 ——
    # 但身份是错的,而且两个程序会互相限速。
    program = declared or authorization_id
    engagement = str(parsed.scope.engagement or "").strip()
    if not engagement or engagement == DEFAULT_PROGRAM:
        engagement = program
    return {
        "schema": SCHEMA,
        "authorization_id": authorization_id,
        "program": program,
        "engagement": engagement,
        "authorization": parsed.scope.authorization,
        # 逐字原文。派生字段是给人读的,这一份是给程序读的 —— 两者不一致时以它为准。
        "document": document,
        "document_digest": document_digest,
        "hosts": list(parsed.hosts),
        "rejected": [[host, reason] for host, reason in parsed.rejected],
        "forbidden_hosts": list(parsed.scope.forbidden),
        "allowed_methods": list(parsed.scope.allowed_methods),
        "allow_request_body": bool(parsed.scope.allow_request_body),
        "requests_per_second": round(parsed.scope.requests_per_second, 6),
        "max_fanout": int(parsed.max_fanout),
        "source": str(source or ""),
        # 刻意没有 created_at:它必须留在 digest 之外,否则同一份文档每次铸出来的
        # 记录 digest 都不同,materialize 的"已存在且必须逐字相同"就永远不成立 ——
        # 重复确认会变成卡对不上。文件的 mtime 就是创建时间。
    }


def _validate(record: Any) -> Dict[str, Any]:
    if not isinstance(record, dict):
        raise EngagementStateError("authorization_record_invalid")
    if record.get("schema") != SCHEMA:
        raise EngagementStateError("authorization_record_invalid")
    authorization_id = str(record.get("authorization_id") or "")
    if _AUTHORIZATION_ID_RE.fullmatch(authorization_id) is None:
        raise EngagementStateError("authorization_record_invalid")
    document = record.get("document")
    if not isinstance(document, dict) or not document:
        raise EngagementStateError("authorization_record_invalid")
    if _DIGEST_RE.fullmatch(str(record.get("document_digest") or "")) is None:
        raise EngagementStateError("authorization_record_invalid")
    hosts = record.get("hosts")
    if not isinstance(hosts, list) or not hosts or not all(isinstance(host, str) and host for host in hosts):
        raise EngagementStateError("authorization_record_invalid")
    if len(hosts) != len(set(hosts)):
        raise EngagementStateError("authorization_record_invalid")
    if not isinstance(record.get("forbidden_hosts"), list):
        raise EngagementStateError("authorization_record_invalid")
    methods = record.get("allowed_methods")
    if not isinstance(methods, list) or not all(isinstance(method, str) and method for method in methods):
        raise EngagementStateError("authorization_record_invalid")
    if not isinstance(record.get("allow_request_body"), bool):
        raise EngagementStateError("authorization_record_invalid")
    try:
        max_fanout = int(record.get("max_fanout"))
    except (TypeError, ValueError) as exc:
        raise EngagementStateError("authorization_record_invalid") from exc
    if max_fanout < 1:
        raise EngagementStateError("authorization_record_invalid")
    # 记录里的原文必须自己就能过一遍 canonical loader。走的是同一个 from_mapping,
    # 所以"记录能读"和"scope 文件能读"是同一句话。
    scope = SurfaceScope.from_mapping(document)
    try:
        scope.require_authorization()
    except ValueError as exc:
        raise EngagementStateError(str(exc)) from exc
    return dict(record)


def _canonical_bytes(record: Mapping[str, Any]) -> bytes:
    return (json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8")


class EngagementAuthorizationStore:
    """Write one authorisation once; every later reader has to match it exactly."""

    def __init__(self, state_dir: Path | str) -> None:
        self.state_dir = Path(state_dir)
        self.root = self.state_dir / "authorizations"
        self._lock_path = self.root / ".authorizations.lock"

    def _lock(self) -> AdvisoryFileLock:
        return AdvisoryFileLock(self._lock_path)

    def path_for(self, authorization_id: str) -> Path:
        if _AUTHORIZATION_ID_RE.fullmatch(str(authorization_id or "")) is None:
            raise EngagementStateError("authorization_id_invalid")
        return self.root / f"{authorization_id}.json"

    def _read(self, path: Path, *, expected_digest: str, authorization_id: str) -> Dict[str, Any]:
        if not path.is_file() or path.is_symlink():
            raise EngagementStateError("canonical_authorization_unavailable")
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EngagementStateError("canonical_authorization_unavailable") from exc
        try:
            record = _validate(record)
        except EngagementStateError as exc:
            raise EngagementStateError("canonical_authorization_mismatch") from exc
        digest = canonical_digest(record)
        if digest != expected_digest:
            raise EngagementStateError("canonical_authorization_mismatch")
        return {
            "authorization": record,
            "authorization_digest": digest,
            "authorization_id": authorization_id,
            "authorization_ref": str(path),
        }

    def materialize(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Create the record once, or require the stored one to match exactly."""
        record = _validate(record)
        authorization_id = str(record["authorization_id"])
        path = self.path_for(authorization_id)
        expected_digest = canonical_digest(record)
        payload = _canonical_bytes(record)
        with self._lock():
            if path.exists():
                return self._read(path, expected_digest=expected_digest, authorization_id=authorization_id)
            path.parent.mkdir(parents=True, exist_ok=True)
            try:
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                return self._read(path, expected_digest=expected_digest, authorization_id=authorization_id)
            except OSError as exc:
                raise EngagementStateError("canonical_authorization_unavailable") from exc
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
            except OSError as exc:
                raise EngagementStateError("canonical_authorization_unavailable") from exc
        return {
            "authorization": record,
            "authorization_digest": expected_digest,
            "authorization_id": authorization_id,
            "authorization_ref": str(path),
        }

    def load(self, authorization_id: str, *, expected_digest: str = "") -> Dict[str, Any]:
        """Resolve the stored record — how a job finds the scope it was confirmed with.

        ``expected_digest`` 是调用方确认过的那个 digest。对不上是**不匹配,不是一个
        更新的版本**:来这里复读的人正要照着它发请求,漂移就必须失败。
        """
        path = self.path_for(authorization_id)
        if not path.is_file() or path.is_symlink():
            raise EngagementStateError("canonical_authorization_unavailable")
        try:
            record = _validate(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EngagementStateError("canonical_authorization_unavailable") from exc
        digest = canonical_digest(record)
        if expected_digest and digest != expected_digest:
            raise EngagementStateError("canonical_authorization_mismatch")
        return {
            "authorization": record,
            "authorization_digest": digest,
            "authorization_id": authorization_id,
            "authorization_ref": str(path),
        }


__all__ = [
    "DEFAULT_PROGRAM", "EngagementAuthorizationStore", "EngagementStateError", "SCHEMA",
    "authorization_id_for", "authorization_from_document",
]
