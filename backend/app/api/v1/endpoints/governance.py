import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import clamd
from fastapi import APIRouter, Depends, HTTPException, Request, status
from redis.asyncio import Redis
from sqlalchemy import desc, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.deps import get_current_user, require_roles
from app.db.session import get_db
from app.models.ai_request import AIRequest
from app.models.audit import AuditLog
from app.models.code_finding import CodeFinding
from app.models.document import Document
from app.models.user import User, UserRole
from app.core.security import hash_password
from app.schemas.governance import (
    AIRequestOut,
    AuditLogEntryOut,
    FindingOut,
    FindingStatusUpdate,
    FrameworkCoverageOut,
    AdminAccountResetOut,
    AdminAccountResetRequest,
    ServiceComponentHealth,
    ServiceHealthOut,
)
from app.services import vector_store
from app.services.audit_service import record as audit_record

_health_settings = get_settings()


router = APIRouter(prefix="/governance", tags=["governance"])

# Governance data (audit trail, org-wide findings, request telemetry) is
# read here by role, not by row ownership - unlike /documents, which scopes
# by who owns/was-shared a specific row. There's no per-row governance
# permission model to check against; the security_engineer/administrator
# role itself IS the access boundary for this whole router.
_GOVERNANCE_ROLES = (UserRole.SECURITY_ENGINEER, UserRole.ADMINISTRATOR)

_FRAMEWORK_COVERAGE_PATH = Path(__file__).resolve().parents[3] / "data" / "framework_coverage.json"


def _client_meta(request: Request) -> tuple[str, str]:
    ip = request.client.host if request.client else "unknown"
    ua = request.headers.get("user-agent", "unknown")
    return ip, ua


async def _check_postgres(db: AsyncSession) -> ServiceComponentHealth:
    start = time.monotonic()
    try:
        await db.execute(text("SELECT 1"))
        return ServiceComponentHealth(
            name="postgresql", status="healthy", latency_ms=round((time.monotonic() - start) * 1000, 1)
        )
    except Exception as exc:
        return ServiceComponentHealth(name="postgresql", status="unreachable", detail=str(exc))


async def _check_redis() -> ServiceComponentHealth:
    start = time.monotonic()
    client = Redis.from_url(_health_settings.redis_url, decode_responses=False, socket_timeout=3)
    try:
        await client.ping()
        return ServiceComponentHealth(
            name="redis", status="healthy", latency_ms=round((time.monotonic() - start) * 1000, 1)
        )
    except Exception as exc:
        return ServiceComponentHealth(name="redis", status="unreachable", detail=str(exc))
    finally:
        await client.aclose()


async def _check_chromadb() -> ServiceComponentHealth:
    start = time.monotonic()
    try:
        client = vector_store._get_client()
        client.heartbeat()
        return ServiceComponentHealth(
            name="chromadb", status="healthy", latency_ms=round((time.monotonic() - start) * 1000, 1)
        )
    except Exception as exc:
        return ServiceComponentHealth(name="chromadb", status="unreachable", detail=str(exc))


async def _check_clamav() -> ServiceComponentHealth:
    start = time.monotonic()
    try:
        cd = clamd.ClamdNetworkSocket(
            host=_health_settings.clamav_host, port=_health_settings.clamav_port, timeout=5
        )
        cd.ping()
        return ServiceComponentHealth(
            name="clamav", status="healthy", latency_ms=round((time.monotonic() - start) * 1000, 1)
        )
    except Exception as exc:
        return ServiceComponentHealth(name="clamav", status="unreachable", detail=str(exc))


@router.get(
    "/service-health",
    response_model=ServiceHealthOut,
    dependencies=[Depends(require_roles(*_GOVERNANCE_ROLES))],
)
async def get_service_health(db: AsyncSession = Depends(get_db)):
    """
    Live checks, not cached/static data - each dependency is actually
    pinged on every call. Every check is independently try/excepted so
    one dependency being down never breaks the response for the others
    (a getattr-driven `client._get_client()` reach into vector_store's
    module-private connection is intentional here: this endpoint only
    needs a heartbeat, not a public API this module doesn't otherwise
    expose).
    """
    components = [
        await _check_postgres(db),
        await _check_redis(),
        await _check_chromadb(),
        await _check_clamav(),
    ]
    return ServiceHealthOut(checked_at=datetime.now(timezone.utc), components=components)


@router.get(
    "/audit-log",
    response_model=list[AuditLogEntryOut],
    dependencies=[Depends(require_roles(*_GOVERNANCE_ROLES))],
)
async def list_audit_log(
    limit: int = 50,
    offset: int = 0,
    event_category: Optional[str] = None,
    outcome: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    limit = max(1, min(limit, 200))
    offset = max(0, offset)

    query = select(AuditLog).order_by(desc(AuditLog.occurred_at)).limit(limit).offset(offset)
    if event_category:
        query = query.where(AuditLog.event_category == event_category)
    if outcome:
        query = query.where(AuditLog.outcome == outcome)

    result = await db.execute(query)
    return result.scalars().all()


@router.get(
    "/findings",
    response_model=list[FindingOut],
    dependencies=[Depends(require_roles(*_GOVERNANCE_ROLES))],
)
async def list_findings(
    limit: int = 50,
    offset: int = 0,
    severity: Optional[str] = None,
    status_filter: Optional[str] = None,
    category: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Org-wide finding list, unlike GET /code-review/findings/{document_id}
    (Phase 5), which is scoped to one document the caller has permission
    on. This intentionally bypasses per-document ownership - the
    security_engineer/administrator role is the access boundary here,
    same reasoning as the audit log above.
    """
    # Fetches more than the requested page from each source (code
    # findings, audit-derived findings) before merging and re-paginating
    # in Python below - two separate tables can't be paginated together
    # at the SQL level with a single LIMIT/OFFSET, and this project's
    # scale doesn't warrant a UNION-based query for it.
    fetch_limit = limit + offset

    code_query = (
        select(CodeFinding, Document.original_filename)
        .join(Document, Document.id == CodeFinding.document_id)
        .order_by(desc(CodeFinding.created_at))
        .limit(fetch_limit)
    )
    if severity:
        code_query = code_query.where(CodeFinding.severity == severity)
    if status_filter:
        code_query = code_query.where(CodeFinding.status == status_filter)
    if category:
        code_query = code_query.where(CodeFinding.category == category)

    code_result = await db.execute(code_query)
    findings: list[FindingOut] = [
        FindingOut(
            id=str(finding.id),
            document_id=finding.document_id,
            document_filename=filename,
            tool=finding.tool,
            rule_id=finding.rule_id,
            category=finding.category,
            title=finding.title,
            description=finding.description,
            line_number=finding.line_number,
            cvss_score=finding.cvss_score,
            cvss_vector=finding.cvss_vector,
            severity=finding.severity,
            status=finding.status,
            created_at=finding.created_at,
        )
        for finding, filename in code_result.all()
    ]

    # Malware-rejected uploads never get a Document row (see
    # document_service.upload_document), so they can't appear via
    # CodeFinding at all - surfaced here from the audit trail instead,
    # normalized into the same FindingOut shape.
    include_malware = category is None or category == "malware"
    if include_malware and status_filter in (None, "blocked") and severity in (None, "critical"):
        audit_query = (
            select(AuditLog)
            .where(AuditLog.event_type == "document_upload_failed")
            .order_by(desc(AuditLog.occurred_at))
            .limit(fetch_limit)
        )
        audit_result = await db.execute(audit_query)
        for entry in audit_result.scalars().all():
            metadata = entry.metadata_ or {}
            # document_upload_failed covers every upload rejection reason
            # (missing extension, bad content-type, oversized file, etc.),
            # not just malware - only the malware-scan rejection message
            # belongs here as a "malware detected" finding.
            if metadata.get("reason") != "File was rejected by malware scanning.":
                continue
            findings.append(
                FindingOut(
                    id=f"audit-{entry.id}",
                    document_id=None,
                    document_filename=metadata.get("filename"),
                    tool="ClamAV",
                    rule_id="malware-scan-rejection",
                    category="malware",
                    title="Malware detected on upload",
                    description=metadata.get("reason", "File was rejected by malware scanning."),
                    line_number=None,
                    cvss_score=None,
                    cvss_vector=None,
                    severity="critical",
                    status="blocked",
                    created_at=entry.occurred_at,
                )
            )

    findings.sort(key=lambda f: f.created_at, reverse=True)
    return findings[offset : offset + limit]


@router.patch(
    "/findings/{finding_id}/status",
    response_model=FindingOut,
    dependencies=[Depends(require_roles(*_GOVERNANCE_ROLES))],
)
async def update_finding_status(
    finding_id: uuid.UUID,
    payload: FindingStatusUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ip, ua = _client_meta(request)

    query = (
        select(CodeFinding, Document.original_filename)
        .join(Document, Document.id == CodeFinding.document_id)
        .where(CodeFinding.id == finding_id)
    )
    result = await db.execute(query)
    row = result.first()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found.")
    finding, filename = row

    previous_status = finding.status
    finding.status = payload.status

    await audit_record(
        db,
        event_type="finding_status_changed",
        event_category="governance",
        actor_user_id=user.id,
        actor_email=user.email,
        ip_address=ip,
        user_agent=ua,
        resource_type="code_finding",
        resource_id=str(finding_id),
        metadata={
            "previous_status": previous_status,
            "new_status": payload.status,
            "rule_id": finding.rule_id,
        },
    )
    await db.commit()
    await db.refresh(finding)

    return FindingOut(
        id=finding.id,
        document_id=finding.document_id,
        document_filename=filename,
        tool=finding.tool,
        rule_id=finding.rule_id,
        category=finding.category,
        title=finding.title,
        description=finding.description,
        line_number=finding.line_number,
        cvss_score=finding.cvss_score,
        cvss_vector=finding.cvss_vector,
        severity=finding.severity,
        status=finding.status,
        created_at=finding.created_at,
    )


@router.get(
    "/ai-requests",
    response_model=list[AIRequestOut],
    dependencies=[Depends(require_roles(*_GOVERNANCE_ROLES))],
)
async def list_ai_requests(
    limit: int = 50,
    offset: int = 0,
    feature: Optional[str] = None,
    provider: Optional[str] = None,
    blocked: Optional[bool] = None,
    db: AsyncSession = Depends(get_db),
):
    limit = max(1, min(limit, 200))
    offset = max(0, offset)

    query = (
        select(AIRequest, User.email)
        .join(User, User.id == AIRequest.user_id)
        .order_by(desc(AIRequest.created_at))
        .limit(limit)
        .offset(offset)
    )
    if feature:
        query = query.where(AIRequest.feature == feature)
    if provider:
        query = query.where(AIRequest.provider == provider)
    if blocked is not None:
        query = query.where(AIRequest.blocked == blocked)

    result = await db.execute(query)
    rows = result.all()
    return [
        AIRequestOut(
            id=req.id,
            user_id=req.user_id,
            user_email=email,
            feature=req.feature,
            provider=req.provider,
            model=req.model,
            prompt_redacted=req.prompt_redacted,
            response_redacted=req.response_redacted,
            input_tokens=req.input_tokens,
            output_tokens=req.output_tokens,
            guardrail_flags=req.guardrail_flags,
            blocked=req.blocked,
            latency_ms=req.latency_ms,
            created_at=req.created_at,
        )
        for req, email in rows
    ]


@router.get(
    "/framework-coverage",
    response_model=FrameworkCoverageOut,
    dependencies=[Depends(require_roles(*_GOVERNANCE_ROLES))],
)
async def get_framework_coverage():
    """
    Static, curated data - not database-driven like the other governance
    endpoints. This deliberately doesn't change based on runtime state;
    it's an explicit, versioned claim about what's actually implemented,
    reviewed and updated by hand (see the file's own methodology field
    and Phase 8's build history), not something computed from the current
    contents of code_findings or any other table.
    """
    if not _FRAMEWORK_COVERAGE_PATH.exists():
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            f"Framework coverage data file not found at {_FRAMEWORK_COVERAGE_PATH}",
        )
    with open(_FRAMEWORK_COVERAGE_PATH) as f:
        data = json.load(f)
    return FrameworkCoverageOut(**data)


@router.post(
    "/users/{user_id}/admin-reset",
    response_model=AdminAccountResetOut,
)
async def admin_reset_user_account(
    user_id: uuid.UUID,
    payload: AdminAccountResetRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _: None = Depends(require_roles(*_GOVERNANCE_ROLES)),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    user.failed_login_attempts = 0
    user.locked_until = None

    password_reset = False
    if payload.new_password:
        user.password_hash = hash_password(payload.new_password)
        user.must_change_password = True
        password_reset = True

    await db.commit()
    await db.refresh(user)

    ip, ua = _client_meta(request)
    await audit_record(
        db,
        event_type="admin_account_reset",
        event_category="admin_action",
        actor_user_id=current_user.id,
        actor_email=current_user.email,
        resource_type="user",
        resource_id=str(user.id),
        ip_address=ip,
        user_agent=ua,
        metadata={"target_email": user.email, "password_reset": password_reset},
    )

    return AdminAccountResetOut(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        role=user.role.value,
        is_locked=False,
        password_reset=password_reset,
    )
