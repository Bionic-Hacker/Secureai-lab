import json
import uuid
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user, require_roles
from app.db.session import get_db
from app.models.ai_request import AIRequest
from app.models.audit import AuditLog
from app.models.code_finding import CodeFinding
from app.models.document import Document
from app.models.user import User, UserRole
from app.schemas.governance import (
    AIRequestOut,
    AuditLogEntryOut,
    FindingOut,
    FindingStatusUpdate,
    FrameworkCoverageOut,
)
from app.services.audit_service import record as audit_record

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
    limit = max(1, min(limit, 200))
    offset = max(0, offset)

    query = (
        select(CodeFinding, Document.original_filename)
        .join(Document, Document.id == CodeFinding.document_id)
        .order_by(desc(CodeFinding.created_at))
        .limit(limit)
        .offset(offset)
    )
    if severity:
        query = query.where(CodeFinding.severity == severity)
    if status_filter:
        query = query.where(CodeFinding.status == status_filter)
    if category:
        query = query.where(CodeFinding.category == category)

    result = await db.execute(query)
    rows = result.all()
    return [
        FindingOut(
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
        for finding, filename in rows
    ]


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
