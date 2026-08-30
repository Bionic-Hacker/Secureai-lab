from typing import Optional

from fastapi import APIRouter, Depends
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import require_roles
from app.db.session import get_db
from app.models.audit import AuditLog
from app.models.user import UserRole
from app.schemas.governance import AuditLogEntryOut

router = APIRouter(prefix="/governance", tags=["governance"])

# Governance data (audit trail, org-wide findings, request telemetry) is
# read here by role, not by row ownership - unlike /documents, which scopes
# by who owns/was-shared a specific row. There's no per-row governance
# permission model to check against; the security_engineer/administrator
# role itself IS the access boundary for this whole router.
_GOVERNANCE_ROLES = (UserRole.SECURITY_ENGINEER, UserRole.ADMINISTRATOR)


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
