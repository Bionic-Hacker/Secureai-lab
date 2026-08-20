"""
Central audit-writing service. Every security-relevant action funnels
through record() so the audit trail has one consistent shape and can't
be silently skipped by a code path that "forgot".

This never raises into the caller's request flow: a failure to write an
audit record must not block or corrupt the underlying operation, but it
IS logged at ERROR level so ops can alert on it.
"""
import logging
from typing import Any, Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog

logger = logging.getLogger("secureai.audit")


async def record(
    db: AsyncSession,
    *,
    event_type: str,
    event_category: str,
    actor_user_id: Optional[UUID] = None,
    actor_email: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    metadata: Optional[dict[str, Any]] = None,
    outcome: str = "success",
) -> None:
    try:
        entry = AuditLog(
            event_type=event_type,
            event_category=event_category,
            actor_user_id=actor_user_id,
            actor_email=actor_email,
            resource_type=resource_type,
            resource_id=resource_id,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata_=metadata or {},
            outcome=outcome,
        )
        db.add(entry)
        await db.flush()
    except Exception:
        logger.exception(
            "AUDIT WRITE FAILED event_type=%s category=%s actor=%s",
            event_type, event_category, actor_email,
        )
