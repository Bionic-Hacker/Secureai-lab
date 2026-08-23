import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user
from app.db.session import get_db
from app.models.threat_model import ThreatEntry, ThreatModel
from app.models.user import User
from app.schemas.threat_model import (
    ThreatEntryCreate,
    ThreatEntryOut,
    ThreatEntryUpdate,
    ThreatModelCreate,
    ThreatModelOut,
    ThreatModelSummaryOut,
)
from app.services import threat_model_service
from app.services.audit_service import record as audit_record

router = APIRouter(prefix="/threat-models", tags=["threat-models"])


async def _load_or_404(db: AsyncSession, threat_model_id: uuid.UUID) -> ThreatModel:
    result = await db.execute(select(ThreatModel).where(ThreatModel.id == threat_model_id))
    model = result.scalar_one_or_none()
    if model is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Threat model not found.")
    return model


@router.post("", response_model=ThreatModelOut, status_code=status.HTTP_201_CREATED)
async def create_threat_model(
    payload: ThreatModelCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ip = request.client.host if request.client else "unknown"
    ua = request.headers.get("user-agent", "unknown")

    try:
        model = await threat_model_service.create_threat_model(
            db, user.id, payload.title, payload.system_description, payload.generate_with_ai
        )
    except threat_model_service.ThreatGenerationError as e:
        await db.rollback()
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(e))

    await audit_record(
        db, event_type="threat_model_created", event_category="ai" if payload.generate_with_ai else "admin",
        actor_user_id=user.id, actor_email=user.email, ip_address=ip, user_agent=ua,
        resource_type="threat_model", resource_id=str(model.id),
    )
    await db.commit()
    await db.refresh(model)

    result = await db.execute(select(ThreatEntry).where(ThreatEntry.threat_model_id == model.id))
    entries = list(result.scalars().all())
    return ThreatModelOut.model_validate({**model.__dict__, "entries": entries})


@router.get("", response_model=list[ThreatModelSummaryOut])
async def list_threat_models(db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    result = await db.execute(
        select(ThreatModel, func.count(ThreatEntry.id))
        .outerjoin(ThreatEntry, ThreatEntry.threat_model_id == ThreatModel.id)
        .group_by(ThreatModel.id)
        .order_by(ThreatModel.created_at.desc())
    )
    return [
        ThreatModelSummaryOut(id=m.id, title=m.title, status=m.status, entry_count=count, created_at=m.created_at)
        for m, count in result.all()
    ]


@router.get("/{threat_model_id}", response_model=ThreatModelOut)
async def get_threat_model(
    threat_model_id: uuid.UUID, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)
):
    model = await _load_or_404(db, threat_model_id)
    result = await db.execute(select(ThreatEntry).where(ThreatEntry.threat_model_id == threat_model_id))
    entries = list(result.scalars().all())
    return ThreatModelOut.model_validate({**model.__dict__, "entries": entries})


@router.post("/{threat_model_id}/entries", response_model=ThreatEntryOut, status_code=status.HTTP_201_CREATED)
async def add_entry(
    threat_model_id: uuid.UUID, payload: ThreatEntryCreate,
    db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user),
):
    await _load_or_404(db, threat_model_id)
    entry = ThreatEntry(threat_model_id=threat_model_id, ai_generated=False, **payload.model_dump())
    db.add(entry)
    await db.commit()
    await db.refresh(entry)
    return entry


@router.patch("/{threat_model_id}/entries/{entry_id}", response_model=ThreatEntryOut)
async def update_entry(
    threat_model_id: uuid.UUID, entry_id: uuid.UUID, payload: ThreatEntryUpdate,
    db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(ThreatEntry).where(ThreatEntry.id == entry_id, ThreatEntry.threat_model_id == threat_model_id)
    )
    entry = result.scalar_one_or_none()
    if entry is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Threat entry not found.")

    updates = payload.model_dump(exclude_unset=True)
    for key, value in updates.items():
        setattr(entry, key, value)
    if updates:
        entry.human_edited = True

    await db.commit()
    await db.refresh(entry)
    return entry


@router.post("/{threat_model_id}/review", response_model=ThreatModelOut)
async def mark_reviewed(
    threat_model_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ip = request.client.host if request.client else "unknown"
    ua = request.headers.get("user-agent", "unknown")

    model = await _load_or_404(db, threat_model_id)
    model.status = "reviewed"
    model.reviewed_by = user.id
    model.reviewed_at = datetime.now(timezone.utc)

    await audit_record(
        db, event_type="threat_model_reviewed", event_category="admin",
        actor_user_id=user.id, actor_email=user.email, ip_address=ip, user_agent=ua,
        resource_type="threat_model", resource_id=str(threat_model_id),
    )
    await db.commit()

    result = await db.execute(select(ThreatEntry).where(ThreatEntry.threat_model_id == threat_model_id))
    entries = list(result.scalars().all())
    return ThreatModelOut.model_validate({**model.__dict__, "entries": entries})
