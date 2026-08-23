import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class ThreatModel(Base):
    """
    A threat model covers one system, feature, or data flow. Visible to
    all authenticated users (organizational knowledge, not per-user
    private data — a real AppSec team's threat models are shared
    artifacts, unlike a personal document upload).
    """
    __tablename__ = "threat_models"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    system_description: Mapped[str] = mapped_column(Text, nullable=False)
    created_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="draft", nullable=False)  # draft | reviewed
    reviewed_by: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ThreatEntry(Base):
    """One STRIDE-categorized threat within a threat model."""
    __tablename__ = "threat_entries"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    threat_model_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("threat_models.id", ondelete="CASCADE"), nullable=False
    )
    # spoofing | tampering | repudiation | info_disclosure | dos | elevation
    stride_category: Mapped[str] = mapped_column(String(24), nullable=False)
    threat_description: Mapped[str] = mapped_column(Text, nullable=False)
    affected_asset: Mapped[str] = mapped_column(String(256), nullable=False)
    mitigation: Mapped[str] = mapped_column(Text, nullable=False)
    mitigation_status: Mapped[str] = mapped_column(String(16), default="planned", nullable=False)  # mitigated | planned | accepted_risk
    ai_generated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    human_edited: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
