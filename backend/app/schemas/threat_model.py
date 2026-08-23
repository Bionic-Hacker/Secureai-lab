from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

STRIDE_CATEGORIES = ["spoofing", "tampering", "repudiation", "info_disclosure", "dos", "elevation"]


class ThreatModelCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=256)
    system_description: str = Field(..., min_length=10, max_length=6000)
    generate_with_ai: bool = False


class ThreatEntryCreate(BaseModel):
    stride_category: str = Field(..., pattern="^(" + "|".join(STRIDE_CATEGORIES) + ")$")
    threat_description: str = Field(..., min_length=1, max_length=2000)
    affected_asset: str = Field(..., min_length=1, max_length=256)
    mitigation: str = Field(..., min_length=1, max_length=2000)
    mitigation_status: str = Field("planned", pattern="^(mitigated|planned|accepted_risk)$")


class ThreatEntryUpdate(BaseModel):
    threat_description: str | None = Field(None, min_length=1, max_length=2000)
    affected_asset: str | None = Field(None, min_length=1, max_length=256)
    mitigation: str | None = Field(None, min_length=1, max_length=2000)
    mitigation_status: str | None = Field(None, pattern="^(mitigated|planned|accepted_risk)$")


class ThreatEntryOut(BaseModel):
    id: UUID
    stride_category: str
    threat_description: str
    affected_asset: str
    mitigation: str
    mitigation_status: str
    ai_generated: bool
    human_edited: bool
    created_at: datetime

    class Config:
        from_attributes = True


class ThreatModelOut(BaseModel):
    id: UUID
    title: str
    system_description: str
    status: str
    reviewed_by: UUID | None
    reviewed_at: datetime | None
    created_at: datetime
    entries: list[ThreatEntryOut]

    class Config:
        from_attributes = True


class ThreatModelSummaryOut(BaseModel):
    id: UUID
    title: str
    status: str
    entry_count: int
    created_at: datetime
