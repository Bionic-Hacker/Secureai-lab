from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field


class DocumentOut(BaseModel):
    id: UUID
    original_filename: str
    content_type: str
    size_bytes: int
    sha256_hash: str
    malware_scan_status: str
    ingestion_status: str
    created_at: datetime

    class Config:
        from_attributes = True


class ShareRequest(BaseModel):
    email: EmailStr
    permission: str = Field("read", pattern="^(read|write)$")
