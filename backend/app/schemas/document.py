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


class RejectedUploadOut(BaseModel):
    # Synthesized from an audit_log entry, not a real Document row - see
    # document_service.upload_document, which deliberately never persists
    # an infected file. Shaped to match DocumentOut's fields the frontend
    # already knows how to render (CustodyTag.jsx), with id as a string
    # (audit_log's primary key is a BigInteger, not a UUID) and no real
    # hash/content-type/size available since the file itself was never
    # read past the malware scan.
    id: str
    original_filename: str
    content_type: str = "unknown"
    size_bytes: int = 0
    sha256_hash: str = ""
    malware_scan_status: str = "infected"
    ingestion_status: str = "blocked"
    created_at: datetime

    class Config:
        from_attributes = True


class ShareRequest(BaseModel):
    email: EmailStr
    permission: str = Field("read", pattern="^(read|write)$")
