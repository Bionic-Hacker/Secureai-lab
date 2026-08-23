from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class CodeFindingOut(BaseModel):
    id: UUID
    tool: str
    rule_id: str
    category: str
    title: str
    description: str
    line_number: int | None
    cvss_score: float
    cvss_vector: str
    severity: str
    created_at: datetime

    class Config:
        from_attributes = True


class CodeScanStatusOut(BaseModel):
    document_id: UUID
    code_scan_status: str
    findings: list[CodeFindingOut]
    summary: dict[str, int]  # {"critical": 1, "high": 2, "medium": 0, "low": 3}
