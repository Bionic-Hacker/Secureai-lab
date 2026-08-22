from uuid import UUID

from pydantic import BaseModel, Field


class RagQueryRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=2000)
    top_k: int | None = Field(None, ge=1, le=20)


class RagChunkResult(BaseModel):
    document_id: UUID
    chunk_index: int
    text: str
    similarity: float


class RagQueryResponse(BaseModel):
    query: str
    results: list[RagChunkResult]
