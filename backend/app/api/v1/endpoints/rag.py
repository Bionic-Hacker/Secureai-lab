"""
RAG retrieval endpoint. This is a standalone way to test/inspect the
ingestion pipeline directly (see what chunks a query actually surfaces)
independent of Phase 4's chat interface, which will call the same
underlying retrieval function internally once it exists.
"""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user
from app.db.session import get_db
from app.models.user import User
from app.schemas.rag import RagQueryRequest, RagQueryResponse
from app.services import document_service, embeddings, vector_store

router = APIRouter(prefix="/rag", tags=["rag"])


@router.post("/query", response_model=RagQueryResponse)
async def query(
    payload: RagQueryRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    # Reuses the exact same ownership+sharing query Phase 2's document
    # listing uses — retrieval and listing must agree on what "accessible"
    # means, or a document could be queryable via RAG while hidden from
    # the document list, which would be a permission model inconsistency.
    accessible_docs = await document_service.list_documents(db, user, limit=1000, offset=0)
    accessible_ids = [d.id for d in accessible_docs if d.ingestion_status == "indexed"]

    if not accessible_ids:
        return RagQueryResponse(query=payload.query, results=[])

    [query_vector] = await embeddings.embed_texts([payload.query])
    chunks = vector_store.query_chunks(
        query_embedding=query_vector,
        allowed_document_ids=accessible_ids,
        top_k=payload.top_k,
    )

    return RagQueryResponse(
        query=payload.query,
        results=[
            {
                "document_id": c["document_id"],
                "chunk_index": c["chunk_index"],
                "text": c["text"],
                "similarity": round(c["similarity"], 4),
            }
            for c in chunks
        ],
    )
