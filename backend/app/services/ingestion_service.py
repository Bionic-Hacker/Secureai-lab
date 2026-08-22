"""
Ingestion pipeline: decrypt -> extract -> chunk -> embed -> store.

Runs as a FastAPI BackgroundTask after a document upload completes (see
documents.py's upload endpoint) — not blocking the upload response, since
embedding a large document can take a few seconds of external API time
that the caller shouldn't have to wait through synchronously.

Uses its own database session, separate from the request's — background
tasks run after the response is sent, by which point the request-scoped
session from the `get_db` dependency has already been closed.
"""
import logging
import uuid

from sqlalchemy import select

from app.core.file_encryption import decrypt_bytes
from app.db.session import AsyncSessionLocal
from app.models.document import Document
from app.services import embeddings, text_extraction, vector_store
from app.services.chunking import chunk_text
from app.services.storage import get_storage_backend

logger = logging.getLogger("secureai.ingestion")


async def ingest_document(document_id: uuid.UUID) -> None:
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Document).where(Document.id == document_id))
        doc = result.scalar_one_or_none()
        if doc is None:
            logger.error("Ingestion requested for missing document_id=%s", document_id)
            return

        doc.ingestion_status = "processing"
        await db.commit()

        try:
            storage = get_storage_backend()
            encrypted = await storage.load(doc.storage_path)
            plaintext = decrypt_bytes(encrypted)

            ext = "." + doc.sanitized_filename.rsplit(".", 1)[-1].replace(".enc", "")
            text = text_extraction.extract_text(plaintext, ext)

            chunks = chunk_text(text)
            if not chunks:
                raise ValueError("Document produced zero chunks after extraction/chunking.")

            vectors = await embeddings.embed_texts(chunks)
            vector_store.add_chunks(
                document_id=doc.id,
                owner_id=doc.owner_id,
                chunk_texts=chunks,
                embeddings=vectors,
            )

            doc.ingestion_status = "indexed"
            await db.commit()
            logger.info("Ingested document_id=%s into %d chunks", document_id, len(chunks))

        except Exception:
            logger.exception("Ingestion failed for document_id=%s", document_id)
            doc.ingestion_status = "failed"
            await db.commit()
