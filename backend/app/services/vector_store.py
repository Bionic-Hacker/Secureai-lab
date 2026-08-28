"""
ChromaDB access layer.

Single collection, not one-collection-per-user. Every chunk is stored
with owner_id and document_id as metadata; every query is REQUIRED to
pass a list of document_ids the requesting user is actually allowed to
see, and that list is applied as a Chroma metadata filter (`$in`) at
query time — not as a post-filter on the results. This mirrors exactly
how object-level permission checks work everywhere else in this codebase
(Postgres row lookups always join through document_permissions), so
there's one consistent isolation model across the whole app rather than
Postgres doing it one way and the vector store doing it another.

query_chunks() takes allowed_document_ids as a required, non-optional
parameter specifically so it's structurally impossible to call this
function without deciding what the caller is allowed to see first.

Accepted risk, verified by code review, not just architecture
argument: chromadb 0.5.5 carries CVE-2026-45830/45831/45833
(authorization-bypass and RCE-via-embedding-function issues in
ChromaDBs own server). None are reachable here. This module never
passes an embedding_function to get_or_create_collection - every
embedding is computed by this app own provider abstraction
(services/embeddings/) and supplied pre-computed, so the vulnerable
embedding-function-loading code path in ChromaDB is never invoked,
for any input. Separately, ChromaDB itself is unreachable from
outside backend_net (an internal-only Docker network), and only
this backend service holds CHROMA_AUTH_TOKEN - end users never
receive ChromaDB credentials directly, so the authorization-bypass
CVEs (which require an authenticated ChromaDB caller) have no
attacker-reachable entry point either.
"""
import uuid

import chromadb
from chromadb.config import Settings as ChromaSettings

from app.core.config import get_settings

settings = get_settings()

_client = None


def _get_client():
    global _client
    if _client is None:
        _client = chromadb.HttpClient(
            host=settings.chroma_host,
            port=settings.chroma_port,
            settings=ChromaSettings(
                chroma_client_auth_provider="chromadb.auth.token_authn.TokenAuthClientProvider",
                chroma_client_auth_credentials=settings.chroma_auth_token,
            ),
        )
    return _client


def _get_collection():
    client = _get_client()
    return client.get_or_create_collection(
        name=settings.chroma_collection_name,
        metadata={"hnsw:space": "cosine"},
    )


def add_chunks(
    document_id: uuid.UUID,
    owner_id: uuid.UUID,
    chunk_texts: list[str],
    embeddings: list[list[float]],
) -> None:
    if len(chunk_texts) != len(embeddings):
        raise ValueError("chunk_texts and embeddings must be the same length.")
    if not chunk_texts:
        return

    collection = _get_collection()
    ids = [f"{document_id}:{i}" for i in range(len(chunk_texts))]
    metadatas = [
        {"document_id": str(document_id), "owner_id": str(owner_id), "chunk_index": i}
        for i in range(len(chunk_texts))
    ]

    collection.upsert(
        ids=ids,
        embeddings=embeddings,
        documents=chunk_texts,
        metadatas=metadatas,
    )


def delete_document_chunks(document_id: uuid.UUID) -> None:
    """Called when a document is deleted (Phase 2's delete_document) so its
    vectors don't outlive the document itself."""
    collection = _get_collection()
    collection.delete(where={"document_id": str(document_id)})


def query_chunks(
    query_embedding: list[float],
    allowed_document_ids: list[uuid.UUID],
    top_k: int | None = None,
) -> list[dict]:
    """
    Returns the top_k most relevant chunks, restricted to
    allowed_document_ids via a Chroma metadata filter applied server-side
    as part of the query itself — never as a filter on already-returned
    results, which would leak the existence/similarity-ranking of chunks
    the caller isn't permitted to see even if their text were withheld.
    """
    if not allowed_document_ids:
        return []

    collection = _get_collection()
    result = collection.query(
        query_embeddings=[query_embedding],
        n_results=top_k or settings.rag_retrieval_top_k,
        where={"document_id": {"$in": [str(d) for d in allowed_document_ids]}},
    )

    chunks = []
    ids = result.get("ids", [[]])[0]
    documents = result.get("documents", [[]])[0]
    metadatas = result.get("metadatas", [[]])[0]
    distances = result.get("distances", [[]])[0]

    for chunk_id, doc_text, meta, distance in zip(ids, documents, metadatas, distances):
        chunks.append(
            {
                "chunk_id": chunk_id,
                "text": doc_text,
                "document_id": meta.get("document_id"),
                "chunk_index": meta.get("chunk_index"),
                "similarity": 1 - distance,  # cosine distance -> similarity, easier to reason about
            }
        )
    return chunks
