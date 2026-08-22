"""
Chunking for RAG ingestion.

Fixed-size chunks with a small overlap between consecutive chunks, so a
fact or sentence that happens to fall right on a chunk boundary doesn't
get split into two half-useless pieces with neither containing the full
context. Token-counted (via tiktoken) rather than character-counted,
since embedding models bill and truncate by token count, not characters.
"""
from app.core.config import get_settings

settings = get_settings()


def chunk_text(text: str) -> list[str]:
    import tiktoken

    encoding = tiktoken.get_encoding("cl100k_base")
    tokens = encoding.encode(text)

    if not tokens:
        return []

    chunk_size = settings.rag_chunk_size_tokens
    overlap = settings.rag_chunk_overlap_tokens
    step = max(chunk_size - overlap, 1)  # guard against a misconfigured overlap >= chunk_size

    chunks = []
    for start in range(0, len(tokens), step):
        chunk_tokens = tokens[start : start + chunk_size]
        chunk_str = encoding.decode(chunk_tokens)
        if chunk_str.strip():
            chunks.append(chunk_str)
        if start + chunk_size >= len(tokens):
            break

    return chunks
