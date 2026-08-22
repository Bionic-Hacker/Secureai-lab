"""
Provider factory. ingestion_service.py and the RAG query endpoint both do
`from app.services import embeddings` then `await embeddings.embed_texts(...)`
— that call site never changes regardless of which provider is active.
Switching from local to OpenAI (or to any future provider) is a one-line
EMBEDDING_PROVIDER change in .env plus a restart, nothing else.
"""
from functools import lru_cache

from app.core.config import get_settings
from app.services.embeddings.base import EmbeddingProvider
from app.services.embeddings.local_provider import EmbeddingError as _LocalError
from app.services.embeddings.local_provider import LocalEmbeddingProvider
from app.services.embeddings.openai_provider import EmbeddingError as _OpenAIError
from app.services.embeddings.openai_provider import OpenAIEmbeddingProvider

settings = get_settings()


class EmbeddingError(Exception):
    """Single exception type for callers, regardless of which provider raised it."""


@lru_cache
def get_embedding_provider() -> EmbeddingProvider:
    if settings.embedding_provider == "local":
        return LocalEmbeddingProvider()
    return OpenAIEmbeddingProvider()


async def embed_texts(texts: list[str]) -> list[list[float]]:
    provider = get_embedding_provider()
    try:
        return await provider.embed_texts(texts)
    except (_LocalError, _OpenAIError) as exc:
        raise EmbeddingError(str(exc)) from exc
