"""
Local embedding provider — runs entirely inside this container, no network
call to any third party. Document content never leaves the infrastructure
for this step, which is the actual reason this is the default provider
(see the .env.example comment and the Phase 3 architecture notes).

The model is loaded lazily, once, on first real use — not at import time —
so backend startup and healthchecks aren't slowed down by it. Model
weights are pre-downloaded into the Docker image at build time (see
Dockerfile) so a fresh container never needs internet access to fetch
them; this lazy-load is a fallback for that pre-download, not the primary
path.

sentence-transformers' .encode() is synchronous and CPU-bound — it runs
via asyncio.to_thread so it doesn't block the event loop the way the
OpenAI provider's native async client wouldn't need to.
"""
import asyncio

from app.core.config import get_settings
from app.services.embeddings.base import EmbeddingProvider

settings = get_settings()


class EmbeddingError(Exception):
    pass


class LocalEmbeddingProvider(EmbeddingProvider):
    def __init__(self):
        self._model = None

    def _get_model(self):
        if self._model is None:
            try:
                from sentence_transformers import SentenceTransformer
            except ImportError as exc:
                raise EmbeddingError(
                    "sentence-transformers is not installed — required because "
                    "EMBEDDING_PROVIDER=local. Check requirements.txt was rebuilt."
                ) from exc
            self._model = SentenceTransformer(settings.local_embedding_model)
        return self._model

    async def embed_texts(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []

        model = self._get_model()

        def _encode():
            return model.encode(texts, normalize_embeddings=True, convert_to_numpy=True)

        try:
            vectors = await asyncio.to_thread(_encode)
        except Exception as exc:
            raise EmbeddingError(f"Local embedding inference failed: {exc}") from exc

        return vectors.tolist()
