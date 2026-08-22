from openai import AsyncOpenAI, OpenAIError

from app.core.config import get_settings
from app.services.embeddings.base import EmbeddingProvider

settings = get_settings()

# OpenAI's embeddings endpoint caps inputs per request — batching stays
# comfortably under that regardless of how many chunks a large document
# produces.
_BATCH_SIZE = 100


class EmbeddingError(Exception):
    pass


class OpenAIEmbeddingProvider(EmbeddingProvider):
    def __init__(self):
        self._client: AsyncOpenAI | None = None

    def _get_client(self) -> AsyncOpenAI:
        if self._client is None:
            if not settings.openai_api_key:
                raise EmbeddingError(
                    "OPENAI_API_KEY is not set — required because EMBEDDING_PROVIDER=openai. "
                    "Set a real key in .env, or switch EMBEDDING_PROVIDER=local."
                )
            self._client = AsyncOpenAI(api_key=settings.openai_api_key)
        return self._client

    async def embed_texts(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []

        client = self._get_client()
        all_embeddings: list[list[float]] = []

        for i in range(0, len(texts), _BATCH_SIZE):
            batch = texts[i : i + _BATCH_SIZE]
            try:
                response = await client.embeddings.create(
                    model=settings.openai_embedding_model,
                    input=batch,
                )
            except OpenAIError as exc:
                raise EmbeddingError(f"OpenAI embeddings request failed: {exc}") from exc

            all_embeddings.extend(item.embedding for item in response.data)

        return all_embeddings
