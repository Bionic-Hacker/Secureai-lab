"""
Embedding generation via OpenAI's API.

Batches all chunks from a single document into as few API calls as
possible (OpenAI's embeddings endpoint accepts a list of inputs per
request) rather than one call per chunk — meaningfully cheaper and
faster for anything beyond a trivial document.

Fails closed: if the API call errors (bad key, rate limit, network),
ingestion for that document is marked 'failed' rather than silently
skipping chunks or storing empty vectors.
"""
from openai import AsyncOpenAI, OpenAIError

from app.core.config import get_settings

settings = get_settings()

_client: AsyncOpenAI | None = None


def _get_client() -> AsyncOpenAI:
    global _client
    if _client is None:
        if not settings.openai_api_key:
            raise EmbeddingError(
                "OPENAI_API_KEY is not set — required because AI_PROVIDER=openai. "
                "Set a real key in .env, or switch AI_PROVIDER to a local embedding backend."
            )
        _client = AsyncOpenAI(api_key=settings.openai_api_key)
    return _client


class EmbeddingError(Exception):
    pass


# OpenAI's embeddings endpoint caps the number of inputs per request —
# batching stays comfortably under that regardless of how many chunks a
# large document produces.
_BATCH_SIZE = 100


async def embed_texts(texts: list[str]) -> list[list[float]]:
    if not texts:
        return []

    client = _get_client()
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

        # OpenAI guarantees response order matches input order, so a plain
        # append (not a dict keyed by index) is safe here.
        all_embeddings.extend(item.embedding for item in response.data)

    return all_embeddings
