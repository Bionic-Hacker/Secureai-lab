"""
Local chat provider — Ollama, running as its own container (see
docker-compose.yml). Ollama exposes an OpenAI-compatible /v1/chat/completions
endpoint, so this reuses the openai SDK already in requirements.txt rather
than writing a separate HTTP client — the only difference from the OpenAI
provider is which base_url and api_key get passed in. Ollama itself
ignores the api_key value; any non-empty string works.
"""
from openai import AsyncOpenAI, OpenAIError

from app.core.config import get_settings
from app.services.chat.base import ChatMessage, ChatProvider

settings = get_settings()


class ChatError(Exception):
    pass


class LocalChatProvider(ChatProvider):
    def __init__(self):
        self._client: AsyncOpenAI | None = None

    def _get_client(self) -> AsyncOpenAI:
        if self._client is None:
            self._client = AsyncOpenAI(
                base_url=settings.local_llm_base_url,
                api_key="ollama",  # unused by Ollama, just needs to be non-empty
            )
        return self._client

    async def generate(self, messages: list[ChatMessage], max_tokens: int) -> str:
        client = self._get_client()
        try:
            response = await client.chat.completions.create(
                model=settings.local_llm_model,
                messages=[{"role": m.role, "content": m.content} for m in messages],
                max_tokens=max_tokens,
            )
        except OpenAIError as exc:
            raise ChatError(
                f"Local chat model request failed: {exc}. Is the model pulled? "
                f"Run: docker compose exec ollama ollama pull {settings.local_llm_model}"
            ) from exc

        return response.choices[0].message.content or ""
