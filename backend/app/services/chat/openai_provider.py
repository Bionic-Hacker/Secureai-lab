from openai import AsyncOpenAI, OpenAIError

from app.core.config import get_settings
from app.services.chat.base import ChatMessage, ChatProvider

settings = get_settings()


class ChatError(Exception):
    pass


class OpenAIChatProvider(ChatProvider):
    def __init__(self):
        self._client: AsyncOpenAI | None = None

    def _get_client(self) -> AsyncOpenAI:
        if self._client is None:
            if not settings.openai_api_key:
                raise ChatError(
                    "OPENAI_API_KEY is not set — required because AI_PROVIDER=openai. "
                    "Set a real key in .env, or switch AI_PROVIDER=local."
                )
            self._client = AsyncOpenAI(api_key=settings.openai_api_key)
        return self._client

    async def generate(self, messages: list[ChatMessage], max_tokens: int) -> str:
        client = self._get_client()
        try:
            response = await client.chat.completions.create(
                model=settings.openai_model,
                messages=[{"role": m.role, "content": m.content} for m in messages],
                max_tokens=max_tokens,
            )
        except OpenAIError as exc:
            raise ChatError(f"OpenAI chat request failed: {exc}") from exc

        return response.choices[0].message.content or ""
