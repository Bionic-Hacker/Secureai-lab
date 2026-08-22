from functools import lru_cache

from app.core.config import get_settings
from app.services.chat.base import ChatMessage, ChatProvider
from app.services.chat.local_provider import ChatError as _LocalError
from app.services.chat.local_provider import LocalChatProvider
from app.services.chat.openai_provider import ChatError as _OpenAIError
from app.services.chat.openai_provider import OpenAIChatProvider

settings = get_settings()


class ChatError(Exception):
    pass


@lru_cache
def get_chat_provider() -> ChatProvider:
    if settings.ai_provider == "local":
        return LocalChatProvider()
    return OpenAIChatProvider()


async def generate(messages: list[ChatMessage], max_tokens: int | None = None) -> str:
    provider = get_chat_provider()
    try:
        return await provider.generate(messages, max_tokens or settings.assistant_max_response_tokens)
    except (_LocalError, _OpenAIError) as exc:
        raise ChatError(str(exc)) from exc
