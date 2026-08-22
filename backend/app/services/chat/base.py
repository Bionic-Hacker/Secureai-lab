"""
Chat provider interface — same pattern as app/services/embeddings/base.py.
A ChatProvider takes a list of role/content messages and returns a
generated response. Nothing outside this package ever imports a specific
provider; everything goes through chat.generate() in __init__.py, which
picks the active provider from AI_PROVIDER in settings. Switching from
local to OpenAI (or any future provider) is a .env change, not a code
change — the exact same guarantee Phase 3 already relies on.
"""
from abc import ABC, abstractmethod


class ChatMessage:
    def __init__(self, role: str, content: str):
        self.role = role  # "system" | "user" | "assistant"
        self.content = content


class ChatProvider(ABC):
    @abstractmethod
    async def generate(self, messages: list[ChatMessage], max_tokens: int) -> str: ...
