from uuid import UUID

from pydantic import BaseModel, Field


class ChatTurn(BaseModel):
    role: str = Field(..., pattern="^(user|assistant)$")
    content: str = Field(..., min_length=1, max_length=8000)


class AssistantChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000)
    history: list[ChatTurn] = Field(default_factory=list)
    use_rag_context: bool = True


class AssistantChatResponse(BaseModel):
    response: str
    guardrail_flags: list[str]
    blocked: bool
    model: str
    provider: str
    latency_ms: int
    disclaimer: str = (
        "AI-generated content — may be incomplete or incorrect. "
        "Recommendations require human review before action is taken."
    )
