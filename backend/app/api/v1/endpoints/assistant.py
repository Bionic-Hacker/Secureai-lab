from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user
from app.db.session import get_db
from app.models.user import User
from app.schemas.assistant import AssistantChatRequest, AssistantChatResponse
from app.services import assistant_service
from app.services.audit_service import record as audit_record

router = APIRouter(prefix="/assistant", tags=["assistant"])


@router.post("/chat", response_model=AssistantChatResponse)
async def chat(
    payload: AssistantChatRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ip = request.client.host if request.client else "unknown"
    ua = request.headers.get("user-agent", "unknown")

    try:
        result = await assistant_service.handle_chat(
            db, user,
            message=payload.message,
            history=[t.model_dump() for t in payload.history],
            use_rag_context=payload.use_rag_context,
        )
    except assistant_service.AssistantError as e:
        await db.commit()
        raise HTTPException(e.status_code, e.message)

    await audit_record(
        db, event_type="ai_request", event_category="ai",
        actor_user_id=user.id, actor_email=user.email, ip_address=ip, user_agent=ua,
        resource_type="assistant_chat",
        metadata={"guardrail_flags": result["guardrail_flags"], "blocked": result["blocked"]},
        outcome="denied" if result["blocked"] else "success",
    )
    await db.commit()

    return result
