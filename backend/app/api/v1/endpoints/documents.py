import uuid

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user
from app.db.session import get_db
from app.models.user import User
from app.schemas.document import DocumentOut, ShareRequest
from app.services import document_service
from app.services.audit_service import record as audit_record

router = APIRouter(prefix="/documents", tags=["documents"])


def _client_meta(request: Request) -> tuple[str, str]:
    ip = request.client.host if request.client else "unknown"
    ua = request.headers.get("user-agent", "unknown")
    return ip, ua


@router.post("", response_model=DocumentOut, status_code=status.HTTP_201_CREATED)
async def upload(
    request: Request,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ip, ua = _client_meta(request)
    try:
        doc = await document_service.upload_document(db, user, file)
    except document_service.DocumentError as e:
        await audit_record(
            db, event_type="document_upload_failed", event_category="upload",
            actor_user_id=user.id, actor_email=user.email, ip_address=ip, user_agent=ua,
            outcome="failure", metadata={"reason": e.message},
        )
        await db.commit()
        raise HTTPException(e.status_code, e.message)

    await audit_record(
        db, event_type="document_uploaded", event_category="upload",
        actor_user_id=user.id, actor_email=user.email, ip_address=ip, user_agent=ua,
        resource_type="document", resource_id=str(doc.id),
        metadata={"filename": doc.original_filename, "size_bytes": doc.size_bytes},
    )
    await db.commit()
    return doc


@router.get("", response_model=list[DocumentOut])
async def list_my_documents(
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    limit = max(1, min(limit, 200))
    offset = max(0, offset)
    return await document_service.list_documents(db, user, limit=limit, offset=offset)


@router.get("/{document_id}", response_model=DocumentOut)
async def get_document(
    document_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    try:
        return await document_service.load_document_for_access(db, document_id, user)
    except document_service.DocumentError as e:
        raise HTTPException(e.status_code, e.message)


@router.get("/{document_id}/content")
async def download_document(
    document_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ip, ua = _client_meta(request)
    try:
        doc, plaintext = await document_service.get_document_content(db, document_id, user)
    except document_service.DocumentError as e:
        await audit_record(
            db, event_type="document_download_denied", event_category="upload",
            actor_user_id=user.id, actor_email=user.email, ip_address=ip, user_agent=ua,
            resource_type="document", resource_id=str(document_id), outcome="denied",
        )
        await db.commit()
        raise HTTPException(e.status_code, e.message)

    await audit_record(
        db, event_type="document_downloaded", event_category="upload",
        actor_user_id=user.id, actor_email=user.email, ip_address=ip, user_agent=ua,
        resource_type="document", resource_id=str(document_id),
    )
    await db.commit()

    # Strip CR/LF from the filename before it goes into a header — an
    # otherwise-valid filename containing a newline could otherwise be
    # used for HTTP response header injection.
    safe_name = doc.original_filename.replace('"', "").replace("\r", "").replace("\n", "")

    return Response(
        content=plaintext,
        media_type=doc.content_type or "application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}"'},
    )


@router.post("/{document_id}/share", status_code=status.HTTP_204_NO_CONTENT)
async def share(
    document_id: uuid.UUID,
    payload: ShareRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ip, ua = _client_meta(request)
    result = await db.execute(select(User).where(User.email == payload.email.lower()))
    target = result.scalar_one_or_none()
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found.")

    try:
        await document_service.share_document(db, document_id, user, target, payload.permission)
    except document_service.DocumentError as e:
        raise HTTPException(e.status_code, e.message)

    await audit_record(
        db, event_type="document_shared", event_category="upload",
        actor_user_id=user.id, actor_email=user.email, ip_address=ip, user_agent=ua,
        resource_type="document", resource_id=str(document_id),
        metadata={"granted_to": target.email, "permission": payload.permission},
    )
    await db.commit()


@router.delete("/{document_id}/share/{target_user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_share(
    document_id: uuid.UUID,
    target_user_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ip, ua = _client_meta(request)
    try:
        await document_service.revoke_document_share(db, document_id, user, target_user_id)
    except document_service.DocumentError as e:
        raise HTTPException(e.status_code, e.message)

    await audit_record(
        db, event_type="document_share_revoked", event_category="upload",
        actor_user_id=user.id, actor_email=user.email, ip_address=ip, user_agent=ua,
        resource_type="document", resource_id=str(document_id),
        metadata={"revoked_from": str(target_user_id)},
    )
    await db.commit()


@router.delete("/{document_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete(
    document_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ip, ua = _client_meta(request)
    try:
        await document_service.delete_document(db, document_id, user)
    except document_service.DocumentError as e:
        raise HTTPException(e.status_code, e.message)

    await audit_record(
        db, event_type="document_deleted", event_category="upload",
        actor_user_id=user.id, actor_email=user.email, ip_address=ip, user_agent=ua,
        resource_type="document", resource_id=str(document_id),
    )
    await db.commit()
