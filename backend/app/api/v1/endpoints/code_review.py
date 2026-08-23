import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user
from app.db.session import get_db
from app.models.code_finding import CodeFinding
from app.models.user import User
from app.schemas.code_review import CodeFindingOut, CodeScanStatusOut
from app.services import code_scan_service, document_service
from app.services.audit_service import record as audit_record

router = APIRouter(prefix="/code-review", tags=["code-review"])

_SCANNABLE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx"}


@router.post("/scan/{document_id}", status_code=status.HTTP_202_ACCEPTED)
async def trigger_scan(
    document_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ip = request.client.host if request.client else "unknown"
    ua = request.headers.get("user-agent", "unknown")

    try:
        doc = await document_service.load_document_for_access(db, document_id, user)
    except document_service.DocumentError as e:
        raise HTTPException(e.status_code, e.message)

    if doc.malware_scan_status != "clean":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "This document is not available for scanning.")

    ext = "." + doc.sanitized_filename.rsplit(".", 1)[-1]
    if ext not in _SCANNABLE_EXTENSIONS:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Code review supports {sorted(_SCANNABLE_EXTENSIONS)} — this document is {ext}.",
        )

    doc.code_scan_status = "scanning"
    await audit_record(
        db, event_type="code_scan_triggered", event_category="ai",
        actor_user_id=user.id, actor_email=user.email, ip_address=ip, user_agent=ua,
        resource_type="document", resource_id=str(document_id),
    )
    await db.commit()

    background_tasks.add_task(code_scan_service.scan_document, document_id)

    return {"document_id": str(document_id), "code_scan_status": "scanning"}


@router.get("/findings/{document_id}", response_model=CodeScanStatusOut)
async def get_findings(
    document_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    try:
        doc = await document_service.load_document_for_access(db, document_id, user)
    except document_service.DocumentError as e:
        raise HTTPException(e.status_code, e.message)

    result = await db.execute(
        select(CodeFinding).where(CodeFinding.document_id == document_id).order_by(CodeFinding.cvss_score.desc())
    )
    findings = list(result.scalars().all())

    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        if f.severity in summary:
            summary[f.severity] += 1

    return CodeScanStatusOut(
        document_id=document_id,
        code_scan_status=doc.code_scan_status,
        findings=findings,
        summary=summary,
    )
