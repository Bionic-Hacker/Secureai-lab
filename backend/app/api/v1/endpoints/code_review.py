import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user
from app.db.session import get_db
from app.models.code_finding import CodeFinding
from app.models.user import User
from app.schemas.code_review import CodeExcerptOut, CodeFindingListItemOut, CodeFindingOut, CodeScanStatusOut
from app.services import code_scan_service, document_service, guardrails
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

    if doc.size_bytes > code_scan_service.MAX_SCAN_BYTES:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            f"This file is too large to scan ({doc.size_bytes // 1024} KB). "
            f"Code review accepts files up to {code_scan_service.MAX_SCAN_BYTES // 1024} KB.",
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

# --- Code Review Engine workspace ---------------------------------------------
# Both endpoints below follow document permissions exactly: a user sees
# findings for, and code from, only documents they own or were shared -
# the same load/list path as downloads and RAG retrieval. The org-wide view
# stays in Governance -> Findings, behind the governance roles.

_MAX_EXCERPT_LINE_CHARS = 400


def _build_excerpt(text: str, line_number: int, context: int) -> tuple[int, list[str]]:
    """Returns (first line number, lines) for a window around line_number.
    Out-of-range line numbers are clamped rather than rejected, and very long
    lines (minified code) are truncated so one line can't bloat the response."""
    all_lines = text.splitlines()
    if not all_lines:
        return 1, []
    target = min(max(line_number, 1), len(all_lines))
    start = max(1, target - context)
    end = min(len(all_lines), target + context)
    window = all_lines[start - 1 : end]
    return start, [
        line if len(line) <= _MAX_EXCERPT_LINE_CHARS else line[:_MAX_EXCERPT_LINE_CHARS] + " …"
        for line in window
    ]


@router.get("/findings", response_model=list[CodeFindingListItemOut])
async def list_accessible_findings(
    limit: int = Query(200, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    docs = await document_service.list_documents(db, user, limit=1000, offset=0)
    names = {d.id: d.original_filename for d in docs}
    if not names:
        return []
    result = await db.execute(
        select(CodeFinding)
        .where(CodeFinding.document_id.in_(list(names)))
        .order_by(CodeFinding.cvss_score.desc(), CodeFinding.created_at.desc())
        .limit(limit)
    )
    return [
        CodeFindingListItemOut(
            **CodeFindingOut.model_validate(f).model_dump(),
            document_id=f.document_id,
            document_filename=names.get(f.document_id, "unknown"),
            status=f.status,
        )
        for f in result.scalars().all()
    ]


@router.get("/findings/{finding_id}/excerpt", response_model=CodeExcerptOut)
async def get_finding_excerpt(
    finding_id: uuid.UUID,
    request: Request,
    context: int = Query(6, ge=0, le=20),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(CodeFinding).where(CodeFinding.id == finding_id))
    finding = result.scalar_one_or_none()
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found.")

    try:
        doc, plaintext = await document_service.get_document_content(db, finding.document_id, user)
    except document_service.DocumentError as e:
        # Same answer whether the finding doesn't exist or belongs to a document
        # this user can't open - never confirm that someone else's finding exists.
        if e.status_code in (status.HTTP_403_FORBIDDEN, status.HTTP_404_NOT_FOUND):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found.")
        raise HTTPException(e.status_code, e.message)

    if finding.line_number is None:
        start, lines = 1, []
    else:
        start, lines = _build_excerpt(plaintext.decode("utf-8", errors="replace"), finding.line_number, context)

    # Code shown on screen goes through the same output guardrail as AI
    # responses. Line by line, so a redaction can never shift the numbering.
    # The owner can still download the original file; this only keeps
    # secrets (the exact thing a hardcoded-credentials finding points at)
    # out of the review UI and out of screenshots of it.
    redactions: set[str] = set()
    safe_lines = []
    for line in lines:
        redacted, flags = guardrails.redact_output(line)
        safe_lines.append(redacted)
        redactions.update(flags)

    ip = request.client.host if request.client else "unknown"
    ua = request.headers.get("user-agent", "unknown")
    await audit_record(
        db, event_type="code_excerpt_viewed", event_category="upload",
        actor_user_id=user.id, actor_email=user.email, ip_address=ip, user_agent=ua,
        resource_type="document", resource_id=str(finding.document_id),
        metadata={"finding_id": str(finding_id), "line": finding.line_number},
    )
    await db.commit()

    return CodeExcerptOut(
        finding_id=finding_id,
        document_filename=doc.original_filename,
        start_line=start,
        highlight_line=finding.line_number,
        lines=safe_lines,
        redactions=sorted(redactions),
    )
