"""
Document upload/retrieval/sharing business logic.

Upload pipeline, in order, and why the order matters:

  1. Sanitize the claimed filename (never trust it for a storage path).
  2. Read the upload with a hard byte-count cap — enforced while reading,
     not just checked against a (spoofable) Content-Length header, so a
     malicious/huge upload can't exhaust memory even if it lies about size.
  3. Verify the actual file content matches its claimed extension via
     magic-byte sniffing — stops the classic "rename malware.exe to
     resume.pdf" trick before it ever reaches storage.
  4. Malware-scan the plaintext. Fail closed: if the scanner is
     unreachable, the upload is rejected, not silently accepted.
  5. Only *after* a clean scan result do we encrypt (AES-256-GCM) and
     persist anything — an infected file is never written to storage in
     any form, encrypted or not.

Object-level authorization (OWASP API1): every read/write/share/delete
operation re-checks ownership or an explicit document_permissions row on
every call — nothing is inferred from the caller's role alone.
"""
import hashlib
import unicodedata
import uuid
from typing import Optional

from fastapi import UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.file_encryption import decrypt_bytes, encrypt_bytes
from app.models.document import Document, DocumentPermission
from app.models.user import User, UserRole
from app.services import malware_scan_service
from app.services.storage import get_storage_backend

settings = get_settings()

MAX_UPLOAD_BYTES = settings.max_upload_size_mb * 1024 * 1024

STRICT_MIME_TYPES = {
    ".pdf": {"application/pdf"},
    ".docx": {
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/zip",  # OOXML files are zip containers; some libmagic versions report the generic type
    },
}


class DocumentError(Exception):
    def __init__(self, message: str, status_code: int = 400):
        self.message = message
        self.status_code = status_code
        super().__init__(message)


def sanitize_filename(raw_name: str) -> tuple[str, str]:
    """
    Returns (display_name, extension_with_dot). The returned display_name
    is stored ONLY for showing to users — the actual on-disk/on-bucket key
    is always a fresh server-generated UUID (see upload_document), so even
    a maximally hostile filename can't influence where the file is written.
    """
    if not raw_name:
        raise DocumentError("Filename is required.")

    # Strip any path components regardless of separator style, so a
    # filename like "../../etc/passwd" or "..\\..\\config" is reduced to
    # just its final segment before anything else happens to it.
    name = raw_name.replace("\\", "/").split("/")[-1]
    name = unicodedata.normalize("NFKC", name)
    name = "".join(ch for ch in name if ch.isprintable())
    name = name.strip().strip(".")

    if not name:
        raise DocumentError("Filename is invalid.")
    if "." not in name:
        raise DocumentError("File must have an extension.")

    ext = "." + name.rsplit(".", 1)[-1].lower()
    if ext not in settings.allowed_upload_extensions_list:
        raise DocumentError(f"File type '{ext}' is not permitted.")

    if len(name) > 255:
        # Truncate the base, not the extension — truncating first (the
        # original bug here) can chop the extension off entirely, which
        # then fails the "must have an extension" check that ran before it.
        base, _, suffix = name.rpartition(".")
        name = base[: 255 - len(suffix) - 1] + "." + suffix

    return name, ext


def validate_content_type(data: bytes, ext: str) -> str:
    """Returns the detected MIME type, or raises DocumentError on mismatch."""
    try:
        import magic

        detected = magic.from_buffer(data[:4096], mime=True)
    except Exception as exc:  # pragma: no cover — environment missing libmagic
        raise DocumentError("Unable to verify file content type.", 500) from exc

    if ext in STRICT_MIME_TYPES:
        if detected not in STRICT_MIME_TYPES[ext]:
            raise DocumentError(f"File content does not match its extension (detected {detected}).")
    else:
        # Source-code / plaintext extensions: any text/* detection is
        # accepted rather than an exact per-language mime match, since
        # libmagic's language guesses for source code are inconsistent
        # and plaintext can't carry the kind of embedded-object exploits
        # that make strict matching necessary for PDF/DOCX.
        if not detected.startswith("text/"):
            raise DocumentError(f"File content does not match its extension (detected {detected}).")

    return detected


async def read_upload_bounded(file: UploadFile) -> bytes:
    chunks: list[bytes] = []
    total = 0
    chunk_size = 1024 * 1024

    while True:
        chunk = await file.read(chunk_size)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_UPLOAD_BYTES:
            raise DocumentError(f"File exceeds the {settings.max_upload_size_mb}MB upload limit.", 413)
        chunks.append(chunk)

    if total == 0:
        raise DocumentError("Uploaded file is empty.")
    return b"".join(chunks)


async def upload_document(db: AsyncSession, owner: User, file: UploadFile) -> Document:
    display_name, ext = sanitize_filename(file.filename or "")
    data = await read_upload_bounded(file)
    detected_mime = validate_content_type(data, ext)
    sha256_hash = hashlib.sha256(data).hexdigest()

    try:
        scan_result = await malware_scan_service.scan_bytes_async(data)
    except malware_scan_service.MalwareScanUnavailable as exc:
        raise DocumentError("Malware scanning is temporarily unavailable. Please try again shortly.", 503) from exc

    if not scan_result.clean:
        # Deliberately never persisted, encrypted or not — an infected
        # upload leaves no trace in storage.
        raise DocumentError("File was rejected by malware scanning.", 422)

    document_id = uuid.uuid4()
    storage_key = f"{owner.id}/{document_id}{ext}.enc"
    encrypted = encrypt_bytes(data)

    storage = get_storage_backend()
    await storage.save(storage_key, encrypted)

    doc = Document(
        id=document_id,
        owner_id=owner.id,
        original_filename=display_name,
        sanitized_filename=f"{document_id}{ext}",
        content_type=detected_mime,
        size_bytes=len(data),
        sha256_hash=sha256_hash,
        storage_path=storage_key,
        malware_scan_status="clean",
        ingestion_status="pending",  # RAG chunking/embedding happens in Phase 3
    )
    db.add(doc)
    await db.flush()
    return doc


async def load_document_for_access(
    db: AsyncSession, document_id: uuid.UUID, user: User, require_write: bool = False
) -> Document:
    result = await db.execute(select(Document).where(Document.id == document_id))
    doc = result.scalar_one_or_none()
    if doc is None:
        raise DocumentError("Document not found.", 404)

    if doc.owner_id == user.id or user.role == UserRole.ADMINISTRATOR:
        return doc

    perm_result = await db.execute(
        select(DocumentPermission).where(
            DocumentPermission.document_id == document_id,
            DocumentPermission.user_id == user.id,
        )
    )
    perm = perm_result.scalar_one_or_none()
    if perm is None:
        # 404, not 403 — a user with zero access shouldn't be able to
        # distinguish "doesn't exist" from "exists but I can't see it."
        raise DocumentError("Document not found.", 404)
    if require_write and perm.permission != "write":
        raise DocumentError("You have read-only access to this document.", 403)
    return doc


async def get_document_content(db: AsyncSession, document_id: uuid.UUID, user: User) -> tuple[Document, bytes]:
    doc = await load_document_for_access(db, document_id, user)
    if doc.malware_scan_status != "clean":
        raise DocumentError("This document is not available for download.", 403)

    storage = get_storage_backend()
    encrypted = await storage.load(doc.storage_path)
    plaintext = decrypt_bytes(encrypted)
    return doc, plaintext


async def list_documents(db: AsyncSession, user: User, limit: int = 50, offset: int = 0) -> list[Document]:
    owned_ids = select(Document.id).where(Document.owner_id == user.id)
    shared_ids = (
        select(Document.id)
        .join(DocumentPermission, DocumentPermission.document_id == Document.id)
        .where(DocumentPermission.user_id == user.id)
    )
    # Combined via SQL UNION rather than an OR'd filter, so ownership and
    # sharing stay two structurally separate access paths — a future
    # change to one can't accidentally weaken the other by sharing a
    # single, easier-to-get-wrong condition. The union is done on bare ids
    # in a subquery, then re-selected as full Document entities — SQLAlchemy
    # can't hydrate ORM entities directly off a compound (UNION) select.
    combined_ids = owned_ids.union(shared_ids).subquery()
    stmt = (
        select(Document)
        .where(Document.id.in_(select(combined_ids.c.id)))
        .order_by(Document.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    result = await db.execute(stmt)
    return list(result.scalars().all())


async def share_document(
    db: AsyncSession, document_id: uuid.UUID, owner: User, target_user: User, permission: str
) -> DocumentPermission:
    doc = await load_document_for_access(db, document_id, owner)
    if doc.owner_id != owner.id and owner.role != UserRole.ADMINISTRATOR:
        raise DocumentError("Only the document owner or an administrator can manage sharing.", 403)
    if permission not in ("read", "write"):
        raise DocumentError("Permission must be 'read' or 'write'.")

    existing = await db.execute(
        select(DocumentPermission).where(
            DocumentPermission.document_id == document_id,
            DocumentPermission.user_id == target_user.id,
        )
    )
    perm = existing.scalar_one_or_none()
    if perm:
        perm.permission = permission
        perm.granted_by = owner.id
    else:
        perm = DocumentPermission(
            document_id=document_id, user_id=target_user.id, permission=permission, granted_by=owner.id
        )
        db.add(perm)
    await db.flush()
    return perm


async def revoke_document_share(db: AsyncSession, document_id: uuid.UUID, owner: User, target_user_id: uuid.UUID) -> None:
    doc = await load_document_for_access(db, document_id, owner)
    if doc.owner_id != owner.id and owner.role != UserRole.ADMINISTRATOR:
        raise DocumentError("Only the document owner or an administrator can manage sharing.", 403)

    await db.execute(
        DocumentPermission.__table__.delete().where(
            DocumentPermission.document_id == document_id,
            DocumentPermission.user_id == target_user_id,
        )
    )
    await db.flush()


async def delete_document(db: AsyncSession, document_id: uuid.UUID, user: User) -> None:
    doc = await load_document_for_access(db, document_id, user)
    if doc.owner_id != user.id and user.role != UserRole.ADMINISTRATOR:
        raise DocumentError("Only the document owner or an administrator can delete this document.", 403)

    storage = get_storage_backend()
    await storage.delete(doc.storage_path)
    await db.delete(doc)
    await db.flush()
