"""
Code review scan orchestration.

Runs as a background task after being triggered (same pattern as Phase 3's
ingestion), since Semgrep/Bandit against a real file can take a few
seconds and shouldn't block the triggering request.

Security notes on running scanners against uploaded content:
  - The file has already passed ClamAV malware scanning (Phase 2) before
    it was ever stored — this scan step runs on content already
    established as clean, not arbitrary untrusted bytes.
  - Scanner subprocesses run with an explicit timeout, so a pathological
    input designed to make a scanner hang can't tie up a worker
    indefinitely.
  - Neither Bandit nor Semgrep is ever invoked with shell=True — the
    exact pattern this project's own Semgrep ruleset flags as a
    vulnerability. Arguments are passed as a list, not a shell string.
  - Scans run in a dedicated temp directory, deleted afterward regardless
    of success or failure.
"""
import asyncio
import json
import logging
import subprocess
import tempfile
import uuid
from pathlib import Path

from sqlalchemy import select

from app.core.file_encryption import decrypt_bytes
from app.services.heavy_jobs import heavy_job
from app.db.session import AsyncSessionLocal
from app.models.code_finding import CodeFinding
from app.models.document import Document
from app.services import cvss_mapping
from app.services.storage import get_storage_backend

logger = logging.getLogger("secureai.code_review")

_SEMGREP_RULES_PATH = "/app/semgrep-rules/security-rules.yaml"
_SCAN_TIMEOUT_SECONDS = 60
# Largest file the code scanners will accept. Real source files are almost
# always far smaller; a bigger one (a 1.2MB, 25,000-line stress fixture) was
# measured to push the scanners past Render's 512MB. Enforced at the scan
# endpoint (clear 413) and again here as a backstop.
MAX_SCAN_BYTES = 500_000
# Semgrep's own engine limits: cap its memory (MiB) and run a single job, so
# an oversized input makes Semgrep fail cleanly instead of the whole backend
# being OOM-killed. Per-rule timeout in seconds.
_SEMGREP_MAX_MEMORY_MB = 200
_SEMGREP_RULE_TIMEOUT_SECONDS = 30
_SEMGREP_LANGUAGE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx"}


def _run_bandit(file_path: Path) -> list[dict]:
    result = subprocess.run(
        ["bandit", "-f", "json", str(file_path)],
        capture_output=True, text=True, timeout=_SCAN_TIMEOUT_SECONDS,
    )
    # Bandit exits non-zero when it finds issues — that's expected, not a failure.
    if not result.stdout:
        return []
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        logger.error("Bandit produced non-JSON output: %s", result.stderr[:500])
        return []
    return data.get("results", [])


def _run_semgrep(file_path: Path) -> list[dict]:
    import os

    # Semgrep writes its own settings to $HOME/.semgrep on first run.
    # This container has no home directory and a read-only root
    # filesystem at runtime, so $HOME must point somewhere writable.
    env = {**os.environ, "HOME": "/tmp"}  # nosec B108 - subprocess-only, single-tenant container, no sensitive data written; see comment above

    result = subprocess.run(
        [
            "semgrep", "scan", "--config", _SEMGREP_RULES_PATH, "--json", "--quiet",
            # Uploaded code is scanned locally only: no usage metrics, no
            # update check - nothing about it goes to a third party.
            "--metrics", "off", "--disable-version-check",
            "--max-memory", str(_SEMGREP_MAX_MEMORY_MB),
            "-j", "1",
            "--timeout", str(_SEMGREP_RULE_TIMEOUT_SECONDS),
            "--max-target-bytes", str(MAX_SCAN_BYTES),
            str(file_path),
        ],
        capture_output=True, text=True, timeout=_SCAN_TIMEOUT_SECONDS, env=env,
    )
    if not result.stdout:
        return []
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        logger.error("Semgrep produced non-JSON output: %s", result.stderr[:500])
        return []
    return data.get("results", [])


def _normalize_bandit(raw: dict) -> dict:
    test_id = raw.get("test_id", "")
    category = cvss_mapping.category_for_bandit(test_id)
    cvss = cvss_mapping.cvss_for_category(category)
    return {
        "tool": "bandit",
        "rule_id": test_id,
        "category": category,
        "title": raw.get("test_name", test_id),
        "description": raw.get("issue_text", ""),
        "line_number": raw.get("line_number"),
        "cvss_score": cvss.score,
        "cvss_vector": cvss.vector,
        "severity": cvss.severity,
    }


def _normalize_semgrep(raw: dict) -> dict:
    rule_id = raw.get("check_id", "")
    category = cvss_mapping.category_for_semgrep(rule_id)
    cvss = cvss_mapping.cvss_for_category(category)
    extra = raw.get("extra", {})
    return {
        "tool": "semgrep",
        "rule_id": rule_id,
        "category": category,
        "title": rule_id.rsplit(".", 1)[-1].replace("-", " ").title(),
        "description": extra.get("message", ""),
        "line_number": raw.get("start", {}).get("line"),
        "cvss_score": cvss.score,
        "cvss_vector": cvss.vector,
        "severity": cvss.severity,
    }


async def scan_document(document_id: uuid.UUID) -> None:
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Document).where(Document.id == document_id))
        doc = result.scalar_one_or_none()
        if doc is None:
            logger.error("Code scan requested for missing document_id=%s", document_id)
            return

        try:
            storage = get_storage_backend()
            encrypted = await storage.load(doc.storage_path)
            plaintext = decrypt_bytes(encrypted)
            if len(plaintext) > MAX_SCAN_BYTES:
                logger.warning(
                    "Code scan skipped for document_id=%s: %d bytes exceeds the %d-byte limit",
                    document_id, len(plaintext), MAX_SCAN_BYTES,
                )
                doc.code_scan_status = "failed"
                await db.commit()
                return

            ext = "." + doc.sanitized_filename.rsplit(".", 1)[-1]

            with tempfile.TemporaryDirectory(prefix="secureai-scan-") as tmp:
                tmp_path = Path(tmp)
                target_file = tmp_path / f"scan_target{ext}"
                target_file.write_bytes(plaintext)

                findings: list[dict] = []
                # Scanners are blocking subprocess calls: run directly, they froze
                # the whole event loop (every request timed out) for the length of
                # the scan. They now run in a worker thread, and under the
                # heavy-job lock so a scan never overlaps an embedding run.
                async with heavy_job():
                    if ext == ".py":
                        bandit_results = await asyncio.to_thread(_run_bandit, target_file)
                        findings.extend(_normalize_bandit(f) for f in bandit_results)
                    if ext in _SEMGREP_LANGUAGE_EXTENSIONS:
                        semgrep_results = await asyncio.to_thread(_run_semgrep, target_file)
                        findings.extend(_normalize_semgrep(f) for f in semgrep_results)

            # Clear any prior findings for this document before inserting fresh
            # ones, so re-scanning doesn't accumulate duplicates.
            await db.execute(CodeFinding.__table__.delete().where(CodeFinding.document_id == document_id))

            for f in findings:
                db.add(CodeFinding(
                    document_id=document_id,
                    tool=f["tool"], rule_id=f["rule_id"], category=f["category"],
                    title=f["title"], description=f["description"], line_number=f["line_number"],
                    cvss_score=f["cvss_score"], cvss_vector=f["cvss_vector"], severity=f["severity"],
                ))

            doc.code_scan_status = "completed"
            await db.commit()
            logger.info("Code scan complete for document_id=%s: %d findings", document_id, len(findings))

        except subprocess.TimeoutExpired:
            logger.error("Code scan timed out for document_id=%s", document_id)
            doc.code_scan_status = "failed"
            await db.commit()
        except Exception:
            logger.exception("Code scan failed for document_id=%s", document_id)
            doc.code_scan_status = "failed"
            await db.commit()
