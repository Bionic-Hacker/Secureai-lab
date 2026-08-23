"""
Seeds a real threat model for this project's own RAG cross-tenant
isolation feature — the platform reviewing itself with the same rigor it
applies to user-submitted code, per the project's stated Feature 5 goal.

Run with:
    docker compose exec backend python3 -m app.scripts.seed_threat_model <user_email>

<user_email> must be an existing user — the threat model's created_by
and reviewed_by will both point at that account, and it's immediately
marked "reviewed" since this content reflects mitigations already built
and tested in Phases 1-5, not draft AI output awaiting review.
"""
import asyncio
import sys
from datetime import datetime, timezone

from sqlalchemy import select

from app.db.session import AsyncSessionLocal
from app.models.threat_model import ThreatEntry, ThreatModel
from app.models.user import User

_ENTRIES = [
    dict(
        stride_category="spoofing",
        threat_description="A forged or replayed JWT is used to impersonate another user or an admin.",
        affected_asset="Session / role claim",
        mitigation="Signature verification, short access-token TTL, role re-checked against the database on every request rather than trusted from the token.",
        mitigation_status="mitigated",
    ),
    dict(
        stride_category="tampering",
        threat_description="A stolen refresh token is replayed after the legitimate client has already rotated it, extending an attacker's session.",
        affected_asset="Refresh token",
        mitigation="Opaque, hashed, single-use refresh tokens with reuse detection — replay revokes the entire token family immediately.",
        mitigation_status="mitigated",
    ),
    dict(
        stride_category="repudiation",
        threat_description="An admin denies having made a privilege change after the fact.",
        affected_asset="Audit trail",
        mitigation="INSERT-only audit_log table (UPDATE/DELETE revoked at the database grant level), actor and IP recorded on every write.",
        mitigation_status="mitigated",
    ),
    dict(
        stride_category="info_disclosure",
        threat_description="A RAG query returns document chunks belonging to a different user — the core cross-tenant isolation risk in the retrieval pipeline.",
        affected_asset="ChromaDB vector store",
        mitigation="Every retrieval query passes an explicit allowlist of document IDs the requesting user can access, applied as a server-side metadata filter at query time, never as a post-hoc filter on already-returned results. Verified directly with a second-account test, not just code review.",
        mitigation_status="mitigated",
    ),
    dict(
        stride_category="dos",
        threat_description="Repeated login attempts exhaust password-hashing CPU capacity, denying service to legitimate users.",
        affected_asset="Auth service",
        mitigation="Redis-backed IP rate limiting at the edge (nginx) plus a separate account-level lockout, so an attacker rotating IPs still trips the per-account limiter.",
        mitigation_status="mitigated",
    ),
    dict(
        stride_category="elevation",
        threat_description="A user demoted mid-session continues acting on their previous, higher role because their JWT still carries the old claim.",
        affected_asset="RBAC",
        mitigation="Role is re-checked against the live database row on every request, not read from the JWT claim, bounding the exposure window to the access token's short TTL.",
        mitigation_status="mitigated",
    ),
    dict(
        stride_category="elevation",
        threat_description="An attacker enumerates or guesses document_id values to access documents outside their permission scope.",
        affected_asset="Document access control",
        mitigation="UUIDv4 document identifiers (not sequential/guessable) combined with a mandatory permission check on every access, independent of ID guessability.",
        mitigation_status="mitigated",
    ),
    dict(
        stride_category="elevation",
        threat_description="A user prompt-injects the AI assistant to ignore its retrieval scope and surface another user's document content through a generated response.",
        affected_asset="AI Security Assistant",
        mitigation="Retrieval scope is enforced in the retrieval layer itself before any content reaches the model — the model never receives out-of-scope context to leak in the first place, so a successful prompt injection has nothing to exfiltrate. Backed by input-guardrail blocking of injection-pattern messages as defense in depth.",
        mitigation_status="mitigated",
    ),
]


async def seed(user_email: str) -> None:
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.email == user_email))
        user = result.scalar_one_or_none()
        if user is None:
            print(f"No user found with email {user_email!r} — create the account first.")
            return

        model = ThreatModel(
            title="RAG Retrieval & Platform Request Path — Cross-Tenant Isolation",
            system_description=(
                "Covers the full request path from browser through nginx, FastAPI backend, "
                "and PostgreSQL, plus the RAG retrieval flow from query through ChromaDB and "
                "back through the AI Security Assistant. Primary concern: could any request "
                "path result in one user seeing another user's data, credentials, or "
                "conversation content."
            ),
            created_by=user.id,
            status="reviewed",
            reviewed_by=user.id,
            reviewed_at=datetime.now(timezone.utc),
        )
        db.add(model)
        await db.flush()

        for entry in _ENTRIES:
            db.add(ThreatEntry(threat_model_id=model.id, ai_generated=False, human_edited=False, **entry))

        await db.commit()
        print(f"Seeded threat model {model.id} with {len(_ENTRIES)} entries, attributed to {user_email}.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 -m app.scripts.seed_threat_model <user_email>")
        sys.exit(1)
    asyncio.run(seed(sys.argv[1]))
