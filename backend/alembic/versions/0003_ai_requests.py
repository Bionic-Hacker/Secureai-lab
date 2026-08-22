"""ai_requests table

Revision ID: 0003
Revises: 0002
Create Date: 2026-08-23

*** IMPORTANT — check before running ***
This file's `down_revision` below is set to "0002", matching this
project's original migration naming. Your actual database's most recent
migration may be a DIFFERENT revision id under a different filename
(e.g. 0002_documents.py rather than 0002_documents_and_permissions.py) —
this happened once already in this project. Before running this
migration, check what your database thinks its current revision actually
is:

    docker compose exec backend alembic current

Then set down_revision below to match that exact string, not necessarily
the literal "0002" shown here.
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0003"
down_revision = "0002"  # VERIFY THIS — see note above
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ai_requests",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("feature", sa.String(32), nullable=False),
        sa.Column("provider", sa.String(16), nullable=False),
        sa.Column("model", sa.String(64), nullable=False),
        sa.Column("prompt_redacted", sa.Text(), nullable=False),
        sa.Column("response_redacted", sa.Text(), nullable=False),
        sa.Column("input_tokens", sa.Integer(), nullable=True),
        sa.Column("output_tokens", sa.Integer(), nullable=True),
        sa.Column("guardrail_flags", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("blocked", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("idx_ai_requests_user", "ai_requests", ["user_id"])
    op.create_index("idx_ai_requests_feature", "ai_requests", ["feature"])
    op.create_index("idx_ai_requests_created_at", "ai_requests", ["created_at"])


def downgrade() -> None:
    op.drop_table("ai_requests")
