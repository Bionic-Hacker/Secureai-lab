"""code_findings table and documents.code_scan_status column

Revision ID: 0004
Revises: 0003
Create Date: 2026-08-24

*** IMPORTANT — check before running, same as every migration in this
project so far ***
    docker compose exec backend alembic current
Confirm the down_revision below actually matches. Given 0003 (ai_requests)
was added cleanly in Phase 4 with no duplicate-file issue, this one is
more likely to be correct as-is than the 0002 situation was — but verify
anyway.
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "documents",
        sa.Column("code_scan_status", sa.String(16), nullable=False, server_default="not_scanned"),
    )

    op.create_table(
        "code_findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("document_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("documents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("tool", sa.String(16), nullable=False),
        sa.Column("rule_id", sa.String(128), nullable=False),
        sa.Column("category", sa.String(32), nullable=False),
        sa.Column("title", sa.String(256), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("line_number", sa.Integer(), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=False),
        sa.Column("cvss_vector", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("idx_code_findings_document", "code_findings", ["document_id"])
    op.create_index("idx_code_findings_severity", "code_findings", ["severity"])


def downgrade() -> None:
    op.drop_table("code_findings")
    op.drop_column("documents", "code_scan_status")
