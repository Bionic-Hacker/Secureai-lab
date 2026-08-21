"""documents + document_permissions

Revision ID: 0002
Revises: 0001
Create Date: 2026-08-20

NOTE: This migration did not exist in the repository in any form - not even
as bytecode. app/models/document.py and app/services/document_service.py
reference these tables, so without it every /api/v1/documents route fails at
runtime with UndefinedTable. Written to match database/schema.sql.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "documents",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("owner_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("original_filename", sa.Text(), nullable=False),
        sa.Column("sanitized_filename", sa.Text(), nullable=False),
        sa.Column("content_type", sa.String(128), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("sha256_hash", sa.CHAR(64), nullable=False),
        sa.Column("storage_path", sa.Text(), nullable=False),
        sa.Column("malware_scan_status", sa.String(16), nullable=False,
                  server_default="pending"),
        sa.Column("ingestion_status", sa.String(16), nullable=False,
                  server_default="pending"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )
    op.create_index("idx_documents_owner", "documents", ["owner_id"])

    op.create_table(
        "document_permissions",
        sa.Column("document_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("documents.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("permission", sa.String(16), nullable=False, server_default="read"),
        sa.Column("granted_by", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id"), nullable=True),
        sa.Column("granted_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("document_permissions")
    op.drop_table("documents")
