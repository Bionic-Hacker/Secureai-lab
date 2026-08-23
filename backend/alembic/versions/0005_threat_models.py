"""threat_models and threat_entries tables

Revision ID: 0005
Revises: 0004
Create Date: 2026-08-23

*** IMPORTANT — check before running, same as every migration in this
project ***
    docker compose exec backend alembic current
Confirm the down_revision below actually matches your real current
revision before running this.
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "threat_models",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("title", sa.String(256), nullable=False),
        sa.Column("system_description", sa.Text(), nullable=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="draft"),
        sa.Column("reviewed_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    op.create_table(
        "threat_entries",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("threat_model_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("threat_models.id", ondelete="CASCADE"), nullable=False),
        sa.Column("stride_category", sa.String(24), nullable=False),
        sa.Column("threat_description", sa.Text(), nullable=False),
        sa.Column("affected_asset", sa.String(256), nullable=False),
        sa.Column("mitigation", sa.Text(), nullable=False),
        sa.Column("mitigation_status", sa.String(16), nullable=False, server_default="planned"),
        sa.Column("ai_generated", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("human_edited", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("idx_threat_entries_model", "threat_entries", ["threat_model_id"])
    op.create_index("idx_threat_models_created_by", "threat_models", ["created_by"])


def downgrade() -> None:
    op.drop_table("threat_entries")
    op.drop_table("threat_models")
