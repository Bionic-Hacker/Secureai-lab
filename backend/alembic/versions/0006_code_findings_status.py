"""add status column to code_findings

Revision ID: 0006
Revises: 0005
Create Date: 2026-08-30

*** IMPORTANT — check before running, same as every migration in this
project ***
    docker compose exec backend alembic current
Confirm the down_revision below actually matches your real current
revision before running this.
"""
import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # server_default backfills every existing finding (real rows from
    # Phase 5 testing already sitting in the table) to 'open', not just
    # rows inserted after this migration runs.
    op.add_column(
        "code_findings",
        sa.Column("status", sa.String(16), nullable=False, server_default="open"),
    )
    op.create_index("idx_code_findings_status", "code_findings", ["status"])


def downgrade() -> None:
    op.drop_index("idx_code_findings_status", table_name="code_findings")
    op.drop_column("code_findings", "status")
