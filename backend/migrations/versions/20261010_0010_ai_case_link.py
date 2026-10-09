"""link AI runs to the case they opened; mark hunt reports

Revision ID: 0010
Revises: 0009
Create Date: 2026-10-10 09:00:00
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "ai_runs",
        sa.Column(
            "case_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("cases.id", ondelete="SET NULL"), nullable=True
        ),
    )
    op.create_index("ix_ai_runs_case_id", "ai_runs", ["case_id"])
    op.add_column("case_reports", sa.Column("kind", sa.String(length=16), nullable=False, server_default="case"))


def downgrade() -> None:
    op.drop_column("case_reports", "kind")
    op.drop_index("ix_ai_runs_case_id", table_name="ai_runs")
    op.drop_column("ai_runs", "case_id")
