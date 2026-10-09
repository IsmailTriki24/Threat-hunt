"""ai run mode + persisted investigation state

Revision ID: 0009
Revises: 0008
Create Date: 2026-10-09 09:00:00
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("ai_runs", sa.Column("mode", sa.String(length=10), nullable=False, server_default="standard"))
    op.add_column("ai_runs", sa.Column("state", postgresql.JSONB(astext_type=sa.Text()), nullable=True))


def downgrade() -> None:
    op.drop_column("ai_runs", "state")
    op.drop_column("ai_runs", "mode")
