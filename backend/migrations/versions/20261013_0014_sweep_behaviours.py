"""behaviours swept alongside indicators

Revision ID: 0014
Revises: 0013
Create Date: 2026-10-13 15:00:00
"""

import sqlalchemy as sa
from alembic import op

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("ioc_sweeps", sa.Column("ioas_total", sa.Integer(), nullable=False, server_default="0"))


def downgrade() -> None:
    op.drop_column("ioc_sweeps", "ioas_total")
