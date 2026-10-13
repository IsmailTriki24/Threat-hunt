"""sweep lanes: a fast lane next to the full lane for every SIEM source

Revision ID: 0015
Revises: 0014
Create Date: 2026-10-13 18:00:00
"""

import sqlalchemy as sa
from alembic import op

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("ioc_sweeps", sa.Column("lane", sa.String(4), nullable=False, server_default="full"))
    op.drop_index("ix_ioc_sweeps_data_source_id", table_name="ioc_sweeps")
    op.create_index("ix_ioc_sweeps_data_source_id", "ioc_sweeps", ["data_source_id"])
    op.create_unique_constraint("uq_ioc_sweep_source_lane", "ioc_sweeps", ["data_source_id", "lane"])


def downgrade() -> None:
    op.drop_constraint("uq_ioc_sweep_source_lane", "ioc_sweeps", type_="unique")
    op.execute("DELETE FROM ioc_sweeps WHERE lane <> 'full'")
    op.drop_index("ix_ioc_sweeps_data_source_id", table_name="ioc_sweeps")
    op.create_index("ix_ioc_sweeps_data_source_id", "ioc_sweeps", ["data_source_id"], unique=True)
    op.drop_column("ioc_sweeps", "lane")
