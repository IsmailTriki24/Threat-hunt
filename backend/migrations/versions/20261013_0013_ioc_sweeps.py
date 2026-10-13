"""indicator sweep state: one row per SIEM data source

Revision ID: 0013
Revises: 0012
Create Date: 2026-10-13 12:00:00
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ioc_sweeps",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column(
            "data_source_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("data_sources.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("cursor", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("queue", postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column("members", postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column("status", sa.String(10), nullable=False, server_default="idle"),
        sa.Column("detail", sa.String(300), nullable=False, server_default=""),
        sa.Column("lock_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_ok_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("windows_done", sa.Integer, nullable=False, server_default="0"),
        sa.Column("searches_total", sa.Integer, nullable=False, server_default="0"),
        sa.Column("hits_total", sa.Integer, nullable=False, server_default="0"),
        sa.Column("iocs_total", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_ioc_sweeps_tenant_id", "ioc_sweeps", ["tenant_id"])
    op.create_index("ix_ioc_sweeps_data_source_id", "ioc_sweeps", ["data_source_id"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_ioc_sweeps_data_source_id", table_name="ioc_sweeps")
    op.drop_index("ix_ioc_sweeps_tenant_id", table_name="ioc_sweeps")
    op.drop_table("ioc_sweeps")
