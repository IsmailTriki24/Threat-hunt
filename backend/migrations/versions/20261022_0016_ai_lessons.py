"""AI experience library: lessons about how to search, kept per tenant

Revision ID: 0016
Revises: 0015
Create Date: 2026-10-22 16:00:00
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ai_lessons",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("run_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("ai_runs.id", ondelete="SET NULL")),
        sa.Column("cue", sa.String(200), nullable=False),
        sa.Column("lesson", sa.String(400), nullable=False),
        sa.Column("evidence", sa.String(300), nullable=False, server_default=""),
        sa.Column("confidence", sa.String(8), nullable=False, server_default="medium"),
        sa.Column("origin", sa.String(8), nullable=False, server_default="auto"),
        sa.Column("status", sa.String(8), nullable=False, server_default="active"),
        sa.Column("fingerprint", sa.String(40), nullable=False),
        sa.Column("times_shown", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("tenant_id", "fingerprint", name="uq_ai_lesson_fingerprint"),
    )
    op.create_index("ix_ai_lessons_tenant_id", "ai_lessons", ["tenant_id"])
    op.create_index("ix_ai_lessons_created_at", "ai_lessons", ["created_at"])


def downgrade() -> None:
    op.drop_table("ai_lessons")
