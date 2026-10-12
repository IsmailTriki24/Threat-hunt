"""composite indexes for the threat map's time-window queries

Revision ID: 0012
Revises: 0011
Create Date: 2026-10-12 12:00:00
"""

from alembic import op

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # iocs: tenant + type + recency (the map reads reported IPs of one tenant inside a time window)
    op.create_index("ix_iocs_tenant_type_last_seen", "iocs", ["tenant_id", "type", "last_seen"])
    # ioc_matches: tenant + event time (hunt matches inside a window)
    op.create_index("ix_ioc_matches_tenant_event_ts", "ioc_matches", ["tenant_id", "event_timestamp"])


def downgrade() -> None:
    op.drop_index("ix_ioc_matches_tenant_event_ts", table_name="ioc_matches")
    op.drop_index("ix_iocs_tenant_type_last_seen", table_name="iocs")
