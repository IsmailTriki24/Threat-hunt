import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class Asset(Base):
    """Hosts, servers, users, IPs, domains, applications and cloud assets. Identity is (tenant, type, key)
    where `key` is the normalised (lower-cased) identifier that appears in telemetry."""

    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("tenant_id", "type", "key", name="uq_asset_identity"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    type: Mapped[str] = mapped_column(String(16))
    key: Mapped[str] = mapped_column(String(320))
    display_name: Mapped[str] = mapped_column(String(320))
    criticality: Mapped[str] = mapped_column(String(16), default="MEDIUM", server_default="MEDIUM")
    owner: Mapped[str] = mapped_column(String(200), default="")
    tags: Mapped[list[str]] = mapped_column(JSONB, default=list)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    event_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
