import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, LargeBinary, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class DataSource(Base):
    __tablename__ = "data_sources"
    __table_args__ = (UniqueConstraint("tenant_id", "name", name="uq_datasource_name"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    connector_type: Mapped[str] = mapped_column(String(64))
    config: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)  # non-secret, validated by the connector
    secrets_enc: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)  # Fernet-encrypted JSON
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    # Push sources authenticate with a per-source key; only its SHA-256 is stored.
    ingest_key_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, unique=True)
    health_status: Mapped[str] = mapped_column(String(16), default="unknown", server_default="unknown")
    health_detail: Mapped[str] = mapped_column(String(300), default="")
    health_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_ingest_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    events_total: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    cursor: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
