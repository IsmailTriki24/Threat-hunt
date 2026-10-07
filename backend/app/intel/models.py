import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Integer, LargeBinary, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


def _tenant() -> Mapped[uuid.UUID]:
    return mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)


class IntelEntity(Base):
    """Tenant-scoped threat-intelligence entity (indicator or named threat object). Everything here is private to the
    tenant: reputation is cached per tenant because it may have been fetched with that tenant's provider credentials."""

    __tablename__ = "intel_entities"
    __table_args__ = (UniqueConstraint("tenant_id", "type", "value", name="uq_intel_entity"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = _tenant()
    type: Mapped[str] = mapped_column(String(16), index=True)
    value: Mapped[str] = mapped_column(String(2048))
    # Analyst / watchlist judgement (also what STIX imports set). Feeds the scoring model as the `watchlist` signal.
    watch_verdict: Mapped[str | None] = mapped_column(String(12), nullable=True)  # malicious | suspicious | benign
    watch_confidence: Mapped[int] = mapped_column(Integer, default=0)  # 0-100
    notes: Mapped[str] = mapped_column(Text, default="")
    tags: Mapped[list[str]] = mapped_column(JSONB, default=list)
    score: Mapped[int] = mapped_column(Integer, default=0)
    verdict: Mapped[str] = mapped_column(String(12), default="unknown")  # unknown | benign | suspicious | malicious
    score_breakdown: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    source: Mapped[str] = mapped_column(String(16), default="lookup")  # lookup | case | import | manual
    last_enriched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class IntelObservation(Base):
    """What one provider said about one entity at one time (cached; refreshed after its TTL)."""

    __tablename__ = "intel_observations"
    __table_args__ = (UniqueConstraint("entity_id", "provider", name="uq_intel_observation"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = _tenant()
    entity_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("intel_entities.id", ondelete="CASCADE"), index=True)
    provider: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16))  # ok | not_found | error | unavailable
    verdict: Mapped[str] = mapped_column(String(12), default="unknown")
    confidence: Mapped[int] = mapped_column(Integer, default=0)
    summary: Mapped[str] = mapped_column(String(500), default="")
    data: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)  # trimmed, allow-listed provider fields only
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class IntelRelation(Base):
    __tablename__ = "intel_relations"
    __table_args__ = (UniqueConstraint("tenant_id", "src_id", "dst_id", "kind", name="uq_intel_relation"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = _tenant()
    src_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("intel_entities.id", ondelete="CASCADE"), index=True)
    dst_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("intel_entities.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(32))  # indicates | uses | attributed-to | part-of
    source: Mapped[str] = mapped_column(String(32), default="manual")


class IntelProvider(Base):
    """Per-tenant provider settings. Offline providers (heuristics, watchlist) need no row."""

    __tablename__ = "intel_providers"
    __table_args__ = (UniqueConstraint("tenant_id", "provider", name="uq_intel_provider"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = _tenant()
    provider: Mapped[str] = mapped_column(String(32))
    enabled: Mapped[bool] = mapped_column(default=True)
    config: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    secrets_enc: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    last_status: Mapped[str] = mapped_column(String(16), default="unknown")
    last_detail: Mapped[str] = mapped_column(String(300), default="")
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
