import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, LargeBinary, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


def _pk() -> Mapped[uuid.UUID]:
    return mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)


def _tenant() -> Mapped[uuid.UUID]:
    return mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)


class Threat(Base):
    """A named threat (malware family, actor, campaign or report) that groups its indicators (IOCs), behaviours (IOAs) and ATT&CK
    techniques (TTPs) into one bulletin an analyst can read and validate as a unit."""

    __tablename__ = "threats"
    __table_args__ = (UniqueConstraint("tenant_id", "key", name="uq_threat_key"),)

    id: Mapped[uuid.UUID] = _pk()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    key: Mapped[str] = mapped_column(String(160))  # normalised name; the grouping identity
    name: Mapped[str] = mapped_column(String(200), index=True)
    kind: Mapped[str] = mapped_column(String(12), default="other")  # malware | actor | campaign | report | other
    aliases: Mapped[list[str]] = mapped_column(JSONB, default=list)
    description: Mapped[str] = mapped_column(Text, default="")
    references: Mapped[list[str]] = mapped_column(JSONB, default=list)
    mitre_id: Mapped[str] = mapped_column(String(16), default="")  # ATT&CK software/group this threat resolved to
    sources: Mapped[list[str]] = mapped_column(JSONB, default=list)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_updated: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    confidence: Mapped[int] = mapped_column(Integer, default=0)
    severity: Mapped[str] = mapped_column(String(10), default="MEDIUM")
    ioc_count: Mapped[int] = mapped_column(Integer, default=0)
    ioc_types: Mapped[dict[str, int]] = mapped_column(JSONB, default=dict)
    seen_count: Mapped[int] = mapped_column(
        Integer, default=0
    )  # events in our own telemetry already containing one of its IOCs
    status: Mapped[str] = mapped_column(String(12), default="NEW", index=True)  # NEW | VALIDATED | REJECTED | EXPIRED
    status_reason: Mapped[str] = mapped_column(String(300), default="")
    validated_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    case_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("cases.id", ondelete="SET NULL"), nullable=True)
    last_hunted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class ThreatTtp(Base):
    """An ATT&CK technique associated with a threat, with where the association came from."""

    __tablename__ = "threat_ttps"
    __table_args__ = (UniqueConstraint("threat_id", "technique_id", name="uq_threat_ttp"),)

    id: Mapped[uuid.UUID] = _pk()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    threat_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("threats.id", ondelete="CASCADE"), index=True)
    technique_id: Mapped[str] = mapped_column(String(16), index=True)
    source: Mapped[str] = mapped_column(String(10))  # mitre | feed | derived | manual
    confidence: Mapped[str] = mapped_column(String(6), default="LOW")
    note: Mapped[str] = mapped_column(String(300), default="")


class ThreatIoa(Base):
    """An indicator of attack: a *behaviour* (not an artefact). Runs as a hunt-language query over the local index and, where a vendor
    query is given, upstream in Trend Vision One. Sources: the built-in catalogue, the tenant's own detection rules, or an analyst."""

    __tablename__ = "threat_ioas"
    __table_args__ = (UniqueConstraint("threat_id", "name", name="uq_threat_ioa"),)

    id: Mapped[uuid.UUID] = _pk()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    threat_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("threats.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(160))
    description: Mapped[str] = mapped_column(String(500), default="")
    technique_id: Mapped[str] = mapped_column(String(16), default="")
    query_text: Mapped[str] = mapped_column(
        String(1000), default=""
    )  # human-readable (catalogue) or hunt query language (manual)
    condition: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB, nullable=True
    )  # executable Condition tree; takes precedence
    trend_query: Mapped[str] = mapped_column(String(1000), default="")  # TMV1-Query over endpoint telemetry
    severity: Mapped[str] = mapped_column(String(10), default="MEDIUM")
    source: Mapped[str] = mapped_column(String(10), default="catalog")  # catalog | rule | manual
    rule_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("detection_rules.id", ondelete="SET NULL"), nullable=True
    )  # a tenant detection rule
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)


class SignalMatch(Base):
    """An event matching a behaviour (IOA) or an ATT&CK technique (TTP) during a threat hunt. Unique per (signal, event)."""

    __tablename__ = "ioc_signal_matches"
    __table_args__ = (UniqueConstraint("kind", "ref", "event_id", name="uq_signal_match"),)

    id: Mapped[uuid.UUID] = _pk()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    hunt_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("ioc_hunts.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(3))  # ioa | ttp
    ref: Mapped[str] = mapped_column(String(64))  # IOA id or technique id
    label: Mapped[str] = mapped_column(String(200), default="")
    event_id: Mapped[str] = mapped_column(String(64), index=True)
    event_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    source: Mapped[str] = mapped_column(String(64))
    host: Mapped[str] = mapped_column(String(256), default="")
    user: Mapped[str] = mapped_column(String(256), default="")
    summary: Mapped[str] = mapped_column(String(500), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class IocFeed(Base):
    """A scheduled source of *recent* indicators for one tenant. Credentials are stored encrypted (never returned)."""

    __tablename__ = "ioc_feeds"
    __table_args__ = (UniqueConstraint("tenant_id", "name", name="uq_ioc_feed_name"),)

    id: Mapped[uuid.UUID] = _pk()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    name: Mapped[str] = mapped_column(String(120))
    feed_type: Mapped[str] = mapped_column(String(32))
    config: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    secrets_enc: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    interval_minutes: Mapped[int] = mapped_column(Integer, default=60)
    max_age_days: Mapped[int] = mapped_column(Integer, default=14)  # indicators older than this are never imported
    min_confidence: Mapped[int] = mapped_column(Integer, default=0)
    max_items: Mapped[int] = mapped_column(Integer, default=2000)  # newest/highest-confidence N kept per run
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_status: Mapped[str] = mapped_column(String(12), default="")  # ok | error
    last_detail: Mapped[str] = mapped_column(String(300), default="")
    last_new: Mapped[int] = mapped_column(Integer, default=0)
    last_seen_total: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Ioc(Base):
    """An indicator in the tenant's IOC database. Lifecycle: NEW -> VALIDATED | REJECTED -> EXPIRED."""

    __tablename__ = "iocs"
    __table_args__ = (UniqueConstraint("tenant_id", "type", "value", name="uq_ioc"),)

    id: Mapped[uuid.UUID] = _pk()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    feed_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("ioc_feeds.id", ondelete="SET NULL"), nullable=True, index=True
    )
    source: Mapped[str] = mapped_column(String(64), default="")  # feed name at import time, or "manual"
    type: Mapped[str] = mapped_column(String(16), index=True)
    value: Mapped[str] = mapped_column(String(2048))
    confidence: Mapped[int] = mapped_column(Integer, default=50)  # 0-100
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    threat_type: Mapped[str] = mapped_column(String(64), default="")  # botnet_cc | payload_delivery | phishing | ...
    malware: Mapped[str] = mapped_column(String(120), default="")
    description: Mapped[str] = mapped_column(String(1000), default="")
    reference: Mapped[str] = mapped_column(String(500), default="")
    tags: Mapped[list[str]] = mapped_column(JSONB, default=list)
    techniques: Mapped[list[str]] = mapped_column(JSONB, default=list)  # ATT&CK ids declared by the feed
    threat_name: Mapped[str] = mapped_column(
        String(200), default=""
    )  # grouping hint from the feed (family / actor / campaign)
    threat_kind: Mapped[str] = mapped_column(String(12), default="")
    threat_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("threats.id", ondelete="SET NULL"), nullable=True, index=True
    )
    status: Mapped[str] = mapped_column(String(12), default="NEW", index=True)
    status_reason: Mapped[str] = mapped_column(String(300), default="")
    validated_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    case_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("cases.id", ondelete="SET NULL"), nullable=True, index=True
    )
    seen_count: Mapped[int] = mapped_column(
        Integer, default=0
    )  # events in this tenant's own telemetry that already contain it
    seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_hunted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class IocAllow(Base):
    """Tenant allow-list: values that must never be imported or hunted (own domains, partners, scanners...)."""

    __tablename__ = "ioc_allowlist"
    __table_args__ = (UniqueConstraint("tenant_id", "type", "value", name="uq_ioc_allow"),)

    id: Mapped[uuid.UUID] = _pk()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    type: Mapped[str] = mapped_column(String(16))
    value: Mapped[str] = mapped_column(String(2048))  # for domains also matches subdomains
    reason: Mapped[str] = mapped_column(String(300), default="")
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class IocHunt(Base):
    """One automatic hunt over a batch of validated IOCs (mode=initial) or a scheduled re-check (mode=rehunt)."""

    __tablename__ = "ioc_hunts"

    id: Mapped[uuid.UUID] = _pk()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    name: Mapped[str] = mapped_column(String(200))
    hypothesis: Mapped[str] = mapped_column(Text, default="")
    mode: Mapped[str] = mapped_column(String(8), default="initial")
    status: Mapped[str] = mapped_column(
        String(10), default="PENDING", index=True
    )  # PENDING|RUNNING|COMPLETED|PARTIAL|FAILED
    ioc_ids: Mapped[list[str]] = mapped_column(JSONB, default=list)
    lookback_days: Mapped[int] = mapped_column(Integer, default=7)
    window_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    window_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    requested_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    case_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("cases.id", ondelete="SET NULL"), nullable=True, index=True
    )
    hunt_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("hunts.id", ondelete="SET NULL"), nullable=True)
    threat_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("threats.id", ondelete="SET NULL"), nullable=True, index=True
    )
    signals: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict
    )  # {"ioa_ids": [...], "ttps": [...]} hunted with the indicators
    signal_count: Mapped[int] = mapped_column(Integer, default=0)
    match_count: Mapped[int] = mapped_column(Integer, default=0)
    new_match_count: Mapped[int] = mapped_column(Integer, default=0)
    coverage: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)  # one entry per data source searched
    error: Mapped[str] = mapped_column(String(300), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class IocMatch(Base):
    """An IOC observed in an event. Unique per (ioc, event): re-hunts never duplicate."""

    __tablename__ = "ioc_matches"
    __table_args__ = (UniqueConstraint("ioc_id", "event_id", name="uq_ioc_match"),)

    id: Mapped[uuid.UUID] = _pk()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    hunt_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("ioc_hunts.id", ondelete="CASCADE"), index=True)
    ioc_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("iocs.id", ondelete="CASCADE"), index=True)
    event_id: Mapped[str] = mapped_column(String(64), index=True)
    event_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    source: Mapped[str] = mapped_column(String(64))
    matched_field: Mapped[str] = mapped_column(String(64), default="")
    host: Mapped[str] = mapped_column(String(256), default="")
    user: Mapped[str] = mapped_column(String(256), default="")
    summary: Mapped[str] = mapped_column(String(500), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
