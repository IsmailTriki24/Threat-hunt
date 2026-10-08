import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


def _pk() -> Mapped[uuid.UUID]:
    return mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)


def _tenant() -> Mapped[uuid.UUID]:
    return mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)


class DetectionRule(Base):
    """A tenant detection. `content` is the author's source (Sigma / hunt query); `compiled` is the validated Condition tree
    that is actually executed. Lifecycle: DRAFT -> TESTING -> ACTIVE <-> DISABLED, any -> ARCHIVED."""

    __tablename__ = "detection_rules"

    id: Mapped[uuid.UUID] = _pk()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    format: Mapped[str] = mapped_column(String(16))
    content: Mapped[str] = mapped_column(Text)
    version: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[str] = mapped_column(String(12), default="DRAFT", index=True)
    severity: Mapped[str] = mapped_column(String(16), default="MEDIUM")
    compiled: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    unsupported: Mapped[list[str]] = mapped_column(JSONB, default=list)
    warnings: Mapped[list[str]] = mapped_column(JSONB, default=list)
    techniques: Mapped[list[str]] = mapped_column(JSONB, default=list)
    tactics: Mapped[list[str]] = mapped_column(JSONB, default=list)
    tags: Mapped[list[str]] = mapped_column(JSONB, default=list)
    hunt_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("hunts.id", ondelete="SET NULL"), nullable=True)
    # Result of the last full run of the rule's unit tests against the *current* version (null = not run / stale).
    tests_passed: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    tests_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # High-water mark of ingestion time already evaluated by the scheduler.
    last_evaluated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_run_status: Mapped[str] = mapped_column(String(12), default="")
    last_run_error: Mapped[str] = mapped_column(String(300), default="")
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class RuleVersion(Base):
    """Immutable history: one row per saved content revision."""

    __tablename__ = "detection_rule_versions"
    __table_args__ = (UniqueConstraint("rule_id", "version", name="uq_rule_version"),)

    id: Mapped[uuid.UUID] = _pk()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    rule_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("detection_rules.id", ondelete="CASCADE"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    format: Mapped[str] = mapped_column(String(16))
    content: Mapped[str] = mapped_column(Text)
    note: Mapped[str] = mapped_column(String(300), default="")
    changed_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class RuleTestCase(Base):
    """A sample event and whether the rule must (not) match it."""

    __tablename__ = "detection_test_cases"

    id: Mapped[uuid.UUID] = _pk()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    rule_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("detection_rules.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    event: Mapped[dict[str, Any]] = mapped_column(JSONB)
    expect_match: Mapped[bool] = mapped_column(Boolean)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class DetectionRun(Base):
    """One execution of a rule over telemetry (scheduled or analyst-triggered backtest). Backtests never raise alerts."""

    __tablename__ = "detection_runs"

    id: Mapped[uuid.UUID] = _pk()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    rule_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("detection_rules.id", ondelete="CASCADE"), index=True)
    rule_version: Mapped[int] = mapped_column(Integer)
    kind: Mapped[str] = mapped_column(String(12))  # scheduled | backtest
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(12))  # ok | error
    error: Mapped[str] = mapped_column(String(300), default="")
    matches: Mapped[int] = mapped_column(Integer, default=0)
    new_alerts: Mapped[int] = mapped_column(Integer, default=0)
    took_ms: Mapped[int] = mapped_column(Integer, default=0)
    sample_event_ids: Mapped[list[str]] = mapped_column(JSONB, default=list)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)


class Alert(Base):
    """A rule match on one event. Unique per (rule, event): re-evaluating never duplicates. The event is snapshotted so the
    alert survives telemetry retention."""

    __tablename__ = "detection_alerts"
    __table_args__ = (UniqueConstraint("rule_id", "event_id", name="uq_alert_rule_event"),)

    id: Mapped[uuid.UUID] = _pk()
    tenant_id: Mapped[uuid.UUID] = _tenant()
    rule_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("detection_rules.id", ondelete="CASCADE"), index=True)
    rule_version: Mapped[int] = mapped_column(Integer)
    rule_title: Mapped[str] = mapped_column(String(200))
    severity: Mapped[str] = mapped_column(String(16))
    event_id: Mapped[str] = mapped_column(String(64), index=True)
    event_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB)
    status: Mapped[str] = mapped_column(String(12), default="OPEN", index=True)  # OPEN | ACKNOWLEDGED | CLOSED
    case_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("cases.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
