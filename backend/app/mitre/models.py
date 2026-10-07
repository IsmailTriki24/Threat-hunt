import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class MitreTactic(Base):
    """ATT&CK reference data (global, read-only at runtime; loaded by `app.cli mitre-load`)."""

    __tablename__ = "mitre_tactics"

    id: Mapped[str] = mapped_column(String(16), primary_key=True)  # TA0002
    shortname: Mapped[str] = mapped_column(String(64), unique=True)  # execution
    name: Mapped[str] = mapped_column(String(120))
    position: Mapped[int] = mapped_column(Integer, default=0)


class MitreTechnique(Base):
    __tablename__ = "mitre_techniques"

    id: Mapped[str] = mapped_column(String(16), primary_key=True)  # T1059 / T1059.001
    name: Mapped[str] = mapped_column(String(200))
    parent_id: Mapped[str | None] = mapped_column(
        ForeignKey("mitre_techniques.id", ondelete="CASCADE"), nullable=True, index=True
    )
    tactics: Mapped[list[str]] = mapped_column(JSONB, default=list)  # tactic shortnames
    description: Mapped[str] = mapped_column(Text, default="")
    url: Mapped[str] = mapped_column(String(300), default="")
    source: Mapped[str] = mapped_column(String(64), default="builtin")


class MitreMapping(Base):
    """A tenant claim that an object (hunt/case/finding/detection) exhibits a technique, with reasoning and evidence."""

    __tablename__ = "mitre_mappings"
    __table_args__ = (
        UniqueConstraint("tenant_id", "technique_id", "object_type", "object_id", name="uq_mitre_mapping"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    technique_id: Mapped[str] = mapped_column(ForeignKey("mitre_techniques.id"), index=True)
    object_type: Mapped[str] = mapped_column(String(16))  # hunt | case | finding | detection
    object_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    confidence: Mapped[str] = mapped_column(String(8))  # LOW | MEDIUM | HIGH
    reasoning: Mapped[str] = mapped_column(Text)
    evidence_event_ids: Mapped[list[str]] = mapped_column(JSONB, default=list)
    source: Mapped[str] = mapped_column(String(16), default="analyst")  # analyst | suggestion
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
