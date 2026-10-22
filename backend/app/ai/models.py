import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class AiRun(Base):
    """One AI-assisted investigation. The full tool trace is kept (audit + reproducibility); conclusions are stored *after* validation."""

    __tablename__ = "ai_runs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    hunt_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("hunts.id", ondelete="SET NULL"), nullable=True, index=True
    )
    case_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("cases.id", ondelete="SET NULL"), nullable=True, index=True
    )  # the case opened from this run's hunt report
    goal: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(12))  # COMPLETED | INCOMPLETE | FAILED
    provider: Mapped[str] = mapped_column(String(32), default="")
    model: Mapped[str] = mapped_column(String(64), default="")
    hours_back: Mapped[int] = mapped_column(Integer, default=24)
    mode: Mapped[str] = mapped_column(String(10), default="standard")
    state: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB, nullable=True
    )  # structured investigation state (resumable)
    steps: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    conclusion: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    saved_findings: Mapped[list[str]] = mapped_column(JSONB, default=list)  # hunt finding ids created from this run
    input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str] = mapped_column(String(300), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)

    @property
    def resumable(self) -> bool:
        return self.status != "COMPLETED" and bool(self.state)


class AiLesson(Base):
    """One lesson about HOW to search, kept for the tenant's future hunts (the experience library). Written by the platform from a finished
    run's trace (origin "auto") or by an analyst; never about findings. Shown to the agent at the start of a hunt; analysts can disable or
    delete any of them."""

    __tablename__ = "ai_lessons"
    __table_args__ = (UniqueConstraint("tenant_id", "fingerprint", name="uq_ai_lesson_fingerprint"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    run_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("ai_runs.id", ondelete="SET NULL"), nullable=True)
    cue: Mapped[str] = mapped_column(String(200))  # when it applies
    lesson: Mapped[str] = mapped_column(String(400))
    evidence: Mapped[str] = mapped_column(String(300), default="")  # what in the trace supports it
    confidence: Mapped[str] = mapped_column(String(8), default="medium")  # low | medium | high
    origin: Mapped[str] = mapped_column(String(8), default="auto")  # auto | analyst
    status: Mapped[str] = mapped_column(String(8), default="active")  # active | disabled
    fingerprint: Mapped[str] = mapped_column(String(40))
    times_shown: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
