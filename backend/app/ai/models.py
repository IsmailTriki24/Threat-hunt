import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
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
    goal: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(12))  # COMPLETED | INCOMPLETE | FAILED
    provider: Mapped[str] = mapped_column(String(32), default="")
    model: Mapped[str] = mapped_column(String(64), default="")
    hours_back: Mapped[int] = mapped_column(Integer, default=24)
    steps: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    conclusion: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    saved_findings: Mapped[list[str]] = mapped_column(JSONB, default=list)  # hunt finding ids created from this run
    input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str] = mapped_column(String(300), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
