import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field


class TenantCreate(BaseModel):
    slug: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$")
    name: str = Field(min_length=1, max_length=200)
    retention_days: int = Field(default=90, ge=1, le=3650)
    admin_email: EmailStr | None = None
    admin_password: str | None = Field(default=None, min_length=12, max_length=256)


class TenantUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    is_active: bool | None = None
    retention_days: int | None = Field(default=None, ge=1, le=3650)


class TenantOut(BaseModel):
    id: uuid.UUID
    slug: str
    name: str
    is_active: bool
    retention_days: int
    created_at: datetime
