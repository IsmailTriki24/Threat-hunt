import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field

from app.auth.rbac import Role


class UserCreate(BaseModel):
    email: EmailStr
    full_name: str = Field(default="", max_length=200)
    password: str = Field(min_length=12, max_length=256)
    role: Role


class MemberUpdate(BaseModel):
    role: Role | None = None
    is_active: bool | None = None


class MemberOut(BaseModel):
    user_id: uuid.UUID
    email: str
    full_name: str
    role: str
    is_active: bool
    last_login_at: datetime | None
