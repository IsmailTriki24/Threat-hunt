import uuid

from pydantic import BaseModel, EmailStr, Field


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)
    tenant_id: uuid.UUID | None = None  # optional tenant to log into; membership is verified server-side


class SwitchTenantRequest(BaseModel):
    tenant_id: uuid.UUID


class TenantRef(BaseModel):
    id: uuid.UUID
    slug: str
    name: str


class SessionInfo(BaseModel):
    user_id: uuid.UUID
    email: str
    full_name: str
    role: str
    permissions: list[str]
    tenant: TenantRef | None
    available_tenants: list[TenantRef]


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105
    expires_in: int
    session: SessionInfo
