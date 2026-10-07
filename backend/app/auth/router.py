import uuid

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import service as audit
from app.auth import service
from app.auth.deps import Principal, get_principal
from app.auth.schemas import LoginRequest, SessionInfo, SwitchTenantRequest, TokenResponse
from app.core.config import Settings, get_settings
from app.core.db import get_session
from app.core.errors import AppError, Unauthorized
from app.core.metrics import LOGIN_ATTEMPTS
from app.core.ratelimit import client_ip, enforce
from app.users.models import User

router = APIRouter(prefix="/auth", tags=["auth"])

COOKIE = "refresh_token"
COOKIE_PATH = "/api/v1/auth"


async def csrf_guard(request: Request) -> None:
    """Cookie-authenticated endpoints require a custom header, which cross-site forms cannot send.
    Combined with SameSite=Strict this blocks CSRF on refresh/logout/switch."""
    if request.headers.get("x-requested-with") != "threat-hunt":
        raise AppError("Missing CSRF guard header")


def _set_cookie(response: Response, settings: Settings, raw: str) -> None:
    response.set_cookie(
        COOKIE,
        raw,
        max_age=settings.refresh_token_ttl_days * 86400,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        path=COOKIE_PATH,
    )


async def _token_response(
    session: AsyncSession,
    settings: Settings,
    response: Response,
    user: User,
    tenant_id: uuid.UUID | None,
    refresh_raw: str,
) -> TokenResponse:
    access, ttl = service.make_access(settings, user, tenant_id)
    _set_cookie(response, settings, refresh_raw)
    return TokenResponse(
        access_token=access, expires_in=ttl, session=await service.build_session_info(session, user, tenant_id)
    )


@router.post("/login", response_model=TokenResponse)
async def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> TokenResponse:
    await enforce(request, f"login:ip:{client_ip(request)}", 30, 60)
    await enforce(request, f"login:email:{body.email.lower()}", 10, 900)
    try:
        user = await service.authenticate(session, body.email, body.password)
        tenant_id = await service.pick_tenant(session, user, body.tenant_id)
    except AppError as exc:
        LOGIN_ATTEMPTS.labels("failure").inc()
        await audit.record(request, "auth.login", "failure", actor_label=body.email, details={"reason": exc.code})
        if isinstance(exc, Unauthorized):
            raise Unauthorized("Invalid credentials") from None
        raise
    refresh_raw = await service.issue_refresh_token(session, settings, user_id=user.id, tenant_id=tenant_id)
    result = await _token_response(session, settings, response, user, tenant_id, refresh_raw)
    LOGIN_ATTEMPTS.labels("success").inc()
    await audit.record(request, "auth.login", "success", actor_label=user.email, tenant_id=tenant_id)
    return result


@router.post("/refresh", response_model=TokenResponse, dependencies=[Depends(csrf_guard)])
async def refresh(
    request: Request,
    response: Response,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> TokenResponse:
    raw = request.cookies.get(COOKIE)
    if not raw:
        raise Unauthorized("Missing refresh token")
    await enforce(request, f"refresh:ip:{client_ip(request)}", 60, 60)
    try:
        new_raw, user, tenant_id = await service.rotate_refresh_token(session, settings, raw)
    except Unauthorized:
        response.delete_cookie(COOKIE, path=COOKIE_PATH)
        await audit.record(request, "auth.refresh", "failure")
        raise
    return await _token_response(session, settings, response, user, tenant_id, new_raw)


@router.post("/logout", status_code=204, dependencies=[Depends(csrf_guard)])
async def logout(request: Request, response: Response, session: AsyncSession = Depends(get_session)) -> Response:
    raw = request.cookies.get(COOKIE)
    if raw:
        await service.revoke_by_raw(session, raw)
    out = Response(status_code=204)
    out.delete_cookie(COOKIE, path=COOKIE_PATH)
    return out


@router.post("/switch-tenant", response_model=TokenResponse, dependencies=[Depends(csrf_guard)])
async def switch_tenant(
    body: SwitchTenantRequest,
    request: Request,
    response: Response,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> TokenResponse:
    user = await session.get(User, principal.user_id)
    if user is None:
        raise Unauthorized("Invalid or expired token")
    tenant_id = await service.pick_tenant(session, user, body.tenant_id)
    if old := request.cookies.get(COOKIE):
        await service.revoke_by_raw(session, old)
    refresh_raw = await service.issue_refresh_token(session, settings, user_id=user.id, tenant_id=tenant_id)
    result = await _token_response(session, settings, response, user, tenant_id, refresh_raw)
    await audit.record(request, "auth.switch_tenant", principal=principal, tenant_id=tenant_id)
    return result


@router.get("/me", response_model=SessionInfo)
async def me(
    principal: Principal = Depends(get_principal), session: AsyncSession = Depends(get_session)
) -> SessionInfo:
    user = await session.get(User, principal.user_id)
    if user is None:
        raise Unauthorized("Invalid or expired token")
    return await service.build_session_info(session, user, principal.tenant_id)
