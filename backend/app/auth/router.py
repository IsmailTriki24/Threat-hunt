import logging
import uuid
from datetime import UTC, datetime
from urllib.parse import parse_qs, urlencode, urlsplit

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import service as audit
from app.auth import oidc, service
from app.auth.deps import Principal, get_principal
from app.auth.schemas import LoginRequest, OidcInfo, SessionInfo, SwitchTenantRequest, TokenResponse
from app.core.config import Settings, get_settings
from app.core.db import get_session
from app.core.errors import AppError, Unauthorized
from app.core.metrics import LOGIN_ATTEMPTS
from app.core.ratelimit import client_ip, enforce
from app.users.models import User

log = logging.getLogger("app.auth")

router = APIRouter(prefix="/auth", tags=["auth"])
# The provider redirects to OIDC_REDIRECT_URI, whose path is registered there verbatim and lives outside /api/v1.
callback_router = APIRouter(tags=["auth"])

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
        tenant_id = await service.pick_tenant(session, user, body.tenant_id, prefer_slug=settings.oidc_default_tenant)
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


# --- Single sign-on (OIDC) ---------------------------------------------------------------------------------------

_SSO_LINK_KEY = "oidc:{kind}:{value}"  # provider sub / sid -> user id, for back-channel logout


def _app_origin(settings: Settings) -> str:
    parts = urlsplit(settings.oidc_redirect_uri)
    return f"{parts.scheme}://{parts.netloc}"


def _to_login(error: str) -> RedirectResponse:
    return RedirectResponse(f"/login?{urlencode({'sso_error': error})}", status_code=302)


@router.get("/oidc", response_model=OidcInfo)
async def oidc_info(settings: Settings = Depends(get_settings)) -> OidcInfo:
    return OidcInfo(enabled=settings.oidc_enabled, name=settings.oidc_provider_name)


@router.get("/oidc/login")
async def oidc_login(request: Request, next: str | None = None, settings: Settings = Depends(get_settings)) -> Response:
    if not settings.oidc_enabled:
        return _to_login("disabled")
    await enforce(request, f"login:ip:{client_ip(request)}", 30, 60)
    try:
        url, cookie = await oidc.start(settings, next)
    except oidc.OidcError as exc:
        log.warning("sso start failed: %s", exc)
        return _to_login(exc.code)
    out = RedirectResponse(url, status_code=302)
    # Lax, not Strict: the browser comes back to the callback from the provider's site.
    out.set_cookie(
        oidc.STATE_COOKIE,
        cookie,
        max_age=oidc.STATE_TTL_S,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path=urlsplit(settings.oidc_redirect_uri).path,
    )
    return out


@callback_router.get("/api/auth/callback/{provider}", include_in_schema=False)
async def oidc_callback(
    provider: str,
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> Response:
    if not settings.oidc_enabled or request.url.path != urlsplit(settings.oidc_redirect_uri).path:
        return _to_login("disabled")
    await enforce(request, f"login:ip:{client_ip(request)}", 30, 60)
    email: str | None = None
    try:
        if error:
            raise oidc.OidcError("provider_rejected", f"provider returned error={error}")
        flow = oidc.read_state(settings, request.cookies.get(oidc.STATE_COOKIE), state)
        if not code:
            raise oidc.OidcError("provider_rejected", "callback without a code")
        identity = await oidc.finish(settings, flow, code)
        email = identity["email"]
        user, created = await service.sso_user(session, settings, email=email, name=identity["name"])
        if created and user is not None:
            await audit.record(
                request,
                "user.provisioned",
                actor_label=email,
                resource_type="user",
                resource_id=str(user.id),
                details={"method": "oidc"},
            )
        if user is None or not user.is_active:
            raise oidc.OidcError("unknown_user", f"no active platform user for {email}")
        try:
            tenant_id = await service.pick_tenant(session, user, None, prefer_slug=settings.oidc_default_tenant)
        except AppError as exc:
            raise oidc.OidcError("no_access", str(exc)) from exc
    except oidc.OidcError as exc:
        LOGIN_ATTEMPTS.labels("failure").inc()
        log.warning("sso sign-in failed (%s): %s", exc.code, exc)
        await audit.record(
            request, "auth.login", "failure", actor_label=email, details={"method": "oidc", "reason": exc.code}
        )
        out = _to_login(exc.code)
        out.delete_cookie(oidc.STATE_COOKIE, path=urlsplit(settings.oidc_redirect_uri).path)
        return out

    user.last_login_at = datetime.now(UTC)
    if not user.full_name and identity["name"]:
        user.full_name = identity["name"][:200]
    refresh_raw = await service.issue_refresh_token(session, settings, user_id=user.id, tenant_id=tenant_id)
    await session.commit()  # before the browser follows the redirect and spends the refresh token
    ttl = settings.refresh_token_ttl_days * 86400
    try:
        for kind in ("sub", "sid"):
            if identity.get(kind):
                await request.app.state.redis.set(
                    _SSO_LINK_KEY.format(kind=kind, value=identity[kind]), str(user.id), ex=ttl
                )
    except Exception:
        log.warning("could not record the SSO session link; back-channel logout will not reach it")
    LOGIN_ATTEMPTS.labels("success").inc()
    await audit.record(
        request, "auth.login", "success", actor_label=user.email, tenant_id=tenant_id, details={"method": "oidc"}
    )
    out = RedirectResponse(flow["next"], status_code=302)
    _set_cookie(out, settings, refresh_raw)
    out.delete_cookie(oidc.STATE_COOKIE, path=urlsplit(settings.oidc_redirect_uri).path)
    return out


@router.get("/oidc/logout")
async def oidc_logout(settings: Settings = Depends(get_settings)) -> Response:
    """Ends the provider session too, so 'Sign in with ...' asks again. Call after POST /logout."""
    if not settings.oidc_enabled:
        return RedirectResponse("/login", status_code=302)
    try:
        url = await oidc.logout_url(settings, f"{_app_origin(settings)}/login")
    except oidc.OidcError as exc:
        log.warning("sso logout: %s", exc)
        url = None
    return RedirectResponse(url or "/login", status_code=302)


@router.post("/oidc/backchannel-logout", include_in_schema=False)
async def oidc_backchannel_logout(
    request: Request, session: AsyncSession = Depends(get_session), settings: Settings = Depends(get_settings)
) -> Response:
    """The provider tells us a session ended there: revoke the user's refresh tokens (access tokens lapse within
    ACCESS_TOKEN_TTL_MINUTES). Register `<app>/api/v1/auth/oidc/backchannel-logout` as the provider's logout URI."""
    no_store = {"cache-control": "no-store"}
    if not settings.oidc_enabled:
        return Response(status_code=404)
    await enforce(request, f"bclogout:ip:{client_ip(request)}", 60, 60)
    token = (parse_qs((await request.body()).decode(errors="replace")).get("logout_token") or [""])[0]
    try:
        claims = await oidc.verify_logout_token(settings, token)
    except oidc.OidcError as exc:
        log.warning("back-channel logout rejected: %s", exc)
        return Response(status_code=400, headers=no_store)
    user_id: str | None = None
    for kind in ("sid", "sub"):
        if claims.get(kind):
            user_id = user_id or await request.app.state.redis.get(_SSO_LINK_KEY.format(kind=kind, value=claims[kind]))
    if user_id:
        await service.revoke_user_tokens(session, uuid.UUID(user_id))
        await audit.record(
            request, "auth.logout", "success", details={"method": "oidc-backchannel"}, resource_id=user_id
        )
    return Response(status_code=200, headers=no_store)
