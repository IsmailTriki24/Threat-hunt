"""Single sign-on through an OpenID Connect provider (Authentik): authorization code flow with PKCE.

The provider only proves who the person is. What they may do stays in the platform: the e-mail it vouches for must
belong to an active user here, whose memberships give the tenants and roles. Nobody is created on first sign-in.

The flow's state (state, nonce, PKCE verifier, where to land) travels in a short-lived cookie signed with JWT_SECRET,
so nothing is stored server-side between the redirect to the provider and the callback."""

import base64
import hashlib
import secrets
import time
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt

from app.core.config import Settings

HTTP_TRANSPORT: httpx.AsyncBaseTransport | None = None  # tests swap in a MockTransport
STATE_COOKIE = "oidc_state"
STATE_TTL_S = 600
_STATE_AUD = "threat-hunt-oidc-state"
_CACHE_TTL_S = 3600
_ALGORITHMS = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}
_LEEWAY_S = 60
BACKCHANNEL_EVENT = "http://schemas.openid.net/event/backchannel-logout"

_cache: dict[str, tuple[float, dict[str, Any]]] = {}


class OidcError(Exception):
    """A failed sign-in. `code` goes back to the sign-in page; the message only to the logs and the audit trail."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


async def _get_json(url: str) -> dict[str, Any]:
    async with httpx.AsyncClient(transport=HTTP_TRANSPORT, timeout=10) as client:
        res = await client.get(url, headers={"accept": "application/json"})
    if res.status_code != 200:
        raise OidcError("provider_unavailable", f"GET {url} returned {res.status_code}")
    data: dict[str, Any] = res.json()
    return data


async def _cached(url: str, *, force: bool = False) -> dict[str, Any]:
    hit = _cache.get(url)
    if hit and not force and hit[0] > time.monotonic():
        return hit[1]
    data = await _get_json(url)
    _cache[url] = (time.monotonic() + _CACHE_TTL_S, data)
    return data


async def discovery(settings: Settings) -> dict[str, Any]:
    url = settings.oidc_issuer.rstrip("/") + "/.well-known/openid-configuration"
    try:
        meta = await _cached(url)
    except httpx.HTTPError as exc:
        raise OidcError("provider_unavailable", f"OIDC discovery failed: {exc}") from exc
    if meta.get("issuer", "").rstrip("/") != settings.oidc_issuer.rstrip("/"):
        raise OidcError("provider_misconfigured", f"discovery issuer {meta.get('issuer')!r} != OIDC_ISSUER")
    return meta


def safe_next(path: str | None) -> str:
    """Only same-site relative paths: never `//host`, `/\\host` or an absolute URL (open redirect)."""
    if not path or not path.startswith("/") or path.startswith(("//", "/\\")):
        return "/"
    return path


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


async def start(settings: Settings, next_path: str | None) -> tuple[str, str]:
    """Returns (provider authorize URL, signed state cookie value)."""
    meta = await discovery(settings)
    state, nonce, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_urlsafe(64)
    cookie = jwt.encode(
        {
            "aud": _STATE_AUD,
            "exp": int(time.time()) + STATE_TTL_S,
            "state": state,
            "nonce": nonce,
            "verifier": verifier,
            "next": safe_next(next_path),
        },
        settings.jwt_secret,
        algorithm="HS256",
    )
    query = urlencode(
        {
            "response_type": "code",
            "client_id": settings.oidc_client_id,
            "redirect_uri": settings.oidc_redirect_uri,
            "scope": settings.oidc_scopes,
            "state": state,
            "nonce": nonce,
            "code_challenge": _b64url(hashlib.sha256(verifier.encode()).digest()),
            "code_challenge_method": "S256",
        }
    )
    return f"{meta['authorization_endpoint']}?{query}", cookie


def read_state(settings: Settings, cookie: str | None, state: str | None) -> dict[str, Any]:
    if not cookie or not state:
        raise OidcError("expired", "missing state cookie or state parameter")
    try:
        data: dict[str, Any] = jwt.decode(cookie, settings.jwt_secret, algorithms=["HS256"], audience=_STATE_AUD)
    except jwt.InvalidTokenError as exc:
        raise OidcError("expired", f"state cookie rejected: {exc}") from exc
    if not secrets.compare_digest(str(data.get("state", "")), state):
        raise OidcError("expired", "state mismatch")
    return data


async def _verify(settings: Settings, token: str, *, require: list[str]) -> dict[str, Any]:
    """Signature (provider JWKS, refetched once for an unknown key id), issuer, audience and expiry."""
    meta = await discovery(settings)
    try:
        header = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError as exc:
        raise OidcError("invalid_token", f"unreadable token: {exc}") from exc
    alg = header.get("alg")
    if alg not in _ALGORITHMS:
        raise OidcError("invalid_token", f"token algorithm {alg!r} not accepted")
    for force in (False, True):
        keys = (await _cached(meta["jwks_uri"], force=force)).get("keys", [])
        jwk = next((k for k in keys if k.get("kid") == header.get("kid")), None)
        if jwk is None and len(keys) == 1 and not header.get("kid"):
            jwk = keys[0]
        if jwk is not None:
            break
    else:
        raise OidcError("invalid_token", f"no provider key for kid {header.get('kid')!r}")
    try:
        claims: dict[str, Any] = jwt.decode(
            token,
            jwt.PyJWK(jwk, algorithm=alg).key,
            algorithms=[alg],
            audience=settings.oidc_client_id,
            issuer=meta["issuer"],
            leeway=_LEEWAY_S,
            options={"require": require},
        )
    except jwt.InvalidTokenError as exc:
        raise OidcError("invalid_token", f"token rejected: {exc}") from exc
    return claims


async def finish(settings: Settings, flow: dict[str, Any], code: str) -> dict[str, Any]:
    """Exchanges the code and returns the verified identity: {"sub", "sid", "email", "name"}."""
    meta = await discovery(settings)
    try:
        async with httpx.AsyncClient(transport=HTTP_TRANSPORT, timeout=15) as client:
            res = await client.post(
                meta["token_endpoint"],
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": settings.oidc_redirect_uri,
                    "code_verifier": flow["verifier"],
                },
                auth=(settings.oidc_client_id, settings.oidc_client_secret),
                headers={"accept": "application/json"},
            )
    except httpx.HTTPError as exc:
        raise OidcError("provider_unavailable", f"token request failed: {exc}") from exc
    if res.status_code != 200:
        raise OidcError("provider_rejected", f"token endpoint returned {res.status_code}: {res.text[:300]}")
    tokens = res.json()
    if not tokens.get("id_token"):
        raise OidcError("provider_rejected", "token response has no id_token")
    claims = await _verify(settings, tokens["id_token"], require=["exp", "iat", "sub"])
    if not secrets.compare_digest(str(claims.get("nonce", "")), flow["nonce"]):
        raise OidcError("invalid_token", "nonce mismatch")

    email, name = claims.get("email"), claims.get("name")
    if not email and tokens.get("access_token") and meta.get("userinfo_endpoint"):
        async with httpx.AsyncClient(transport=HTTP_TRANSPORT, timeout=10) as client:
            info = await client.get(
                meta["userinfo_endpoint"], headers={"authorization": f"Bearer {tokens['access_token']}"}
            )
        if info.status_code == 200 and info.json().get("sub") == claims["sub"]:
            email, name = info.json().get("email"), name or info.json().get("name")
    if not email:
        raise OidcError("no_email", "the provider did not return an e-mail address (is the 'email' scope mapped?)")
    return {"sub": claims["sub"], "sid": claims.get("sid"), "email": str(email).strip().lower(), "name": name or ""}


async def logout_url(settings: Settings, post_logout_redirect: str) -> str | None:
    meta = await discovery(settings)
    end = meta.get("end_session_endpoint")
    if not end:
        return None
    query = urlencode({"client_id": settings.oidc_client_id, "post_logout_redirect_uri": post_logout_redirect})
    return f"{end}?{query}"


async def verify_logout_token(settings: Settings, token: str) -> dict[str, Any]:
    """OIDC Back-Channel Logout 1.0, section 2.6: a signed logout token naming a subject, never carrying a nonce."""
    claims = await _verify(settings, token, require=["iat"])
    if BACKCHANNEL_EVENT not in (claims.get("events") or {}):
        raise OidcError("invalid_token", "not a back-channel logout token")
    if "nonce" in claims:
        raise OidcError("invalid_token", "logout token must not carry a nonce")
    if not claims.get("sub") and not claims.get("sid"):
        raise OidcError("invalid_token", "logout token names neither sub nor sid")
    return claims
