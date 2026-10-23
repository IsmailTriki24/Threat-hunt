"""Single sign-on through an OIDC provider, against a fake provider: the code flow, what makes it fail, and
back-channel logout."""

import time
import uuid
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from app.auth import oidc
from app.auth.rbac import Role
from app.core.config import get_settings

ISSUER = "https://sso.test/application/o/threat-hunt/"
CLIENT_ID = "client-123"
REDIRECT = "http://test/api/auth/callback/authentik"
CSRF = {"x-requested-with": "threat-hunt"}


class FakeProvider:
    def __init__(self) -> None:
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.signing_key: rsa.RSAPrivateKey | None = None  # set to sign with a key the JWKS does not publish
        self.kid = "k1"
        self.email = "nobody@test.example"
        self.sid = "sid-1"
        self.nonce_override: str | None = None
        self.issued_nonce = ""
        self.token_requests: list[dict[str, list[str]]] = []

    def sign(self, claims: dict[str, Any], kid: str | None = None) -> str:
        return jwt.encode(claims, self.signing_key or self.key, algorithm="RS256", headers={"kid": kid or self.kid})

    def jwk(self) -> dict[str, Any]:
        public = jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
        return {**public, "kid": self.kid, "use": "sig", "alg": "RS256"}

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.endswith("/.well-known/openid-configuration"):
            return httpx.Response(
                200,
                json={
                    "issuer": ISSUER,
                    "authorization_endpoint": "https://sso.test/application/o/authorize/",
                    "token_endpoint": "https://sso.test/application/o/token/",
                    "userinfo_endpoint": "https://sso.test/application/o/userinfo/",
                    "end_session_endpoint": f"{ISSUER}end-session/",
                    "jwks_uri": f"{ISSUER}jwks/",
                },
            )
        if url.endswith("/jwks/"):
            return httpx.Response(200, json={"keys": [self.jwk()]})
        if url.endswith("/token/"):
            form = parse_qs(request.content.decode())
            self.token_requests.append(form)
            if form.get("code") != ["good-code"]:
                return httpx.Response(400, json={"error": "invalid_grant"})
            now = int(time.time())
            id_token = self.sign(
                {
                    "iss": ISSUER,
                    "aud": CLIENT_ID,
                    "sub": f"sub-{self.email}",
                    "sid": self.sid,
                    "email": self.email,
                    "name": "Sso Person",
                    "iat": now,
                    "exp": now + 300,
                    "nonce": self.nonce_override or self.issued_nonce,
                }
            )
            return httpx.Response(200, json={"access_token": "at", "token_type": "Bearer", "id_token": id_token})
        return httpx.Response(404)


@pytest.fixture
def provider(monkeypatch: pytest.MonkeyPatch) -> FakeProvider:
    fake = FakeProvider()
    settings = get_settings()
    for name, value in {
        "oidc_issuer": ISSUER,
        "oidc_client_id": CLIENT_ID,
        "oidc_client_secret": "secret",
        "oidc_redirect_uri": REDIRECT,
    }.items():
        monkeypatch.setattr(settings, name, value)
    monkeypatch.setattr(oidc, "HTTP_TRANSPORT", httpx.MockTransport(fake.handler))
    monkeypatch.setattr(oidc, "_cache", {})
    return fake


async def _start(client: httpx.AsyncClient, provider: FakeProvider, next_path: str = "/hunts") -> str:
    r = await client.get("/api/v1/auth/oidc/login", params={"next": next_path})
    assert r.status_code == 302
    query = parse_qs(urlsplit(r.headers["location"]).query)
    assert query["client_id"] == [CLIENT_ID] and query["redirect_uri"] == [REDIRECT]
    assert query["code_challenge_method"] == ["S256"]
    provider.issued_nonce = query["nonce"][0]
    return query["state"][0]


async def test_oidc_disabled_by_default(client):
    assert (await client.get("/api/v1/auth/oidc")).json()["enabled"] is False
    r = await client.get("/api/v1/auth/oidc/login")
    assert r.status_code == 302 and r.headers["location"] == "/login?sso_error=disabled"


async def test_sso_signs_in_existing_user_and_session_refreshes(client, make, provider):
    t = await make.tenant()
    u = await make.user(t, Role.SOC_ANALYST)
    provider.email = u.email.upper()  # e-mail matching ignores case
    assert (await client.get("/api/v1/auth/oidc")).json() == {"enabled": True, "name": "Authentik"}

    state = await _start(client, provider)
    r = await client.get("/api/auth/callback/authentik", params={"code": "good-code", "state": state})
    assert r.status_code == 302 and r.headers["location"] == "/hunts"
    assert "refresh_token" in r.cookies
    sent = provider.token_requests[0]
    assert sent["redirect_uri"] == [REDIRECT] and sent["code_verifier"][0]

    session = await client.post("/api/v1/auth/refresh", headers=CSRF)
    assert session.status_code == 200
    assert session.json()["session"]["email"] == u.email and session.json()["session"]["tenant"]["id"] == str(t.id)


async def test_sso_refuses_unknown_user(client, provider):
    provider.email = f"ghost-{uuid.uuid4().hex[:6]}@test.example"
    state = await _start(client, provider)
    r = await client.get("/api/auth/callback/authentik", params={"code": "good-code", "state": state})
    assert r.headers["location"] == "/login?sso_error=unknown_user"
    assert "refresh_token" not in r.cookies


async def test_sso_refuses_user_without_membership(client, make, provider):
    u = await make.user(None, None)
    provider.email = u.email
    state = await _start(client, provider)
    r = await client.get("/api/auth/callback/authentik", params={"code": "good-code", "state": state})
    assert r.headers["location"] == "/login?sso_error=no_access"


@pytest.mark.parametrize("case", ["state", "nonce", "no-cookie", "foreign-key"])
async def test_sso_rejects_tampered_flows(client, make, provider, case):
    t = await make.tenant()
    u = await make.user(t, Role.VIEWER)
    provider.email = u.email
    state = await _start(client, provider)
    if case == "state":
        state = "forged"
    elif case == "nonce":
        provider.nonce_override = "replayed"
    elif case == "no-cookie":
        client.cookies.clear()
    elif case == "foreign-key":
        provider.signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    r = await client.get("/api/auth/callback/authentik", params={"code": "good-code", "state": state})
    assert r.status_code == 302 and r.headers["location"].startswith("/login?sso_error=")
    assert "refresh_token" not in r.cookies


async def test_sso_next_cannot_leave_the_site(client, make, provider):
    t = await make.tenant()
    u = await make.user(t, Role.VIEWER)
    provider.email = u.email
    state = await _start(client, provider, next_path="//evil.example/x")
    r = await client.get("/api/auth/callback/authentik", params={"code": "good-code", "state": state})
    assert r.headers["location"] == "/"


async def test_backchannel_logout_revokes_refresh_tokens(client, make, provider):
    t = await make.tenant()
    u = await make.user(t, Role.VIEWER)
    provider.email, provider.sid = u.email, f"sid-{uuid.uuid4().hex}"
    state = await _start(client, provider)
    await client.get("/api/auth/callback/authentik", params={"code": "good-code", "state": state})

    now = int(time.time())
    base = {"iss": ISSUER, "aud": CLIENT_ID, "iat": now, "jti": uuid.uuid4().hex, "sid": provider.sid}
    bad = provider.sign({**base, "events": {oidc.BACKCHANNEL_EVENT: {}}, "nonce": "x"})
    assert (await client.post("/api/v1/auth/oidc/backchannel-logout", data={"logout_token": bad})).status_code == 400

    good = provider.sign({**base, "events": {oidc.BACKCHANNEL_EVENT: {}}})
    r = await client.post("/api/v1/auth/oidc/backchannel-logout", data={"logout_token": good})
    assert r.status_code == 200
    assert (await client.post("/api/v1/auth/refresh", headers=CSRF)).status_code == 401


async def test_sso_logout_redirects_to_provider(client, provider):
    r = await client.get("/api/v1/auth/oidc/logout")
    assert r.status_code == 302 and r.headers["location"].startswith(f"{ISSUER}end-session/?client_id={CLIENT_ID}")


async def test_auto_provision_creates_user_in_default_tenant(client, make, provider, monkeypatch):
    t = await make.tenant()
    settings = get_settings()
    monkeypatch.setattr(settings, "oidc_auto_provision", True)
    monkeypatch.setattr(settings, "oidc_default_tenant", t.slug)
    monkeypatch.setattr(settings, "oidc_default_role", "VIEWER")
    provider.email = f"new-{uuid.uuid4().hex[:6]}@test.example"
    state = await _start(client, provider)
    r = await client.get("/api/auth/callback/authentik", params={"code": "good-code", "state": state})
    assert r.headers["location"] == "/hunts"
    me = (await client.post("/api/v1/auth/refresh", headers=CSRF)).json()["session"]
    assert me["email"] == provider.email and me["role"] == "VIEWER" and me["tenant"]["id"] == str(t.id)
    assert me["full_name"] == "Sso Person"


async def test_auto_provision_does_not_regrant_a_deactivated_membership(client, make, provider, monkeypatch, db):
    from sqlalchemy import update

    from app.users.models import Membership

    t = await make.tenant()
    u = await make.user(t, Role.SOC_ANALYST)
    await db.execute(update(Membership).where(Membership.user_id == u.id).values(is_active=False))
    await db.commit()
    settings = get_settings()
    monkeypatch.setattr(settings, "oidc_auto_provision", True)
    monkeypatch.setattr(settings, "oidc_default_tenant", t.slug)
    provider.email = u.email
    state = await _start(client, provider)
    r = await client.get("/api/auth/callback/authentik", params={"code": "good-code", "state": state})
    assert r.headers["location"] == "/login?sso_error=no_access"


async def test_listed_email_becomes_super_admin(client, make, provider, monkeypatch):
    t = await make.tenant()
    settings = get_settings()
    monkeypatch.setattr(settings, "oidc_default_tenant", t.slug)
    provider.email = f"boss-{uuid.uuid4().hex[:6]}@test.example"
    monkeypatch.setattr(settings, "oidc_auto_provision", True)
    monkeypatch.setattr(settings, "oidc_super_admins", f"other@test.example, {provider.email.upper()}")
    state = await _start(client, provider)
    r = await client.get("/api/auth/callback/authentik", params={"code": "good-code", "state": state})
    assert r.headers["location"] == "/hunts"
    me = (await client.post("/api/v1/auth/refresh", headers=CSRF)).json()["session"]
    assert me["role"] == "SUPER_ADMIN" and me["tenant"]["id"] == str(t.id)  # opens inside the default tenant
