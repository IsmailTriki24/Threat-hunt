"""Move one tenant between deployments: settings, members, log sources and IOC feeds (with credentials), sealed.

The file is opaque without the passphrase (scrypt -> Fernet over the whole payload, so even the tenant name and the SIEM
addresses are hidden). Credentials are decrypted with the source deployment's key on export and re-encrypted with the
target's key on import. NOT moved: telemetry, cases, hunts, detections, indicators, provider keys, and per-source and
per-feed runtime state (cursors, health, counters, last run), which rebuild themselves: an imported feed runs at once.
"""

import base64
import hashlib
import json
import os
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.connectors import registry
from app.core.config import Settings
from app.core.crypto import decrypt_json, encrypt_json
from app.core.errors import AppError, Conflict, NotFound
from app.datasources import service as ds_service
from app.datasources.models import DataSource
from app.iochunt.feeds import registry as feed_registry
from app.iochunt.models import IocFeed
from app.tenants.models import Tenant
from app.users.models import Membership, User

FORMAT = 1
_SCRYPT = {"n": 2**15, "r": 8, "p": 1, "maxmem": 128 * 1024 * 1024}


def _key(passphrase: str, salt: bytes) -> bytes:
    return base64.urlsafe_b64encode(hashlib.scrypt(passphrase.encode(), salt=salt, dklen=32, **_SCRYPT))


def seal(payload: dict[str, Any], passphrase: str) -> bytes:
    salt = os.urandom(16)
    token = Fernet(_key(passphrase, salt)).encrypt(json.dumps(payload).encode())
    return json.dumps(
        {"format": FORMAT, "kdf": "scrypt", "salt": base64.b64encode(salt).decode(), "token": token.decode()}
    ).encode()


def unseal(blob: bytes, passphrase: str) -> dict[str, Any]:
    try:
        envelope = json.loads(blob)
        if envelope.get("format") != FORMAT:
            raise AppError("Unsupported bundle format")
        payload = json.loads(
            Fernet(_key(passphrase, base64.b64decode(envelope["salt"]))).decrypt(envelope["token"].encode())
        )
    except (InvalidToken, KeyError, ValueError, TypeError):
        raise AppError("Wrong passphrase, or the file is not a tenant bundle or was altered") from None
    if not isinstance(payload, dict):
        raise AppError("The file is not a tenant bundle")
    return payload


def _feed_out(settings: Settings, f: IocFeed) -> dict[str, Any]:
    return {
        "name": f.name,
        "feed_type": f.feed_type,
        "config": f.config,
        "secrets": {k: str(v) for k, v in decrypt_json(settings, f.secrets_enc).items()},
        "enabled": f.enabled,
        "interval_minutes": f.interval_minutes,
        "max_age_days": f.max_age_days,
        "min_confidence": f.min_confidence,
        "max_items": f.max_items,
    }


def _feed_in(settings: Settings, tenant_id: Any, f: dict[str, Any]) -> IocFeed:
    return IocFeed(
        tenant_id=tenant_id,
        name=f["name"],
        feed_type=f["feed_type"],
        config=f["config"],
        secrets_enc=encrypt_json(settings, f["secrets"]) if f["secrets"] else None,
        enabled=f["enabled"],
        interval_minutes=f["interval_minutes"],
        max_age_days=f["max_age_days"],
        min_confidence=f["min_confidence"],
        max_items=f["max_items"],
    )


async def export_tenant(session: AsyncSession, settings: Settings, slug: str) -> dict[str, Any]:
    tenant = (await session.execute(select(Tenant).where(Tenant.slug == slug))).scalar_one_or_none()
    if tenant is None:
        raise NotFound(f"No tenant with slug {slug!r}")
    sources = (
        await session.execute(select(DataSource).where(DataSource.tenant_id == tenant.id).order_by(DataSource.name))
    ).scalars()
    feeds = (
        await session.execute(select(IocFeed).where(IocFeed.tenant_id == tenant.id).order_by(IocFeed.name))
    ).scalars()
    members = await session.execute(
        select(User, Membership)
        .join(Membership, Membership.user_id == User.id)
        .where(Membership.tenant_id == tenant.id)
        .order_by(User.email)
    )
    return {
        "tenant": {
            "slug": tenant.slug,
            "name": tenant.name,
            "retention_days": tenant.retention_days,
            "is_active": tenant.is_active,
        },
        "members": [
            {
                "email": u.email,
                "full_name": u.full_name,
                "password_hash": u.password_hash,
                "user_active": u.is_active,
                "role": m.role,
                "active": m.is_active,
            }
            for u, m in members.all()
            if not u.is_super_admin
        ],
        "data_sources": [
            {
                "name": d.name,
                "connector_type": d.connector_type,
                "config": d.config,
                "secrets": {k: str(v) for k, v in decrypt_json(settings, d.secrets_enc).items()},
                "enabled": d.enabled,
            }
            for d in sources
        ],
        "feeds": [_feed_out(settings, f) for f in feeds],
    }


async def import_tenant(
    session: AsyncSession, settings: Settings, payload: dict[str, Any], slug: str | None = None
) -> dict[str, Any]:
    """Create the tenant, its members and its sources here. All or nothing; never touches an existing tenant."""
    try:
        t = payload["tenant"]
        members, sources = payload["members"], payload["data_sources"]
        feeds = payload.get("feeds", [])  # bundles written before feeds were moved have none
        target_slug = slug or t["slug"]
        if (await session.execute(select(Tenant.id).where(Tenant.slug == target_slug))).first():
            raise Conflict(f"A tenant with slug {target_slug!r} already exists here; nothing was imported")
        for s in sources:  # validate everything before writing anything
            registry.build(s["connector_type"], s["config"])
        for f in feeds:
            feed_registry.build(f["feed_type"], f["config"])
    except (KeyError, TypeError):
        raise AppError("The file is not a tenant bundle") from None
    except (ValidationError, ValueError) as exc:
        raise AppError(f"A log source or feed in the bundle is not valid for this version: {str(exc)[:200]}") from None

    tenant = Tenant(slug=target_slug, name=t["name"], retention_days=t["retention_days"], is_active=t["is_active"])
    session.add(tenant)
    await session.flush()
    created = attached = 0
    for m in members:
        user = (await session.execute(select(User).where(User.email == m["email"].lower()))).scalar_one_or_none()
        if user is None:
            user = User(
                email=m["email"].lower(),
                full_name=m["full_name"],
                password_hash=m["password_hash"],
                is_active=m["user_active"],
            )
            session.add(user)
            await session.flush()
            created += 1
        elif user.is_super_admin:
            continue
        else:
            attached += 1
        session.add(Membership(user_id=user.id, tenant_id=tenant.id, role=m["role"], is_active=m["active"]))
    new_keys: dict[str, str] = {}
    for s in sources:
        raw_key, key_hash = ds_service.new_ingest_key()
        session.add(
            DataSource(
                tenant_id=tenant.id,
                name=s["name"],
                connector_type=s["connector_type"],
                config=s["config"],
                secrets_enc=ds_service.encrypt_secrets(settings, s["secrets"]),
                enabled=s["enabled"],
                ingest_key_hash=key_hash,
            )
        )
        if not registry._REGISTRY[s["connector_type"]].supports_collect:  # noqa: SLF001  push sources need their new key
            new_keys[s["name"]] = raw_key
    for f in feeds:
        session.add(_feed_in(settings, tenant.id, f))
    await session.flush()
    return {
        "slug": target_slug,
        "members_created": created,
        "members_attached": attached,
        "data_sources": len(sources),
        "feeds": len(feeds),
        "ingest_keys": new_keys,
    }


async def export_feeds(session: AsyncSession, settings: Settings, slug: str) -> dict[str, Any]:
    """Only the tenant's IOC feeds (with their keys): for adding them to a tenant that already exists elsewhere."""
    tenant = (await session.execute(select(Tenant).where(Tenant.slug == slug))).scalar_one_or_none()
    if tenant is None:
        raise NotFound(f"No tenant with slug {slug!r}")
    feeds = (
        await session.execute(select(IocFeed).where(IocFeed.tenant_id == tenant.id).order_by(IocFeed.name))
    ).scalars()
    return {"kind": "feeds", "tenant_slug": tenant.slug, "feeds": [_feed_out(settings, f) for f in feeds]}


async def import_feeds(
    session: AsyncSession, settings: Settings, payload: dict[str, Any], slug: str | None = None
) -> dict[str, Any]:
    """Add the file's feeds to an EXISTING tenant. A feed whose name the tenant already has is left exactly as it is.
    Reads a feeds file or a whole tenant bundle. All or nothing."""
    try:
        feeds = payload["feeds"]
        target_slug = slug or payload.get("tenant_slug") or payload["tenant"]["slug"]
        for f in feeds:  # validate everything before writing anything
            feed_registry.build(f["feed_type"], f["config"])
    except (KeyError, TypeError):
        raise AppError("The file does not contain IOC feeds") from None
    except (ValidationError, ValueError) as exc:
        raise AppError(f"A feed in the file is not valid for this version: {str(exc)[:200]}") from None
    tenant = (await session.execute(select(Tenant).where(Tenant.slug == target_slug))).scalar_one_or_none()
    if tenant is None:
        raise NotFound(f"No tenant with slug {target_slug!r} here; create or import it first")
    have = set((await session.execute(select(IocFeed.name).where(IocFeed.tenant_id == tenant.id))).scalars())
    added = [f["name"] for f in feeds if f["name"] not in have]
    skipped = [f["name"] for f in feeds if f["name"] in have]
    for f in feeds:
        if f["name"] not in have:
            session.add(_feed_in(settings, tenant.id, f))
    await session.flush()
    return {"slug": target_slug, "added": added, "skipped": skipped}
