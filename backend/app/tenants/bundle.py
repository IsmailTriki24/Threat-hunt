"""Move one tenant between deployments: settings, members and log sources (with credentials) in one sealed file.

The file is opaque without the passphrase (scrypt -> Fernet over the whole payload, so even the tenant name and the SIEM
addresses are hidden). Credentials are decrypted with the source deployment's key on export and re-encrypted with the
target's key on import. NOT moved: telemetry, cases, hunts, detections, feeds, provider keys, and per-source runtime
state (cursors, health, counters), which rebuild themselves.
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
from app.core.crypto import decrypt_json
from app.core.errors import AppError, Conflict, NotFound
from app.datasources import service as ds_service
from app.datasources.models import DataSource
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


async def export_tenant(session: AsyncSession, settings: Settings, slug: str) -> dict[str, Any]:
    tenant = (await session.execute(select(Tenant).where(Tenant.slug == slug))).scalar_one_or_none()
    if tenant is None:
        raise NotFound(f"No tenant with slug {slug!r}")
    sources = (
        await session.execute(select(DataSource).where(DataSource.tenant_id == tenant.id).order_by(DataSource.name))
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
    }


async def import_tenant(
    session: AsyncSession, settings: Settings, payload: dict[str, Any], slug: str | None = None
) -> dict[str, Any]:
    """Create the tenant, its members and its sources here. All or nothing; never touches an existing tenant."""
    try:
        t = payload["tenant"]
        members, sources = payload["members"], payload["data_sources"]
        target_slug = slug or t["slug"]
        if (await session.execute(select(Tenant.id).where(Tenant.slug == target_slug))).first():
            raise Conflict(f"A tenant with slug {target_slug!r} already exists here; nothing was imported")
        for s in sources:  # validate everything before writing anything
            registry.build(s["connector_type"], s["config"])
    except (KeyError, TypeError):
        raise AppError("The file is not a tenant bundle") from None
    except (ValidationError, ValueError) as exc:
        raise AppError(f"A log source in the bundle is not valid for this version: {str(exc)[:200]}") from None

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
    await session.flush()
    return {
        "slug": target_slug,
        "members_created": created,
        "members_attached": attached,
        "data_sources": len(sources),
        "ingest_keys": new_keys,
    }
