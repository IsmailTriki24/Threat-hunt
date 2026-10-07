"""Operational CLI: `python -m app.cli init|seed|create-superadmin`."""

import argparse
import asyncio
import getpass
import logging
import subprocess  # nosec B404
import sys
from collections.abc import Awaitable, Callable
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings, get_settings
from app.core.db import create_engine, create_sessionmaker
from app.core.logging import configure_logging
from app.core.security import hash_password
from app.events.search.opensearch import OpenSearchBackend
from app.main import make_opensearch
from app.users.models import User

log = logging.getLogger("app.cli")
ROOT = Path(__file__).resolve().parent.parent


def migrate() -> None:
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=ROOT, check=True)  # noqa: S603  # nosec B603 - fixed argv, no user input


Action = Callable[[Settings, async_sessionmaker[AsyncSession], OpenSearchBackend], Awaitable[None]]


async def _with_backend(action: Action) -> None:
    settings = get_settings()
    engine = create_engine(settings)
    client = make_opensearch(settings)
    try:
        await action(settings, create_sessionmaker(engine), OpenSearchBackend(client, settings))
    finally:
        await client.close()
        await engine.dispose()


async def _init(settings: Settings, sessionmaker: async_sessionmaker[AsyncSession], backend: OpenSearchBackend) -> None:
    await backend.ensure_schema()
    log.info("opensearch index template ensured")
    from app.mitre.loader import load_builtin

    async with sessionmaker() as session:
        tactics, techniques = await load_builtin(session)
        await session.commit()
    log.info("mitre reference data loaded", extra={"tactics": tactics, "techniques": techniques})
    if settings.seed_demo_data:
        from app.seed.run import seed_demo

        generated = await seed_demo(sessionmaker, backend, settings.seed_password)
        if generated:
            # Printed once to the operator's console; never logged via the structured logger.
            print(f"\n=== Demo users password (generated): {generated} ===\n", flush=True)  # noqa: T201


async def _create_superadmin(sessionmaker: async_sessionmaker[AsyncSession], email: str, password: str) -> None:
    async with sessionmaker() as session:
        if (await session.execute(select(User).where(User.email == email.lower()))).scalar_one_or_none():
            raise SystemExit("user already exists")
        session.add(User(email=email.lower(), password_hash=hash_password(password), is_super_admin=True))
        await session.commit()


async def _mitre_load(sessionmaker: async_sessionmaker[AsyncSession], file: str | None) -> None:
    from app.mitre.loader import import_stix_bundle, load_builtin

    async with sessionmaker() as session:
        if file:
            tactics, techniques = await import_stix_bundle(session, await asyncio.to_thread(Path(file).read_bytes))
        else:
            tactics, techniques = await load_builtin(session)
        await session.commit()
    log.info("mitre reference data loaded", extra={"tactics": tactics, "techniques": techniques})


def main() -> None:
    configure_logging(get_settings().log_level)
    parser = argparse.ArgumentParser(prog="app.cli")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init", help="run migrations, provision OpenSearch, optionally seed demo data")
    sub.add_parser("migrate", help="run database migrations only")
    ml = sub.add_parser("mitre-load", help="load ATT&CK reference data (built-in subset, or a STIX bundle file)")
    ml.add_argument("--file", help="path to an official enterprise-attack STIX bundle (JSON)")
    sa = sub.add_parser("create-superadmin", help="create a platform super admin")
    sa.add_argument("email")
    args = parser.parse_args()

    if args.cmd == "migrate":
        migrate()
    elif args.cmd == "init":
        migrate()
        asyncio.run(_with_backend(_init))
    elif args.cmd == "mitre-load":
        asyncio.run(_with_backend(lambda s, sm, b: _mitre_load(sm, args.file)))
    elif args.cmd == "create-superadmin":
        password = getpass.getpass("Password (min 12 chars): ")
        if len(password) < get_settings().password_min_length:
            raise SystemExit("password too short")
        asyncio.run(_with_backend(lambda s, sm, b: _create_superadmin(sm, args.email, password)))


if __name__ == "__main__":
    main()
