import pytest_asyncio

from app.mitre.loader import load_builtin


@pytest_asyncio.fixture(scope="session")
async def mitre_loaded(app):
    async with app.state.sessionmaker() as s:
        await load_builtin(s)
        await s.commit()
