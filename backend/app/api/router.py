from fastapi import APIRouter

from app.assets.router import router as assets_router
from app.audit.router import router as audit_router
from app.auth.router import router as auth_router
from app.cases.router import router as cases_router
from app.datasources.router import ingest_router
from app.datasources.router import router as datasources_router
from app.events.router import router as events_router
from app.hunts.router import router as hunts_router
from app.investigations.router import router as timeline_router
from app.tenants.router import router as tenants_router
from app.users.router import router as users_router

api_router = APIRouter(prefix="/api/v1")
for r in (
    auth_router,
    tenants_router,
    users_router,
    events_router,
    hunts_router,
    timeline_router,
    cases_router,
    assets_router,
    audit_router,
    datasources_router,
    ingest_router,
):
    api_router.include_router(r)
