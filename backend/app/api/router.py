from fastapi import APIRouter

from app.auth.router import router as auth_router
from app.events.router import router as events_router
from app.tenants.router import router as tenants_router
from app.users.router import router as users_router

api_router = APIRouter(prefix="/api/v1")
for r in (auth_router, tenants_router, users_router, events_router):
    api_router.include_router(r)
