from fastapi import APIRouter

from app.api import health, security_events

api_router = APIRouter()
api_router.include_router(health.router, tags=["health"])
api_router.include_router(security_events.router, prefix="/api/v1")
