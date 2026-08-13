from fastapi import FastAPI

from app.api.router import api_router
from app.config import get_settings
from app.logging import setup_logging


def create_app() -> FastAPI:
    setup_logging()
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        debug=settings.debug,
    )
    app.include_router(api_router)

    return app


app = create_app()
