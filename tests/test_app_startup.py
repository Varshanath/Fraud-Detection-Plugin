from fastapi import FastAPI

from app.main import app, create_app


def test_create_app_returns_fastapi_instance():
    instance = create_app()
    assert isinstance(instance, FastAPI)


def test_module_level_app_is_fastapi_instance():
    assert isinstance(app, FastAPI)


def test_health_route_registered():
    schema = app.openapi()
    assert "/health" in schema["paths"]


def test_database_module_imports_without_live_postgres():
    from app import database

    assert database.engine is not None
    assert database.SessionLocal is not None
    assert database.Base is not None
