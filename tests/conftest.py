import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.ingestion import models  # noqa: F401 -- registers SecurityEvent on Base.metadata
from app.main import create_app

TEST_DATABASE_URL = "sqlite://"


@pytest.fixture(scope="session")
def test_engine():
    engine = create_engine(
        TEST_DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    yield engine
    engine.dispose()


@pytest.fixture(scope="session")
def TestingSessionLocal(test_engine):
    return sessionmaker(bind=test_engine, autoflush=False, autocommit=False, future=True)


@pytest.fixture
def db_schema(test_engine):
    Base.metadata.create_all(bind=test_engine)
    try:
        yield
    finally:
        Base.metadata.drop_all(bind=test_engine)


@pytest.fixture
def db_session(db_schema, TestingSessionLocal):
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client(db_schema, TestingSessionLocal):
    app = create_app()

    def override_get_db():
        session = TestingSessionLocal()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
