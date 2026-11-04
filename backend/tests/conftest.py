"""Pytest configuration and fixtures for Project Sentinel test suite.

Configures an isolated test environment utilizing the dedicated testing database
'sentinel_test_db'. Enforces strict safeguards preventing tests from executing
against development or external databases.
"""

import os
from typing import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.engine.url import make_url
from sqlalchemy.orm import Session, sessionmaker

# Import all models so metadata is fully populated
import app.models  # noqa: F401
from app.core.config import settings
from app.core.database import Base, get_db
from app.main import app

EXPECTED_TEST_DB = "sentinel_test_db"

# Retrieve test database URL from environment or settings
test_db_url = os.getenv("TEST_DATABASE_URL") or getattr(settings, "TEST_DATABASE_URL", None)

if not test_db_url or not str(test_db_url).strip():
    pytest.exit(
        "CRITICAL ERROR: TEST_DATABASE_URL is missing or empty. "
        f"Tests must run exclusively against dedicated test database '{EXPECTED_TEST_DB}'. "
        "Never use development database as a fallback.",
        returncode=1,
    )

parsed_test_url = make_url(test_db_url)
if parsed_test_url.database != EXPECTED_TEST_DB:
    pytest.exit(
        f"CRITICAL SAFETY VIOLATION: TEST_DATABASE_URL target database is '{parsed_test_url.database}', "
        f"expected '{EXPECTED_TEST_DB}'. "
        "Aborting tests immediately to protect development and production databases.",
        returncode=1,
    )

# Create engine for the dedicated test database
test_engine = create_engine(
    test_db_url,
    pool_pre_ping=True,
)

TestingSessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=test_engine,
)


@pytest.fixture(scope="session", autouse=True)
def setup_test_database():
    """Create all schema tables in sentinel_test_db and drop them on teardown."""
    # Secondary safety check
    parsed = make_url(test_db_url)
    assert parsed.database == EXPECTED_TEST_DB, (
        f"Database '{parsed.database}' is not '{EXPECTED_TEST_DB}'"
    )

    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)
    test_engine.dispose()


@pytest.fixture(scope="function")
def db() -> Generator[Session, None, None]:
    """Provide an isolated database session and clean up created test data."""
    connection = test_engine.connect()
    session = TestingSessionLocal(bind=connection)
    try:
        yield session
    finally:
        session.close()
        # Clean up data after each test in reverse topological table order
        with connection.begin():
            for table in reversed(Base.metadata.sorted_tables):
                connection.execute(table.delete())
        connection.close()


@pytest.fixture(scope="function")
def db_session(db: Session) -> Session:
    """Alias fixture for db."""
    return db


@pytest.fixture(scope="function")
def client(db: Session) -> Generator[TestClient, None, None]:
    """Provide a FastAPI TestClient configured with test database dependency overrides."""
    def _override_get_db() -> Generator[Session, None, None]:
        try:
            yield db
        finally:
            pass  # Session cleanup is managed by the db fixture

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
