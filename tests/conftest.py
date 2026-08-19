from collections.abc import Iterator
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base, get_database_session
from app.main import app

# Import all SQLAlchemy models so they are registered with Base.metadata
# before create_all() runs.
from app.models.analysis_record import AnalysisRecord  # noqa: F401
from app.models.investigation_report_record import (
    InvestigationReportRecord,
)  # noqa: F401
from app.models.user_record import UserRecord  # noqa: F401
from app.models.threat_intel_record import ThreatIntelEnrichmentRecord

TEST_ENGINE = create_engine(
    "sqlite://",
    connect_args={
        "check_same_thread": False,
    },
    poolclass=StaticPool,
)


TestingSessionLocal = sessionmaker(
    bind=TEST_ENGINE,
    autoflush=False,
    expire_on_commit=False,
)


@pytest.fixture()
def client() -> Iterator[TestClient]:
    """Return a TestClient backed by an isolated in-memory database."""

    Base.metadata.create_all(
        bind=TEST_ENGINE,
    )

    def override_database_session() -> Iterator[Session]:
        with TestingSessionLocal() as session:
            yield session

    app.dependency_overrides[
        get_database_session
    ] = override_database_session

    test_client = TestClient(app)

    try:
        yield test_client

    finally:
        test_client.close()

        app.dependency_overrides.pop(
            get_database_session,
            None,
        )

        Base.metadata.drop_all(
            bind=TEST_ENGINE,
        )


@pytest.fixture()
def analysis_client(
    client: TestClient,
) -> TestClient:
    """Return a client authenticated as an analysis user."""

    identifier = uuid.uuid4().hex

    registration_payload = {
        "email": (
            f"analysis_{identifier}@example.com"
        ),
        "username": (
            f"analysis_{identifier}"
        ),
        "password": "StrongPassword123!",
    }

    registration_response = client.post(
        "/auth/register",
        json=registration_payload,
    )

    assert (
        registration_response.status_code
        == 201
    )

    token_response = client.post(
        "/auth/token",
        data={
            "username": (
                registration_payload["username"]
            ),
            "password": (
                registration_payload["password"]
            ),
        },
    )

    assert token_response.status_code == 200

    access_token = token_response.json()[
        "access_token"
    ]

    client.headers.update(
        {
            "Authorization": (
                f"Bearer {access_token}"
            )
        }
    )

    return client


@pytest.fixture()
def database_session(
    client: TestClient,
) -> Iterator[Session]:
    """Return a database session using the same DB as the TestClient.

    Depending on `client` ensures the test schema has already been
    created and will be cleaned up after the test.
    """

    session = TestingSessionLocal()

    try:
        yield session

    finally:
        session.rollback()
        session.close()