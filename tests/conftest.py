from collections.abc import Iterator
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool
from app.core.database import Base, get_database_session
from app.main import app
from app.models.analysis_record import AnalysisRecord
from app.models.user_record import UserRecord
import uuid


@pytest.fixture
def client() -> Iterator[TestClient]:
    engine = create_engine(
        "sqlite://",
        connect_args={
            "check_same_thread": False,
        },
        poolclass=StaticPool,
    )

    Base.metadata.create_all(bind=engine)

    testing_session = sessionmaker(
        bind=engine,
        autoflush=False,
        expire_on_commit=False,
    )

    def override_database_session() -> (
        Iterator[Session]
    ):
        with testing_session() as session:
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

        Base.metadata.drop_all(bind=engine)
        engine.dispose()

@pytest.fixture()
def analysis_client(
        client: TestClient,
) -> TestClient:
    """Return a client authenticated as a analysis user"""

    identifier = str(uuid.uuid4())

    registration_payload = {
        "email": f"analysis_{identifier}@example.com",
        "username": f"analysis_{identifier}",
        "password": f"StrongPassword123!"
    }

    registration_response = client.post(
        "/auth/register",
        json=registration_payload,
    )

    assert registration_response.status_code == 201

    token_response = client.post(
        "/auth/token",
        data={
            "username": registration_payload["username"],
            "password": registration_payload["password"],
        },
    )

    assert token_response.status_code == 200

    access_token = token_response.json()["access_token"]

    client.headers.update({"Authorization": f"Bearer {access_token}"})

    return client


