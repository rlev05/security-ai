from collections.abc import Iterator
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool
from app.core.database import Base, get_database_session
from app.main import app
from app.models.analysis_record import AnalysisRecord

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



