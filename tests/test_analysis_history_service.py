from collections.abc import Iterator
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool
from app.core.database import Base
from app.services.analysis_history_service import get_analysis_record, save_analysis_result
from app.services.analysis_service import analyse_auth_log


@pytest.fixture
def database_session() -> Iterator[Session]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    Base.metadata.create_all(bind=engine)

    testing_session = sessionmaker(
        bind=engine,
        autoflush=False,
        expire_on_commit=False,
    )

    with testing_session() as session:
        yield session

    Base.metadata.drop_all(bind=engine)
    engine.dispose()

def create_analysis_result():
    content = """
    2026-08-01T12:00:00 Failed password for admin from 192.168.1.5
    2026-08-01T12:01:00 Failed password for admin from 192.168.1.5
    2026-08-01T12:02:00 Failed password for admin from 192.168.1.5
    2026-08-01T12:03:00 Failed password for admin from 192.168.1.5
    2026-08-01T12:04:00 Failed password for admin from 192.168.1.5
    """

    return analyse_auth_log(content)

def test_saves_complete_analysis_snapshot(
        database_session: Session,
) -> None:
    result = create_analysis_result()

    record = save_analysis_result(
        database_session,
        result,
        source_type="file",
        source_name="auth.log",
    )

    assert record.id is not None
    assert record.source_type =="file"
    assert record.source_name == "auth.log"
    assert record.total_lines == 5
    assert record.ignored_lines == 0
    assert record.event_count == 5
    assert record.incident_count == 1

    stored_alert = (
        record.result_json["incidents"][0]["alerts"][0]
    )

    assert (stored_alert["rule_id"] == "AUTH-BRUTE-FORCE-001")

def test_retrieves_analysis_by_identifier(
        database_session: Session,
) -> None:
    result = create_analysis_result()

    saved_record = save_analysis_result(
        database_session,
        result,
        source_type="text",
    )

    retrieved_record = get_analysis_record(
        database_session,
        saved_record.id,
    )

    assert retrieved_record is not None
    assert retrieved_record.id == saved_record.id
    assert retrieved_record.result_json == (saved_record.result_json)


def test_rejects_unsupported_source_type(
        database_session: Session,
) -> None:
    result = create_analysis_result()

    with pytest.raises(
        ValueError,
        match="Source type must be either 'text' or 'file'",
    ):
        save_analysis_result(
            database_session,
            result,
            source_type="unkown",
        )


