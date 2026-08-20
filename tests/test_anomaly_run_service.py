from datetime import datetime, timezone
from uuid import uuid4
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from app.anomaly.schemas import AnomalyDetectionResult, EventAnomaly
from app.core.database import Base
from app.models.analysis_record import AnalysisRecord
from app.models.anomaly_run_record import AnomalyRunRecord
from app.models.user_record import UserRecord
from app.services.anomaly_run_service import get_anomaly_run, get_latest_anomaly_run, list_anomaly_run, load_anomaly_result, save_anomaly_run

def build_database(
    tmp_path,
) -> sessionmaker[Session]:
    database_path = (
        tmp_path
        / "anomaly-runs.db"
    )

    engine = create_engine(
        (
            "sqlite:///"
            f"{database_path}"
        )
    )

    Base.metadata.create_all(
        engine
    )

    return sessionmaker(
        bind=engine,
        expire_on_commit=False,
    )


def create_user(
    session: Session,
) -> UserRecord:
    user = UserRecord(
        id=str(uuid4()),
        email=(
            f"{uuid4().hex}@example.com"
        ),
        username=(
            f"user_{uuid4().hex[:8]}"
        ),
        password_hash="test-hash",
        role="user",
        is_active=True,
    )

    session.add(user)
    session.commit()

    return user


def create_analysis(
    session: Session,
    *,
    owner_user_id: str,
) -> AnalysisRecord:
    record = AnalysisRecord(
        id=str(uuid4()),
        owner_user_id=owner_user_id,
        source_type="text",
        source_name="auth.log",
        total_lines=25,
        ignored_lines=0,
        event_count=25,
        incident_count=1,
        result_json={
            "events": [],
            "incidents": [],
        },
    )

    session.add(record)
    session.commit()

    return record


def create_result(
    *,
    contamination: float = 0.05,
    anomaly_score: float = 0.91,
) -> AnomalyDetectionResult:
    return AnomalyDetectionResult(
        model_name="IsolationForest",
        model_version="test-version",
        total_events=25,
        analysed_events=25,
        anomaly_count=1,
        contamination=contamination,
        feature_names=[
            "is_login_failure",
            "ip_failure_count",
        ],
        anomalies=[
            EventAnomaly(
                event_index=7,
                anomaly_score=anomaly_score,
                reasons=[
                    (
                        "Source IP generated a high "
                        "number of authentication failures."
                    )
                ],
                features={
                    "is_login_failure": 1.0,
                    "ip_failure_count": 8.0,
                },
                event={
                    "timestamp": (
                        "2026-08-20T03:00:00+00:00"
                    ),
                    "source_ip": (
                        "203.0.113.250"
                    ),
                    "username": "target",
                    "event_type": (
                        "LOGIN_FAILURE"
                    ),
                },
            )
        ],
        skipped_reason=None,
    )


def test_saves_complete_anomaly_run(
    tmp_path,
):
    SessionLocal = build_database(
        tmp_path
    )

    with SessionLocal() as session:
        user = create_user(
            session
        )

        analysis = create_analysis(
            session,
            owner_user_id=user.id,
        )

        result = create_result()

        record = save_anomaly_run(
            session,
            analysis_id=analysis.id,
            requested_by_user_id=user.id,
            result=result,
        )

        assert record.id
        assert (
            record.analysis_id
            == analysis.id
        )
        assert (
            record.requested_by_user_id
            == user.id
        )

        assert (
            record.model_name
            == "IsolationForest"
        )

        assert (
            record.contamination
            == 0.05
        )

        assert (
            record.anomaly_count
            == 1
        )

        assert (
            record.result_json[
                "anomalies"
            ][0]["event_index"]
            == 7
        )

        assert (
            record.result_json[
                "anomalies"
            ][0]["reasons"]
        )


def test_loads_validated_persisted_result(
    tmp_path,
):
    SessionLocal = build_database(
        tmp_path
    )

    with SessionLocal() as session:
        user = create_user(
            session
        )

        analysis = create_analysis(
            session,
            owner_user_id=user.id,
        )

        saved = save_anomaly_run(
            session,
            analysis_id=analysis.id,
            requested_by_user_id=user.id,
            result=create_result(
                anomaly_score=0.87,
            ),
        )

        loaded_record = get_anomaly_run(
            session,
            saved.id,
            analysis_id=analysis.id,
            requested_by_user_id=user.id,
        )

        assert (
            loaded_record
            is not None
        )

        result = load_anomaly_result(
            loaded_record
        )

        assert (
            result.model_name
            == "IsolationForest"
        )

        assert (
            result.anomalies[0]
            .anomaly_score
            == 0.87
        )


def test_returns_latest_and_lists_runs(
    tmp_path,
):
    SessionLocal = build_database(
        tmp_path
    )

    with SessionLocal() as session:
        user = create_user(
            session
        )

        analysis = create_analysis(
            session,
            owner_user_id=user.id,
        )

        first = save_anomaly_run(
            session,
            analysis_id=analysis.id,
            requested_by_user_id=user.id,
            result=create_result(
                contamination=0.05,
            ),
        )

        first.created_at = datetime(
            2026,
            8,
            20,
            10,
            0,
            tzinfo=timezone.utc,
        )

        session.commit()

        second = save_anomaly_run(
            session,
            analysis_id=analysis.id,
            requested_by_user_id=user.id,
            result=create_result(
                contamination=0.10,
            ),
        )

        second.created_at = datetime(
            2026,
            8,
            20,
            11,
            0,
            tzinfo=timezone.utc,
        )

        session.commit()

        latest = (
            get_latest_anomaly_run(
                session,
                analysis_id=(
                    analysis.id
                ),
            )
        )

        assert latest is not None
        assert (
            latest.id
            == second.id
        )

        records = list_anomaly_run(
            session,
            analysis_id=analysis.id,
        )

        assert [
            record.id
            for record in records
        ] == [
            second.id,
            first.id,
        ]

