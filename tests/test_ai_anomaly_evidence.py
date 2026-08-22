from datetime import datetime, timezone
from uuid import uuid4
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from app.ai.schemas import AnomalyEvidenceContext
from app.anomaly.schemas import AnomalyDetectionResult, EventAnomaly
from app.core.database import Base
from app.models.analysis_record import AnalysisRecord
from app.models.anomaly_run_record import AnomalyRunRecord
from app.models.user_record import UserRecord
from app.services.anomaly_run_service import save_anomaly_run
from app.services.investigation_report_service import build_anomaly_evidence_context



def build_database(
    tmp_path,
) -> sessionmaker[Session]:
    database_path = (
        tmp_path
        / "ai-anomaly-evidence.db"
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
            f"ai_ml_{uuid4().hex[:8]}"
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
    analysis = AnalysisRecord(
        id=str(uuid4()),
        owner_user_id=owner_user_id,
        source_type="text",
        source_name="auth.log",
        total_lines=40,
        ignored_lines=0,
        event_count=40,
        incident_count=1,
        result_json={
            "events": [],
            "incidents": [],
        },
    )

    session.add(analysis)
    session.commit()

    return analysis


def create_anomaly_result(
    *,
    score: float = 0.94,
) -> AnomalyDetectionResult:
    return AnomalyDetectionResult(
        model_name="IsolationForest",
        model_version="test-version",
        total_events=40,
        analysed_events=40,
        anomaly_count=1,
        contamination=0.05,
        feature_names=[
            "is_login_failure",
            "ip_failure_count",
            "distinct_users_for_ip",
        ],
        anomalies=[
            EventAnomaly(
                event_index=12,
                anomaly_score=score,
                reasons=[
                    (
                        "Source IP generated a high "
                        "number of authentication failures."
                    ),
                    (
                        "Source IP interacted with an "
                        "unusually broad set of accounts."
                    ),
                ],
                features={
                    "is_login_failure": 1.0,
                    "ip_failure_count": 8.0,
                    "distinct_users_for_ip": 8.0,
                },
                event={
                    "timestamp": (
                        "2026-08-20T03:00:00+00:00"
                    ),
                    "source_ip": (
                        "203.0.113.250"
                    ),
                    "username": "target0",
                    "event_type": (
                        "LOGIN_FAILURE"
                    ),
                },
            )
        ],
        skipped_reason=None,
    )


def test_empty_anomaly_context_when_no_run_exists(
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

        context = (
            build_anomaly_evidence_context(
                session,
                analysis_id=analysis.id,
            )
        )

        assert isinstance(
            context,
            AnomalyEvidenceContext,
        )

        assert context.run_id is None
        assert context.created_at is None
        assert context.result is None


def test_latest_persisted_anomaly_run_becomes_ai_evidence(
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
            result=create_anomaly_result(
                score=0.80,
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
            result=create_anomaly_result(
                score=0.97,
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

        context = (
            build_anomaly_evidence_context(
                session,
                analysis_id=analysis.id,
            )
        )

        assert (
            context.run_id
            == second.id
        )

        assert (
            context.result
            is not None
        )

        assert (
            context.result.model_name
            == "IsolationForest"
        )

        assert (
            context.result.anomaly_count
            == 1
        )

        assert (
            context.result
            .anomalies[0]
            .anomaly_score
            == 0.97
        )

        assert (
            context.result
            .anomalies[0]
            .event["source_ip"]
            == "203.0.113.250"
        )


def test_anomaly_context_serialises_for_ai_provider(
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
            result=create_anomaly_result(),
        )

        context = (
            build_anomaly_evidence_context(
                session,
                analysis_id=analysis.id,
            )
        )

        payload = context.model_dump(
            mode="json"
        )

        assert (
            payload["run_id"]
            == saved.id
        )

        assert (
            payload["result"][
                "model_name"
            ]
            == "IsolationForest"
        )

        assert (
            payload["result"][
                "anomalies"
            ][0]["reasons"]
        )