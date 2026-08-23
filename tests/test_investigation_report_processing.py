from sqlalchemy.orm import Session

from app.anomaly.schemas import (
    AnomalyDetectionResult,
    EventAnomaly,
)
from app.models.investigation_report import (
    InvestigationReportStatus,
)
from app.services.analysis_history_service import (
    save_analysis_result,
)
from app.services.analysis_service import (
    analyse_auth_log,
)
from app.services.anomaly_run_service import (
    save_anomaly_run,
)
from app.services.investigation_report_service import (
    create_pending_report,
    process_investigation_report,
)
from tests.fake_ai_provider import (
    FakeInvestigationProvider,
    HallucinatingInvestigationProvider,
)
from tests.fake_attack_knowledge import (
    build_fake_attack_repository,
)
from tests.fake_threat_intel_provider import (
    FakeThreatIntelProvider,
)

AUTH_LOG_CONTENT = """
2026-08-01T12:00:00 Failed password for admin from 192.168.1.5
2026-08-01T12:01:00 Failed password for admin from 192.168.1.5
2026-08-01T12:02:00 Failed password for admin from 192.168.1.5
2026-08-01T12:03:00 Failed password for admin from 192.168.1.5
2026-08-01T12:04:00 Failed password for admin from 192.168.1.5
"""


REQUESTED_BY_USER_ID = "00000000-0000-0000-0000-000000000001"


def build_analysis_and_pending_report(
    session: Session,
):
    result = analyse_auth_log(AUTH_LOG_CONTENT)

    analysis = save_analysis_result(
        session,
        result=result,
        source_type="text",
        source_name=None,
        owner_user_id=None,
    )

    report = create_pending_report(
        session,
        analysis_id=analysis.id,
        requested_by_user_id=(REQUESTED_BY_USER_ID),
    )

    return analysis, report


def build_pending_report(
    session: Session,
):
    _, report = build_analysis_and_pending_report(session)

    return report


def build_anomaly_result() -> AnomalyDetectionResult:
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
                anomaly_score=0.97,
                reasons=[
                    (
                        "Source IP generated a high "
                        "number of authentication "
                        "failures."
                    ),
                    (
                        "Source IP interacted with an "
                        "unusually broad set of "
                        "accounts."
                    ),
                ],
                features={
                    "is_login_failure": 1.0,
                    "ip_failure_count": 8.0,
                    "distinct_users_for_ip": 8.0,
                },
                event={
                    "timestamp": ("2026-08-20T03:00:00+00:00"),
                    "source_ip": ("203.0.113.250"),
                    "username": "target0",
                    "event_type": ("LOGIN_FAILURE"),
                },
            )
        ],
        skipped_reason=None,
    )


def test_worker_processing_completes_report(
    database_session: Session,
) -> None:
    report = build_pending_report(database_session)

    processed = process_investigation_report(
        database_session,
        report_id=report.id,
        provider=FakeInvestigationProvider(),
        repository=build_fake_attack_repository(),
    )

    assert processed is not None

    assert processed.status == InvestigationReportStatus.COMPLETED.value

    assert processed.provider == "fake"

    assert processed.model == "fake-investigator-v1"

    assert processed.report_json is not None
    assert processed.grounding_json is not None

    assert processed.anomaly_json == {
        "run_id": None,
        "created_at": None,
        "result": None,
    }

    assert processed.completed_at is not None
    assert processed.error_message is None


def test_worker_rejects_hallucinated_attack_mapping(
    database_session: Session,
) -> None:
    report = build_pending_report(database_session)

    processed = process_investigation_report(
        database_session,
        report_id=report.id,
        provider=(HallucinatingInvestigationProvider()),
        repository=build_fake_attack_repository(),
    )

    assert processed is not None

    assert processed.status == InvestigationReportStatus.FAILED.value

    assert processed.report_json is None
    assert processed.completed_at is not None

    assert processed.error_message is not None
    assert "T1059" in processed.error_message


def test_completed_report_is_not_processed_twice(
    database_session: Session,
) -> None:
    report = build_pending_report(database_session)

    first = process_investigation_report(
        database_session,
        report_id=report.id,
        provider=FakeInvestigationProvider(),
        repository=build_fake_attack_repository(),
    )

    assert first is not None

    assert first.status == InvestigationReportStatus.COMPLETED.value

    assert first.completed_at is not None

    original_completed_at = first.completed_at

    original_report_json = first.report_json

    original_anomaly_json = first.anomaly_json

    second = process_investigation_report(
        database_session,
        report_id=report.id,
        provider=(HallucinatingInvestigationProvider()),
        repository=build_fake_attack_repository(),
    )

    assert second is not None

    assert second.status == InvestigationReportStatus.COMPLETED.value

    assert second.completed_at == original_completed_at

    assert second.report_json == original_report_json

    assert second.anomaly_json == original_anomaly_json

    assert second.error_message is None


def test_worker_persists_threat_intelligence(
    database_session: Session,
) -> None:
    public_auth_log = """
2026-08-01T12:00:00 Failed password for admin from 8.8.8.8
2026-08-01T12:01:00 Failed password for admin from 8.8.8.8
2026-08-01T12:02:00 Failed password for admin from 8.8.8.8
2026-08-01T12:03:00 Failed password for admin from 8.8.8.8
2026-08-01T12:04:00 Failed password for admin from 8.8.8.8
"""

    result = analyse_auth_log(public_auth_log)

    analysis = save_analysis_result(
        database_session,
        result=result,
        source_type="text",
        source_name=None,
        owner_user_id=None,
    )

    report = create_pending_report(
        database_session,
        analysis_id=analysis.id,
        requested_by_user_id=(REQUESTED_BY_USER_ID),
    )

    threat_provider = FakeThreatIntelProvider()

    processed = process_investigation_report(
        database_session,
        report_id=report.id,
        provider=FakeInvestigationProvider(),
        repository=(build_fake_attack_repository()),
        threat_intel_provider=(threat_provider),
        threat_intel_cache_ttl_hours=24,
    )

    assert processed is not None

    assert processed.status == "completed"

    assert processed.threat_intel_json is not None

    items = processed.threat_intel_json["items"]

    enriched = [item for item in items if item["status"] == "enriched"]

    assert len(enriched) == 1

    assert enriched[0]["indicator"]["value"] == "8.8.8.8"

    assert enriched[0]["reputation"]["abuse_confidence_score"] == 87

    assert threat_provider.call_count == 1


def test_worker_persists_anomaly_evidence(
    database_session: Session,
) -> None:
    analysis, report = build_analysis_and_pending_report(database_session)

    anomaly_run = save_anomaly_run(
        database_session,
        analysis_id=analysis.id,
        requested_by_user_id=(REQUESTED_BY_USER_ID),
        result=build_anomaly_result(),
    )

    processed = process_investigation_report(
        database_session,
        report_id=report.id,
        provider=FakeInvestigationProvider(),
        repository=build_fake_attack_repository(),
    )

    assert processed is not None

    assert processed.status == InvestigationReportStatus.COMPLETED.value

    assert processed.anomaly_json is not None

    assert processed.anomaly_json["run_id"] == anomaly_run.id

    anomaly_result = processed.anomaly_json["result"]

    assert anomaly_result["model_name"] == "IsolationForest"

    assert anomaly_result["model_version"] == "test-version"

    assert anomaly_result["anomaly_count"] == 1

    anomalies = anomaly_result["anomalies"]

    assert len(anomalies) == 1

    assert anomalies[0]["anomaly_score"] == 0.97

    assert anomalies[0]["event"]["source_ip"] == "203.0.113.250"

    assert anomalies[0]["reasons"]


def test_worker_records_absence_of_anomaly_evidence(
    database_session: Session,
) -> None:
    report = build_pending_report(database_session)

    processed = process_investigation_report(
        database_session,
        report_id=report.id,
        provider=FakeInvestigationProvider(),
        repository=build_fake_attack_repository(),
    )

    assert processed is not None

    assert processed.status == InvestigationReportStatus.COMPLETED.value

    assert processed.anomaly_json == {
        "run_id": None,
        "created_at": None,
        "result": None,
    }
