from sqlalchemy import select
from sqlalchemy.orm import Session
from app.anomaly.schemas import AnomalyDetectionResult
from app.models.anomaly_run_record import AnomalyRunRecord

def save_anomaly_run(
        session: Session,
        *,
        analysis_id: str,
        requested_by_user_id: str | None,
        result: AnomalyDetectionResult,
) -> AnomalyRunRecord:

    """Persist the complete output of one anomaly detection run"""


    record = AnomalyRunRecord(
        analysis_id=analysis_id,
        requested_by_user_id=requested_by_user_id,
        model_name=result.model_name,
        model_version=result.model_version,
        contamination=result.contamination,
        total_events=result.total_events,
        analysed_events=result.analysed_events,
        anomaly_count=result.anomaly_count,
        result_json=result.model_dump(mode="json")
    )

    try:
        session.add(record)
        session.commit()
        session.refresh(record)
    except Exception:
        session.rollback()
        raise
    return record


def get_anomaly_run(
        session: Session,
        run_id: str,
        *,
        analysis_id: str,
        requested_by_user_id: str | None,
) -> AnomalyRunRecord | None:
    statement = select(
        AnomalyRunRecord
    ).where(
        AnomalyRunRecord.id == run_id
    )

    return session.scalar(statement)

def get_latest_anomaly_run(
        session: Session,
        *,
        analysis_id: str,
) -> AnomalyRunRecord | None:
    statement = select(
        AnomalyRunRecord
    ).where(
        AnomalyRunRecord.analysis_id == analysis_id
    ).order_by(AnomalyRunRecord.created_at.desc()).limit(1)


    return session.scalar(statement)

def list_anomaly_run(
        session: Session,
        *,
        analysis_id: str,
        limit: int = 20,
        offset: int = 0,
) -> list[AnomalyRunRecord]:
    statement = (select(
        AnomalyRunRecord
    ).where(
        AnomalyRunRecord.analysis_id == analysis_id).order_by(
        AnomalyRunRecord.created_at.desc()
    )
        .offset(offset)
        .limit(limit)
    )

    return list(session.scalars(statement).all())

def load_anomaly_result(
        record: AnomalyRunRecord
) -> AnomalyDetectionResult:
    """Reconstruct validated API result from JSON"""

    return AnomalyDetectionResult.model_validate(record.result_json)





