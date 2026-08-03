from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.schemas import AnalysisResponse
from app.models.analysis import AnalysisResult
from app.models.analysis_record import AnalysisRecord


SUPPORTED_SOURCE_TYPES = {
    "text",
    "file",
}


def save_analysis_result(
    session: Session,
    result: AnalysisResult,
    *,
    source_type: str,
    source_name: str | None = None,
) -> AnalysisRecord:
    """Persist a completed analysis as an immutable snapshot."""

    if source_type not in SUPPORTED_SOURCE_TYPES:
        raise ValueError(
            "Source type must be either 'text' or 'file'"
        )

    response = AnalysisResponse.model_validate(result)

    record = AnalysisRecord(
        source_type=source_type,
        source_name=source_name,
        total_lines=result.total_lines,
        ignored_lines=result.ignored_lines,
        event_count=len(result.events),
        incident_count=len(result.incidents),
        result_json=response.model_dump(mode="json"),
    )

    try:
        session.add(record)
        session.commit()
        session.refresh(record)
    except Exception:
        session.rollback()
        raise

    return record


def get_analysis_record(
    session: Session,
    analysis_id: str,
) -> AnalysisRecord | None:
    """Retrieve a stored analysis by its public identifier."""

    return session.get(
        AnalysisRecord,
        analysis_id,
    )


def list_analysis_records(
    session: Session,
    *,
    limit: int = 20,
    offset: int = 0,
) -> list[AnalysisRecord]:
    """Return stored analyses from newest to oldest."""

    if limit < 1:
        raise ValueError("Limit must be at least 1")

    if offset < 0:
        raise ValueError("Offset cannot be negative")

    statement = (
        select(AnalysisRecord)
        .order_by(AnalysisRecord.created_at.desc())
        .offset(offset)
        .limit(limit)
    )

    return list(
        session.scalars(statement)
    )