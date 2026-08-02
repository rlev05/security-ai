from sqlalchemy.orm import Session
from app.api.schemas import AnalysisResponse
from app.models.analysis_record import AnalysisRecord
from app.models.analysis import AnalysisResult


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
) -> AnalysisResult:
    """Persit a completed analysis result as a fixed snap"""
    if source_type not in SUPPORTED_SOURCE_TYPES:
        raise ValueError("Source type must be either 'text' or 'file'")

    response = AnalysisResponse.model_validate(result)
    result_json = response.model_dump(mode="json")

    record = AnalysisRecord(
        source_type=source_type,
        source_name=source_name,
        total_lines=result.total_lines,
        ignored_lines=result.ignored_lines,
        event_count=len(result.events),
        incident_count=len(result.incidents),
        result_json=result_json,
    )

    session.add(record)
    session.commit()
    session.refresh(record)

    return record

def get_analysis_record(
        session: Session,
        analysis_id: str,
) -> AnalysisRecord | None:
    """ Retrieve stored analysis by its id"""

    return session.get(
        AnalysisRecord,
        analysis_id,
    )

