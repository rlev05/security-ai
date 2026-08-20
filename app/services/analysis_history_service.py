from dataclasses import asdict, is_dataclass
from datetime import datetime
from enum import Enum
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.analysis import AnalysisResult
from app.models.analysis_record import AnalysisRecord


VALID_SOURCE_TYPES = {
    "text",
    "file",
}


def _json_safe(
    value: Any,
) -> Any:
    """
    Convert application values into JSON-safe Python values.

    Analysis results contain dataclasses, datetimes and enums,
    which need normalising before they can be stored in a JSON
    database column.
    """

    if value is None:
        return None

    if isinstance(value, datetime):
        return value.isoformat()

    if isinstance(value, Enum):
        return value.value

    if is_dataclass(value):
        return {
            key: _json_safe(item)
            for key, item in asdict(value).items()
        }

    if isinstance(value, dict):
        return {
            str(key): _json_safe(item)
            for key, item in value.items()
        }

    if isinstance(
        value,
        (
            list,
            tuple,
            set,
        ),
    ):
        return [
            _json_safe(item)
            for item in value
        ]

    return value


def _build_persisted_result(
    result: AnalysisResult,
) -> dict[str, Any]:
    """
    Persist the complete structured analysis result.

    Keeping parsed events allows downstream capabilities such as
    ML anomaly detection to operate on stored analyses.
    """

    payload = _json_safe(
        result
    )

    if not isinstance(
        payload,
        dict,
    ):
        raise TypeError(
            "Analysis result must serialise "
            "to a dictionary"
        )

    return payload


def save_analysis_result(
    session: Session,
    result: AnalysisResult,
    *,
    source_type: str,
    source_name: str | None = None,
    owner_user_id: str | None = None,
) -> AnalysisRecord:
    """
    Persist one completed security analysis.
    """

    if source_type not in VALID_SOURCE_TYPES:
        raise ValueError(
            "Source type must be either 'text' or 'file'"
        )

    record = AnalysisRecord(
        owner_user_id=owner_user_id,
        source_type=source_type,
        source_name=source_name,
        total_lines=result.total_lines,
        ignored_lines=result.ignored_lines,
        event_count=len(result.events),
        incident_count=len(result.incidents),
        result_json=_build_persisted_result(
            result
        ),
    )

    try:
        session.add(record)
        session.commit()
        session.refresh(record)
    except Exception:
        session.rollback()
        raise

    return record


def list_analysis_records(
    session: Session,
    *,
    owner_user_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[AnalysisRecord]:
    statement = (
        select(AnalysisRecord)
        .order_by(
            AnalysisRecord.created_at.desc()
        )
        .offset(offset)
        .limit(limit)
    )

    if owner_user_id is not None:
        statement = statement.where(
            AnalysisRecord.owner_user_id
            == owner_user_id
        )

    return list(
        session.scalars(
            statement
        ).all()
    )


def get_analysis_record(
    session: Session,
    analysis_id: str,
    *,
    owner_user_id: str | None = None,
) -> AnalysisRecord | None:
    statement = select(
        AnalysisRecord
    ).where(
        AnalysisRecord.id
        == analysis_id
    )

    if owner_user_id is not None:
        statement = statement.where(
            AnalysisRecord.owner_user_id
            == owner_user_id
        )

    return session.scalar(
        statement
    )