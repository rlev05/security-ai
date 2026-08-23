from typing import (
    Annotated,
    Any,
)

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    status,
)
from sqlalchemy.orm import Session

from app.anomaly.detector import (
    DEFAULT_CONTAMINATION,
    detect_event_anomalies,
)
from app.anomaly.schemas import (
    AnomalyRunResponse,
    AnomalyRunSummary,
)
from app.api.auth_dependencies import (
    get_current_user,
)
from app.core.database import (
    get_database_session,
)
from app.models.anomaly_run_record import (
    AnomalyRunRecord,
)
from app.models.user import UserRole
from app.models.user_record import (
    UserRecord,
)
from app.services.analysis_history_service import (
    get_analysis_record,
)
from app.services.anomaly_run_service import (
    get_latest_anomaly_run,
    list_anomaly_runs,
    load_anomaly_result,
    save_anomaly_run,
)

router = APIRouter(
    prefix="/analysis",
    tags=["ML anomaly detection"],
)


DatabaseSession = Annotated[
    Session,
    Depends(get_database_session),
]

CurrentUser = Annotated[
    UserRecord,
    Depends(get_current_user),
]


def _is_admin(
    user: UserRecord,
) -> bool:
    return user.role == UserRole.ADMIN.value


def _normalise_event_list(
    value: Any,
) -> list[dict[str, Any]]:
    if not isinstance(
        value,
        list,
    ):
        return []

    return [
        event
        for event in value
        if isinstance(
            event,
            dict,
        )
    ]


def _find_nested_events(
    value: Any,
) -> list[dict[str, Any]]:
    if isinstance(
        value,
        dict,
    ):
        if "events" in value:
            events = _normalise_event_list(value["events"])

            if events:
                return events

        for nested_value in value.values():
            if not isinstance(
                nested_value,
                (
                    dict,
                    list,
                ),
            ):
                continue

            events = _find_nested_events(nested_value)

            if events:
                return events

    elif isinstance(
        value,
        list,
    ):
        for item in value:
            if not isinstance(
                item,
                (
                    dict,
                    list,
                ),
            ):
                continue

            events = _find_nested_events(item)

            if events:
                return events

    return []


def _extract_events(
    result_json: dict[str, Any],
) -> list[dict[str, Any]]:
    return _find_nested_events(result_json)


def _get_visible_analysis(
    database: Session,
    *,
    analysis_id: str,
    current_user: UserRecord,
):
    owner_user_id = None if _is_admin(current_user) else current_user.id

    analysis = get_analysis_record(
        database,
        analysis_id,
        owner_user_id=owner_user_id,
    )

    if analysis is None:
        raise HTTPException(
            status_code=(status.HTTP_404_NOT_FOUND),
            detail=("Analysis not found"),
        )

    return analysis


def _build_run_summary(
    record: AnomalyRunRecord,
) -> AnomalyRunSummary:
    return AnomalyRunSummary(
        id=record.id,
        analysis_id=record.analysis_id,
        model_name=record.model_name,
        model_version=record.model_version,
        contamination=record.contamination,
        total_events=record.total_events,
        analysed_events=(record.analysed_events),
        anomaly_count=record.anomaly_count,
        created_at=record.created_at,
    )


def _build_run_response(
    record: AnomalyRunRecord,
) -> AnomalyRunResponse:
    result = load_anomaly_result(record)

    return AnomalyRunResponse(
        **_build_run_summary(record).model_dump(),
        result=result,
    )


@router.post(
    "/{analysis_id}/anomalies",
    response_model=AnomalyRunResponse,
    status_code=status.HTTP_201_CREATED,
)
def run_anomaly_detection(
    analysis_id: str,
    database: DatabaseSession,
    current_user: CurrentUser,
    contamination: Annotated[
        float,
        Query(
            gt=0.0,
            lt=0.5,
            description=("Expected proportion of " "anomalous events."),
        ),
    ] = DEFAULT_CONTAMINATION,
) -> AnomalyRunResponse:
    analysis = _get_visible_analysis(
        database,
        analysis_id=analysis_id,
        current_user=current_user,
    )

    result_json = (
        analysis.result_json
        if isinstance(
            analysis.result_json,
            dict,
        )
        else {}
    )

    events = _extract_events(result_json)

    result = detect_event_anomalies(
        events,
        contamination=contamination,
    )

    record = save_anomaly_run(
        database,
        analysis_id=analysis.id,
        requested_by_user_id=(current_user.id),
        result=result,
    )

    return _build_run_response(record)


@router.get(
    "/{analysis_id}/anomalies",
    response_model=AnomalyRunResponse,
)
def get_latest_anomaly_detection(
    analysis_id: str,
    database: DatabaseSession,
    current_user: CurrentUser,
) -> AnomalyRunResponse:
    analysis = _get_visible_analysis(
        database,
        analysis_id=analysis_id,
        current_user=current_user,
    )

    record = get_latest_anomaly_run(
        database,
        analysis_id=analysis.id,
    )

    if record is None:
        raise HTTPException(
            status_code=(status.HTTP_404_NOT_FOUND),
            detail=("No anomaly-detection run " "exists for this analysis"),
        )

    return _build_run_response(record)


@router.get(
    "/{analysis_id}/anomalies/history",
    response_model=list[AnomalyRunSummary],
)
def get_anomaly_detection_history(
    analysis_id: str,
    database: DatabaseSession,
    current_user: CurrentUser,
    limit: Annotated[
        int,
        Query(
            ge=1,
            le=100,
        ),
    ] = 20,
    offset: Annotated[
        int,
        Query(
            ge=0,
        ),
    ] = 0,
) -> list[AnomalyRunSummary]:
    analysis = _get_visible_analysis(
        database,
        analysis_id=analysis_id,
        current_user=current_user,
    )

    records = list_anomaly_runs(
        database,
        analysis_id=analysis.id,
        limit=limit,
        offset=offset,
    )

    return [_build_run_summary(record) for record in records]
