from typing import Annotated, Any

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
    AnomalyDetectionResult,
)
from app.api.auth_dependencies import (
    get_current_user,
)
from app.core.database import (
    get_database_session,
)
from app.models.user import UserRole
from app.models.user_record import (
    UserRecord,
)
from app.services.analysis_history_service import (
    get_analysis_record,
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
    return (
        user.role
        == UserRole.ADMIN.value
    )


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
    """
    Find the first structured event collection in a persisted
    analysis payload.

    Analysis history may contain the analysis result inside a
    wrapper object rather than storing `events` at the root.
    """

    if isinstance(
        value,
        dict,
    ):
        if "events" in value:
            events = (
                _normalise_event_list(
                    value["events"]
                )
            )

            if events:
                return events

        # Check common analysis wrapper fields first.
        for key in (
            "analysis",
            "result",
            "analysis_result",
            "data",
        ):
            if key not in value:
                continue

            events = (
                _find_nested_events(
                    value[key]
                )
            )

            if events:
                return events

        # Fall back to remaining nested dictionaries/lists.
        for key, nested_value in value.items():
            if key in {
                "analysis",
                "result",
                "analysis_result",
                "data",
                "events",
            }:
                continue

            if not isinstance(
                nested_value,
                (
                    dict,
                    list,
                ),
            ):
                continue

            events = (
                _find_nested_events(
                    nested_value
                )
            )

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

            events = (
                _find_nested_events(
                    item
                )
            )

            if events:
                return events

    return []


def _extract_events(
    result_json: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Extract structured security events from a persisted
    analysis result.

    Raw log content is never supplied directly to the ML model.
    """

    return _find_nested_events(
        result_json
    )


@router.get(
    "/{analysis_id}/anomalies",
    response_model=AnomalyDetectionResult,
)
def analyse_persisted_events_for_anomalies(
    analysis_id: str,
    database: DatabaseSession,
    current_user: CurrentUser,
    contamination: Annotated[
        float,
        Query(
            gt=0.0,
            lt=0.5,
            description=(
                "Expected proportion of anomalous events."
            ),
        ),
    ] = DEFAULT_CONTAMINATION,
) -> AnomalyDetectionResult:
    owner_user_id = (
        None
        if _is_admin(
            current_user
        )
        else current_user.id
    )

    analysis = get_analysis_record(
        database,
        analysis_id,
        owner_user_id=owner_user_id,
    )

    if analysis is None:
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail=(
                "Analysis not found"
            ),
        )

    result_json = (
        analysis.result_json
        if isinstance(
            analysis.result_json,
            dict,
        )
        else {}
    )

    events = _extract_events(
        result_json
    )

    return detect_event_anomalies(
        events,
        contamination=contamination,
    )