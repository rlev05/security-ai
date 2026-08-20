from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.api.auth_dependencies import get_current_user
from app.api.case_schemas import CaseAnalysisLinkRequest, CaseAnalysisResponse, CaseAssignmentRequest, CaseCreateRequest, CaseDetailResponse, CaseNoteCreateRequest, CaseNoteResponse, CaseResponse, CaseSeverityUpdateRequest, CaseStatusUpdateRequest, CaseTimelineEventResponse
from app.core.database import get_database_session
from app.models.case import CaseSeverity, CaseStatus
from app.models.case_record import CaseRecord
from app.models.user import UserRole
from app.models.user_record import UserRecord
from app.services.analysis_history_service import get_analysis_record
from app.services.case_service import add_case_note, assign_case, create_case, get_active_user, get_case, get_case_analyses, link_analysis_to_case, list_case_notes, list_case_timeline, list_cases, set_case_severity, set_case_status


router = APIRouter(
    prefix="/cases",
    tags=["Analyst cases"],
)

DatabaseSession = Annotated[
    Session,
    Depends(get_database_session),
]

CurrentUser = Annotated[
    UserRecord,
    Depends(get_current_user),
]

def is_admin(
    current_user: UserRecord,
) -> bool:
    """Return whether the authenticated user is an administrator."""

    return (
        current_user.role
        == UserRole.ADMIN.value
    )


def require_visible_case(
    session: Session,
    *,
    case_id: str,
    current_user: UserRecord,
) -> CaseRecord:
    """Return a case the current user is allowed to access."""

    record = get_case(
        session,
        case_id=case_id,
        user_id=current_user.id,
        is_admin=is_admin(
            current_user
        ),
    )

    if record is None:
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail="Case not found",
        )

    return record


def build_case_response(
    record: CaseRecord,
) -> CaseResponse:
    """Convert a persisted case into its public API representation."""

    return CaseResponse(
        case_id=record.id,
        title=record.title,
        description=record.description,
        severity=CaseSeverity(
            record.severity
        ),
        status=CaseStatus(
            record.status
        ),
        created_by_user_id=(
            record.created_by_user_id
        ),
        assigned_to_user_id=(
            record.assigned_to_user_id
        ),
        created_at=record.created_at,
        updated_at=record.updated_at,
        closed_at=record.closed_at,
    )


def build_case_detail_response(
    session: Session,
    record: CaseRecord,
) -> CaseDetailResponse:
    """Build the full analyst investigation view for a case."""

    analyses = get_case_analyses(
        session,
        case_id=record.id,
    )

    notes = list_case_notes(
        session,
        case_id=record.id,
    )

    timeline = list_case_timeline(
        session,
        case_id=record.id,
    )

    base = build_case_response(
        record
    )

    return CaseDetailResponse(
        **base.model_dump(),
        analyses=[
            CaseAnalysisResponse(
                analysis_id=analysis.id,
                source_type=(
                    analysis.source_type
                ),
                source_name=(
                    analysis.source_name
                ),
                total_lines=(
                    analysis.total_lines
                ),
                ignored_lines=(
                    analysis.ignored_lines
                ),
                event_count=(
                    analysis.event_count
                ),
                incident_count=(
                    analysis.incident_count
                ),
                created_at=(
                    analysis.created_at
                ),
            )
            for analysis in analyses
        ],
        notes=[
            CaseNoteResponse(
                note_id=note.id,
                author_user_id=(
                    note.author_user_id
                ),
                content=note.content,
                created_at=(
                    note.created_at
                ),
            )
            for note in notes
        ],
        timeline=[
            CaseTimelineEventResponse(
                event_id=event.id,
                event_type=(
                    event.event_type
                ),
                actor_user_id=(
                    event.actor_user_id
                ),
                event=event.event_json,
                created_at=(
                    event.created_at
                ),
            )
            for event in timeline
        ],
    )


@router.post(
    "",
    response_model=CaseResponse,
    status_code=(
        status.HTTP_201_CREATED
    ),
)
def create_analyst_case(
    request: CaseCreateRequest,
    session: DatabaseSession,
    current_user: CurrentUser,
) -> CaseResponse:
    """Create a new analyst investigation case."""

    if (
        request.assigned_to_user_id
        is not None
    ):
        assignee = get_active_user(
            session,
            user_id=(
                request.assigned_to_user_id
            ),
        )

        if assignee is None:
            raise HTTPException(
                status_code=(
                    status.HTTP_400_BAD_REQUEST
                ),
                detail=(
                    "Assigned user does not exist "
                    "or is inactive"
                ),
            )

    record = create_case(
        session,
        title=request.title,
        description=request.description,
        severity=request.severity,
        created_by_user_id=(
            current_user.id
        ),
        assigned_to_user_id=(
            request.assigned_to_user_id
        ),
    )

    return build_case_response(
        record
    )


@router.get(
    "",
    response_model=list[CaseResponse],
)
def get_cases(
    session: DatabaseSession,
    current_user: CurrentUser,
) -> list[CaseResponse]:
    """List all cases visible to the authenticated user."""

    records = list_cases(
        session,
        user_id=current_user.id,
        is_admin=is_admin(
            current_user
        ),
    )

    return [
        build_case_response(
            record
        )
        for record in records
    ]


@router.get(
    "/{case_id}",
    response_model=CaseDetailResponse,
)
def get_case_detail(
    case_id: str,
    session: DatabaseSession,
    current_user: CurrentUser,
) -> CaseDetailResponse:
    """Return a complete analyst investigation case."""

    record = require_visible_case(
        session,
        case_id=case_id,
        current_user=current_user,
    )

    return build_case_detail_response(
        session,
        record,
    )


@router.post(
    "/{case_id}/analyses",
    response_model=CaseDetailResponse,
)
def link_analysis(
    case_id: str,
    request: CaseAnalysisLinkRequest,
    session: DatabaseSession,
    current_user: CurrentUser,
) -> CaseDetailResponse:
    """Link a visible security analysis to an investigation case."""

    case_record = require_visible_case(
        session,
        case_id=case_id,
        current_user=current_user,
    )

    owner_user_id = (
        None
        if is_admin(current_user)
        else current_user.id
    )

    analysis = get_analysis_record(
        session,
        request.analysis_id,
        owner_user_id=owner_user_id,
    )

    if analysis is None:
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail=(
                "Analysis record not found"
            ),
        )

    link = link_analysis_to_case(
        session,
        case_record=case_record,
        analysis=analysis,
        actor_user_id=(
            current_user.id
        ),
    )

    if link is None:
        raise HTTPException(
            status_code=(
                status.HTTP_409_CONFLICT
            ),
            detail=(
                "Analysis is already linked "
                "to this case"
            ),
        )

    return build_case_detail_response(
        session,
        case_record,
    )


@router.post(
    "/{case_id}/notes",
    response_model=CaseNoteResponse,
    status_code=(
        status.HTTP_201_CREATED
    ),
)
def create_case_note(
    case_id: str,
    request: CaseNoteCreateRequest,
    session: DatabaseSession,
    current_user: CurrentUser,
) -> CaseNoteResponse:
    """Append a human analyst note to a case."""

    case_record = require_visible_case(
        session,
        case_id=case_id,
        current_user=current_user,
    )

    note = add_case_note(
        session,
        case_record=case_record,
        author_user_id=(
            current_user.id
        ),
        content=request.content,
    )

    return CaseNoteResponse(
        note_id=note.id,
        author_user_id=(
            note.author_user_id
        ),
        content=note.content,
        created_at=note.created_at,
    )


@router.patch(
    "/{case_id}/assignment",
    response_model=CaseResponse,
)
def update_case_assignment(
    case_id: str,
    request: CaseAssignmentRequest,
    session: DatabaseSession,
    current_user: CurrentUser,
) -> CaseResponse:
    """Assign or unassign an analyst from a case."""

    case_record = require_visible_case(
        session,
        case_id=case_id,
        current_user=current_user,
    )

    if (
        request.assigned_to_user_id
        is not None
    ):
        assignee = get_active_user(
            session,
            user_id=(
                request.assigned_to_user_id
            ),
        )

        if assignee is None:
            raise HTTPException(
                status_code=(
                    status.HTTP_400_BAD_REQUEST
                ),
                detail=(
                    "Assigned user does not exist "
                    "or is inactive"
                ),
            )

    updated = assign_case(
        session,
        case_record=case_record,
        actor_user_id=(
            current_user.id
        ),
        assigned_to_user_id=(
            request.assigned_to_user_id
        ),
    )

    return build_case_response(
        updated
    )


@router.patch(
    "/{case_id}/status",
    response_model=CaseResponse,
)
def update_case_status(
    case_id: str,
    request: CaseStatusUpdateRequest,
    session: DatabaseSession,
    current_user: CurrentUser,
) -> CaseResponse:
    """Change the investigation workflow state."""

    case_record = require_visible_case(
        session,
        case_id=case_id,
        current_user=current_user,
    )

    updated = set_case_status(
        session,
        case_record=case_record,
        actor_user_id=(
            current_user.id
        ),
        new_status=request.status,
    )

    return build_case_response(
        updated
    )


@router.patch(
    "/{case_id}/severity",
    response_model=CaseResponse,
)
def update_case_severity(
    case_id: str,
    request: CaseSeverityUpdateRequest,
    session: DatabaseSession,
    current_user: CurrentUser,
) -> CaseResponse:
    """Change the analyst-assigned severity of a case."""

    case_record = require_visible_case(
        session,
        case_id=case_id,
        current_user=current_user,
    )

    updated = set_case_severity(
        session,
        case_record=case_record,
        actor_user_id=(
            current_user.id
        ),
        new_severity=request.severity,
    )

    return build_case_response(
        updated
    )