from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
)
from sqlalchemy.orm import Session

from app.ai.dependencies import get_ai_provider
from app.ai.provider import (
    AIProviderResponseError,
    AIProviderUnavailableError,
    InvestigationReportProvider,
)
from app.ai.schemas import InvestigationReportContent
from app.api.ai_report_schemas import (
    InvestigationReportResponse,
)
from app.api.auth_dependencies import get_current_user
from app.core.database import get_database_session
from app.knowledge.attack_repository import AttackKnowledgeRepository
from app.knowledge.dependencies import get_attack_repository
from app.knowledge.schemas import AttackGroundingContext
from app.models.investigation_report_record import (
    InvestigationReportRecord,
)
from app.models.user import UserRole
from app.models.user_record import UserRecord
from app.services.analysis_history_service import (
    get_analysis_record,
)
from app.services.investigation_report_service import (
    generate_investigation_report,
    get_latest_investigation_report,
)


router = APIRouter(
    prefix="/analysis/history",
    tags=["AI investigation"],
)


DatabaseSession = Annotated[
    Session,
    Depends(get_database_session),
]

CurrentUser = Annotated[
    UserRecord,
    Depends(get_current_user),
]

AIProvider = Annotated[
    InvestigationReportProvider,
    Depends(get_ai_provider),
]

AttackRepository = Annotated[
    AttackKnowledgeRepository,
    Depends(get_attack_repository)
]

def get_owner_filter(
    current_user: UserRecord,
) -> str | None:
    if current_user.role == UserRole.ADMIN.value:
        return None

    return current_user.id


def get_visible_analysis(
    session: Session,
    *,
    analysis_id: str,
    current_user: UserRecord,
):
    analysis = get_analysis_record(
        session,
        analysis_id,
        owner_user_id=get_owner_filter(current_user),
    )

    if analysis is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Analysis record not found",
        )

    return analysis


def build_report_response(
    record: InvestigationReportRecord,
) -> InvestigationReportResponse:
    report = None

    if record.report_json is not None:
        report = InvestigationReportContent.model_validate(
            record.report_json
        )

    grounding = None

    if record.grounding_json is not None:
        grounding = (
            AttackGroundingContext.model_validate(record.grounding_json)
        )

    return InvestigationReportResponse(
        report_id=record.id,
        analysis_id=record.analysis_id,
        requested_by_user_id=record.requested_by_user_id,
        status=record.status,
        provider=record.provider,
        model=record.model,
        report=report,
        grounding=grounding,
        error_message=record.error_message,
        created_at=record.created_at,
        completed_at=record.completed_at,
    )


@router.post(
    "/{analysis_id}/ai-report",
    response_model=InvestigationReportResponse,
    status_code=status.HTTP_201_CREATED,
)
@router.post(
    "/{analysis_id}/ai-report",
    response_model=(
        InvestigationReportResponse
    ),
    status_code=status.HTTP_201_CREATED,
)
def create_ai_investigation_report(
    analysis_id: str,
    session: DatabaseSession,
    current_user: CurrentUser,
    provider: AIProvider,
    repository: AttackRepository,
) -> InvestigationReportResponse:
    analysis = get_visible_analysis(
        session,
        analysis_id=analysis_id,
        current_user=current_user,
    )

    try:
        record = generate_investigation_report(
            session,
            analysis=analysis,
            requested_by_user_id=(
                current_user.id
            ),
            provider=provider,
            repository=repository,
        )
    except AIProviderUnavailableError as exc:
        raise HTTPException(
            status_code=(
                status.HTTP_503_SERVICE_UNAVAILABLE
            ),
            detail=str(exc),
        ) from exc

    except AIProviderResponseError as exc:
        raise HTTPException(
            status_code=(
                status.HTTP_502_BAD_GATEWAY
            ),
            detail=str(exc),
        ) from exc

    return build_report_response(record)


@router.get(
    "/{analysis_id}/ai-report",
    response_model=(
        InvestigationReportResponse
    ),
)
def get_ai_investigation_report(
    analysis_id: str,
    session: DatabaseSession,
    current_user: CurrentUser,
) -> InvestigationReportResponse:
    get_visible_analysis(
        session,
        analysis_id=analysis_id,
        current_user=current_user,
    )

    record = (
        get_latest_investigation_report(
            session,
            analysis_id=analysis_id,
        )
    )

    if record is None:
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail=(
                "No investigation report exists "
                "for this analysis"
            ),
        )

    return build_report_response(record)
