from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.anomaly.schemas import AnomalyRunResponse
from app.api.auth_dependencies import get_current_user
from app.api.workspace_schemas import AnalysisWorkspaceResponse, WorkspaceAnalysis, WorkspaceInvestigationReport
from app.core.database import get_database_session
from app.models.anomaly_run_record import AnomalyRunRecord
from app.models.investigation_report_record import InvestigationReportRecord
from app.models.user import UserRole
from app.models.user_record import UserRecord
from app.services.analysis_history_service import get_analysis_record
from app.services.anomaly_run_service import get_latest_anomaly_run, load_anomaly_result
from app.services.investigation_report_service import get_latest_investigation_report


router = APIRouter(
    prefix="/analysis",
    tags=["Analyst workspace"]
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
        user: UserRecord
) -> bool:
    return user.role == UserRole.ADMIN.value

def _build_anomaly_response(
        record: AnomalyRunRecord,
) -> AnomalyRunResponse:
    return AnomalyRunResponse(
        id=record.id,
        analysis_id=record.analysis_id,
        model_name=record.model_name,
        model_version=record.model_version,
        contamination=record.contamination,
        total_events=record.total_events,
        analysed_events=record.analysed_events,
        anomaly_count=record.anomaly_count,
        created_at=record.created_at,
        result=load_anomaly_result(record),
    )

def _build_report_response(
        record: InvestigationReportRecord
) -> WorkspaceInvestigationReport:
    return WorkspaceInvestigationReport(
        id=record.id,
        analysis_id=record.analysis_id,
        status=record.status,
        provider=record.provider,
        model=record.model,
        report=record.report_json,
        grounding=record.grounding_json,
        threat_intelligence=record.threat_intel_json,
        anomaly_evidence=record.anomaly_json,
        error_message=record.error_message,
        created_at=record.created_at,
        completed_at=record.completed_at,
    )



@router.get(
    "/{analysis_id}/workspace",
    response_model=AnalysisWorkspaceResponse,
)
def get_analysis_workspace(
    analysis_id: str,
    database: DatabaseSession,
    current_user: CurrentUser,
) -> AnalysisWorkspaceResponse:
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
            detail="Analysis not found",
        )

    anomaly_record = (
        get_latest_anomaly_run(
            database,
            analysis_id=analysis.id,
        )
    )

    report_record = (
        get_latest_investigation_report(
            database,
            analysis_id=analysis.id,
        )
    )

    anomaly_response = None

    if anomaly_record is not None:
        anomaly_response = (
            _build_anomaly_response(
                anomaly_record
            )
        )

    report_response = None

    if report_record is not None:
        report_response = (
            _build_report_response(
                report_record
            )
        )

    return AnalysisWorkspaceResponse(
        analysis=WorkspaceAnalysis(
            id=analysis.id,
            created_at=analysis.created_at,
            source_type=analysis.source_type,
            source_name=analysis.source_name,
            total_lines=analysis.total_lines,
            ignored_lines=(
                analysis.ignored_lines
            ),
            event_count=analysis.event_count,
            incident_count=(
                analysis.incident_count
            ),
            result=analysis.result_json,
        ),
        latest_anomaly_run=(
            anomaly_response
        ),
        latest_investigation_report=(
            report_response
        ),
    )

