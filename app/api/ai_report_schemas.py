from datetime import datetime
from pydantic import BaseModel
from app.ai.schemas import InvestigationReportContent
from app.knowledge.schemas import AttackGroundingContext
from app.models.investigation_report_record import InvestigationReportStatus


class InvestigationReportResponse(BaseModel):
    report_id: str
    analysis_id: str
    requested_by_user_id: str | None
    status: InvestigationReportStatus
    provider: str | None
    model: str | None
    report: InvestigationReportContent | None
    grounding: AttackGroundingContext | None
    error_message: str | None
    created_at: datetime
    completed_at: datetime | None

