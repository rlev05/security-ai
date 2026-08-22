from datetime import datetime
from typing import Any
from pydantic import BaseModel, ConfigDict
from app.anomaly.schemas import AnomalyRunResponse

class WorkspaceAnalysis(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )

    id: str
    created_at: datetime

    source_type: str
    source_name: str | None

    total_lines: int
    ignored_lines: int
    event_count: int
    incident_count: int

    result: dict[str, Any]


class WorkspaceInvestigationReport(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )

    id: str
    analysis_id: str

    status: str

    provider: str | None
    model: str | None

    report: dict[str, Any] | None
    grounding: dict[str, Any] | None
    threat_intelligence: dict[str, Any] | None
    anomaly_evidence: dict[str, Any] | None

    error_message: str | None

    created_at: datetime
    completed_at: datetime | None


class AnalysisWorkspaceResponse(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )

    analysis: WorkspaceAnalysis

    latest_anomaly_run: AnomalyRunResponse | None = None

    latest_investigation_report: (
        WorkspaceInvestigationReport | None
    ) = None