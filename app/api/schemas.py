from datetime import datetime
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field
from app.models.alert import Severity
from app.models.event import EventType

class LogAnalysisRequest(BaseModel):
    content: str = Field(
        min_length=1,
        max_length=1_000_000,
    )


class SecurityEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    timestamp: datetime
    source_ip: str
    username: str
    event_type: EventType
    raw_log: str


class AlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )
    mitre_tactic: str
    mitre_technique_id: str
    mitre_technique_name: str
    evidence: list[str]


class IncidentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    events: list[SecurityEventResponse]
    alerts: list[AlertResponse]


class AnalysisResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    total_lines: int
    ignored_lines: int
    events: list[SecurityEventResponse]
    incidents: list[IncidentResponse]

class AnalysisSubmissionResponse(AnalysisResponse):
    analysis_id: str
    created_at: datetime
    source_type: Literal["text", "file"]
    source_name: str | None

class AnalysisHistorySummaryResponse(BaseModel):
    analysis_id: str
    created_at: datetime
    source_type: Literal["text", "file"]
    source_name: str | None
    total_lines: int
    ignored_lines: int
    event_count: int
    incident_count: int

class AnalysisHistoryResponse(
    AnalysisHistorySummaryResponse
):
    result: AnalysisResponse




