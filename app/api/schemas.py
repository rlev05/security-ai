from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field
from app.models.alert import Severity
from app.models.event import EventType, SecurityEvent


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