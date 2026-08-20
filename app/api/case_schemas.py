from datetime import datetime
from typing import Any
from pydantic import BaseModel, ConfigDict, Field
from app.models.case import CaseStatus, CaseSeverity

class CaseCreateRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid"
    )

    title: str = Field(
        min_length=1,
        max_length=200,
    )

    description: str | None = Field(
        default=None,
        max_length=10_000,
    )

    severity: CaseSeverity = CaseSeverity.MEDIUM

    assigned_to_user_id: str | None = None


class CaseUpdateRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid"
    )

    assigned_to_user_id: str | None = None

class CaseStatusUpdateRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid"
    )

    status: CaseStatus

class CaseSeverityUpdateRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid"
    )

    severity: CaseSeverity

class CaseAnalysisLinkRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )

    analysis_id: str


class CaseNoteCreateRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )

    content: str = Field(
        min_length=1,
        max_length=20_000,
    )


class CaseResponse(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )

    case_id: str

    title: str
    description: str | None

    severity: CaseSeverity
    status: CaseStatus

    created_by_user_id: str | None
    assigned_to_user_id: str | None

    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None


class CaseAnalysisResponse(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )

    analysis_id: str

    source_type: str
    source_name: str | None

    total_lines: int
    ignored_lines: int

    event_count: int
    incident_count: int

    created_at: datetime


class CaseNoteResponse(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )

    note_id: str

    author_user_id: str | None

    content: str

    created_at: datetime


class CaseTimelineEventResponse(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )

    event_id: str

    event_type: str

    actor_user_id: str | None

    event: dict[str, Any]

    created_at: datetime


class CaseDetailResponse(
    CaseResponse
):
    analyses: list[
        CaseAnalysisResponse
    ] = Field(
        default_factory=list
    )

    notes: list[
        CaseNoteResponse
    ] = Field(
        default_factory=list
    )

    timeline: list[
        CaseTimelineEventResponse
    ] = Field(
        default_factory=list
    )

