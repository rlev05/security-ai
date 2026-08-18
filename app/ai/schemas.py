from enum import StrEnum
from typing import Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
)

from app.knowledge.schemas import (
    AttackGroundingContext,
)


class InvestigationRiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EvidenceBasis(StrEnum):
    OBSERVED_EVIDENCE = "observed_evidence"
    DETECTION_ENGINE = "detection_engine"
    ATTACK_KNOWLEDGE = "attack_knowledge"
    AI_INFERENCE = "ai_inference"


class AnalysisEvidence(BaseModel):
    """Evidence supplied to an AI investigation provider."""

    analysis_id: str
    source_type: str
    source_name: str | None

    total_lines: int
    ignored_lines: int

    result: dict[str, Any]

    attack_context: AttackGroundingContext


class KeyFinding(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )

    finding: str

    supporting_evidence: list[str] = Field(
        default_factory=list,
    )

    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )


class EvidenceAssessment(BaseModel):
    """A report statement labelled by the evidence it is based on."""

    model_config = ConfigDict(
        extra="forbid",
    )

    basis: EvidenceBasis
    statement: str

    technique_ids: list[str] = Field(
        default_factory=list,
    )


class MitreAssessment(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )

    tactic: str
    technique_id: str
    technique_name: str
    explanation: str


class InvestigationStep(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )

    priority: int = Field(
        ge=1,
        le=10,
    )

    action: str
    rationale: str

    evidence_to_collect: list[str] = Field(
        default_factory=list,
    )


class InvestigationReportContent(BaseModel):
    """Structured output required from an AI investigation provider."""

    model_config = ConfigDict(
        extra="forbid",
    )

    executive_summary: str
    attack_narrative: str

    risk_level: InvestigationRiskLevel

    risk_score: int = Field(
        ge=0,
        le=100,
    )

    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )

    key_findings: list[KeyFinding] = Field(
        default_factory=list,
    )

    evidence_assessment: list[
        EvidenceAssessment
    ] = Field(
        default_factory=list,
    )

    mitre_assessment: list[
        MitreAssessment
    ] = Field(
        default_factory=list,
    )

    investigation_steps: list[
        InvestigationStep
    ] = Field(
        default_factory=list,
    )

    containment_recommendations: list[str] = Field(
        default_factory=list,
    )

    evidence_gaps: list[str] = Field(
        default_factory=list,
    )

    limitations: list[str] = Field(
        default_factory=list,
    )