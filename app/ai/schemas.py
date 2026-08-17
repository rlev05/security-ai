from enum import StrEnum
from typing import Any
from pydantic import BaseModel, ConfigDict, Field

class InvestigationRiskLevel(StrEnum):
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'
    CRITICAL = 'critical'

class EvidenceBasis(StrEnum):
    OBSERVED_EVIDENCE = "observed_evidence"
    DETECTION_ENGINE = "detection_engine"
    ATTACK_KNOWLEDGE = "attack_knowledge"
    AI_INFERENCE = "ai_inference"

class AnalysisEvidence(BaseModel):
    """Evidence supplied to an AI provider"""

    analysis_id: str
    source_type: str
    source_name: str | None
    total_lines: int
    ignored_lines: int
    result: dict[str, Any]


class KeyFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding: str
    supporting_evidence: list[str]
    confidence: float = Field(ge=0.0, le=1.0)

class EvidenceAssessment(BaseModel):
    """A claim explicitly labelled by its source/basis"""

    model_config = ConfigDict(extra="forbid")

    basis: EvidenceBasis
    statement: str

    technique_ids: list[str] = Field(default_factory=list)




class MitreAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tactic: str
    technique_id: str
    technique_name: str
    explanation: str

class InvestigationStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    priority: int = Field(ge=1, le=10)
    action: str
    rationale: str
    evidence_to_collect: list[str]

class InvestigationReportContent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    executive_summary: str
    attack_narrative: str

    risk_level: InvestigationRiskLevel
    risk_score: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0.0, le=1.0)

    key_findings: list[KeyFinding]
    mitre_assessment: list[MitreAssessment]
    investigation_steps: list[InvestigationStep]

    containment_recommendations: list[str]
    evidence_gaps: list[str]
    limitations: list[str]

    