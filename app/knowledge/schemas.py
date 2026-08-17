from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class AttackAnalyticKnowledge(BaseModel):
    model_config = ConfigDict(extra="forbid")

    analytic_id: str
    name: str
    description: str | None = None


class AttackDetectionStrategyKnowledge(BaseModel):
    model_config = ConfigDict(extra="forbid")

    strategy_id: str
    name: str
    description: str | None = None
    source_url: str | None = None

    analytics: list[AttackAnalyticKnowledge] = Field(
        default_factory=list
    )


class AttackMitigationKnowledge(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mitigation_id: str
    name: str
    description: str | None = None
    source_url: str | None = None


class AttackTechniqueKnowledge(BaseModel):
    model_config = ConfigDict(extra="forbid")

    technique_id: str
    name: str
    description: str

    tactics: list[str] = Field(
        default_factory=list
    )

    platforms: list[str] = Field(
        default_factory=list
    )

    source_url: str

    mitigations: list[
        AttackMitigationKnowledge
    ] = Field(
        default_factory=list
    )

    detection_strategies: list[
        AttackDetectionStrategyKnowledge
    ] = Field(
        default_factory=list
    )


class AttackKnowledgeMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attack_version: str
    domain: str
    source_url: str
    generated_at: datetime
    copyright_notice: str


class AttackKnowledgeSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    metadata: AttackKnowledgeMetadata

    techniques: list[
        AttackTechniqueKnowledge
    ] = Field(
        default_factory=list
    )


class AttackGroundingContext(BaseModel):
    """Trusted ATT&CK knowledge supplied to an AI provider."""

    model_config = ConfigDict(extra="forbid")

    attack_version: str

    techniques: list[
        AttackTechniqueKnowledge
    ] = Field(
        default_factory=list
    )

    unresolved_technique_ids: list[str] = Field(
        default_factory=list
    )