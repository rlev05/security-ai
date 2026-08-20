from typing import Any
from pydantic import BaseModel, ConfigDict, Field


class EventAnomaly(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )

    event_index: int = Field(
        ge=0,
    )

    anomaly_score: float = Field(
        ge=0.0,
        le=1.0,
    )

    reasons: list[str] = Field(
        default_factory=list,
    )

    features: dict[str, float]

    event: dict[str, Any]


class AnomalyDetectionResult(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )

    model_name: str

    model_version: str

    total_events: int = Field(
        ge=0,
    )

    analysed_events: int = Field(
        ge=0,
    )

    anomaly_count: int = Field(
        ge=0,
    )

    contamination: float = Field(
        gt=0.0,
        lt=0.5,
    )

    feature_names: list[str] = Field(
        default_factory=list,
    )

    anomalies: list[EventAnomaly] = Field(
        default_factory=list,
    )

    skipped_reason: str | None = None