from datetime import datetime
from enum import StrEnum
from pydantic import BaseModel, ConfigDict, Field
from app.ioc.schemas import Indicator

class ThreatIntelLookupStatus(StrEnum):
    ENRICHED = "enriched"
    CACHED = "cached"
    SKIPPED = "skipped"
    FAILED = "failed"

class IPReputation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )

    ip_address: str

    abuse_confidence_score: int = Field(
        ge=0,
        le=100,
    )

    is_public: bool | None = None
    ip_version: int | None = None
    is_whitelisted: bool | None = None

    country_code: str | None = None
    usage_type: str | None = None
    isp: str | None = None
    domain: str | None = None

    hostnames: list[str] = Field(
        default_factory=list,
    )

    is_tor: bool | None = None

    total_reports: int = Field(
        default=0,
        ge=0,
    )

    num_distinct_users: int = Field(
        default=0,
        ge=0,
    )

    last_reported_at: datetime | None = None

class ThreatIntelItem(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )

    indicator: Indicator

    status: ThreatIntelLookupStatus

    provider: str | None = None

    reputation: IPReputation | None = None

    reason: str | None = None

class ThreatIntelContext(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )

    items: list[ThreatIntelItem] = Field(
        default_factory=list,
    )



