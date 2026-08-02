from dataclasses import dataclass, field
from enum import StrEnum

class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass(slots=True)
class Alert:
    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: float
    mitre_tactic: str
    mitre_technique_id: str
    mitre_technique_name: str
    evidence: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("Confidence must be between 0.0 and 1.0")

