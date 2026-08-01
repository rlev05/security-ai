from dataclasses import dataclass
from enum import StrEnum

class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass(slots=True)
class Alert:
    title: str
    description: str
    severity: Severity

