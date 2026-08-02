from dataclasses import dataclass, field
from app.models.event import SecurityEvent
from app.models.incident import Incident


@dataclass(slots=True)
class AnalysisResult:
    total_lines: int
    ignored_lines: int
    events: list[SecurityEvent] = field(default_factory=list)
    incidents: list[Incident] = field(default_factory=list)
