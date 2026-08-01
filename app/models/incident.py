from dataclasses import dataclass, field
from app.models.alert import Alert
from app.models.event import SecurityEvent

@dataclass(slots=True)
class Incident:
    events: list[SecurityEvent] = field(default_factory=list)
    alerts: list[Alert] = field(default_factory=list)

