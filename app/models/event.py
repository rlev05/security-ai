from dataclasses import dataclass
from datetime import datetime
from enum import Enum

class EventType(Enum):
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    UNKNOWN = "unknown"

@dataclass(slots=True)
class SecurityEvent:
    timestamp: datetime
    source_ip: str
    username: str
    event_type: EventType
    raw_log: str


