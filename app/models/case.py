from enum import StrEnum

class CaseSeverit(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class CaseStatus(StrEnum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"

class CaseTimelineEventType(StrEnum):
    CASE_CREATED = "case_created"
    ANALYSIS_LINKED = "analysis_linked"
    NOTE_ADDED = "note_added"
    ASSIGNEE_CHANGED = "assignee_changed"
    STATUS_CHANGED = "status_changed"
    SEVERITY_CHANGED = "severity_changed"

