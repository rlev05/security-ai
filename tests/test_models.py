from datetime import datetime
from app.models.alert import Alert, Severity
from app.models.event import SecurityEvent, EventType
from app.models.incident import Incident

def test_incident_contains_event_and_alert():
    event = SecurityEvent(
        timestamp=datetime(2026, 8, 1, 12, 0),
        source_ip="192.168.1.5",
        username='admin',
        event_type=EventType.LOGIN_FAILURE,
        raw_log="Failed password for admin from 192.168.1.5"
    )

    alert = Alert(
        title="Possible brute-force attach",
        description="Repeated failed login attempts detected",
        severity=Severity.HIGH,
    )

    incident = Incident(
        events=[event],
        alerts=[alert],
    )

    assert incident.events == [event]
    assert incident.alerts == [alert]