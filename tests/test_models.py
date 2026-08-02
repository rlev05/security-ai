from datetime import datetime
from app.models.alert import Alert, Severity
from app.models.event import SecurityEvent, EventType
from app.models.incident import Incident

def test_incident_contains_event_and_alert():
    raw_log = (
        "2026-08-01T12:00:00 "
        "Failed password for admin from 192.168.1.5"
    )

    event = SecurityEvent(
        timestamp=datetime(2026, 8, 1, 12, 0),
        source_ip="192.168.1.5",
        username="admin",
        event_type=EventType.LOGIN_FAILURE,
        raw_log=raw_log,
    )

    alert = Alert(
        rule_id="AUTH-BRUTE-FORCE-001",
        title="Possible brute-force attack",
        description="Repeated failed login attempts detected.",
        severity=Severity.HIGH,
        confidence=0.95,
        mitre_tactic="Credential Access",
        mitre_technique_id="T1110.001",
        mitre_technique_name="Password Guessing",
        evidence=[raw_log],
    )

    incident = Incident(
        events=[event],
        alerts=[alert],
    )

    assert incident.events == [event]
    assert incident.alerts == [alert]