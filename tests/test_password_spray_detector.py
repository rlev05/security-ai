from datetime import datetime, timedelta
import pytest
from app.detection.password_spray_detector import detect_password_spraying
from app.models.alert import Severity
from app.models.event import EventType, SecurityEvent


def create_failed_login(
        minute: int,
        username: str,
        source_ip: str = "192.168.1.5",
) -> SecurityEvent:
    raw_log = (
        f"2026-08-02T12:{minute:02d}:00"
        f"Failed password for {username} from {source_ip}"
    )

    return SecurityEvent(
        timestamp=datetime(2026, 8, 2, 12, minute),
        source_ip=source_ip,
        username=username,
        event_type=EventType.LOGIN_FAILURE,
        raw_log=raw_log,
    )


def test_detects_password_spraying_attack() -> None:
    events = [
        create_failed_login(0, "admin"),
        create_failed_login(1, "root"),
        create_failed_login(2, "ryan"),
        create_failed_login(3, "service"),
        create_failed_login(4, "backup"),
    ]

    incidents = detect_password_spraying(events)

    assert len(incidents) == 1

    alert = incidents[0].alerts[0]

    assert alert.rule_id == "AUTH-PASSWORD-SPRAY-001"
    assert alert.severity == Severity.HIGH
    assert alert.confidence == 0.92
    assert alert.mitre_technique_id == "T1110.003"
    assert alert.mitre_technique_name == "Password Spraying"
    assert len(alert.evidence) == 5


def test_does_not_count_duplicate_usernames() -> None:
    events = [
        create_failed_login(0, "admin"),
        create_failed_login(1, "admin"),
        create_failed_login(2, "admin"),
        create_failed_login(3, "admin"),
        create_failed_login(4, "admin"),
    ]

    incidents = detect_password_spraying(events)

    assert incidents == []


def test_does_not_combine_different_ip_addresses() -> None:
    events = [
        create_failed_login(
            0,
            "admin",
            "192.168.1.5",
        ),
        create_failed_login(
            1,
            "root",
            "192.168.1.5",
        ),
        create_failed_login(
            2,
            "ryan",
            "10.0.0.20",
        ),
        create_failed_login(
            3,
            "service",
            "10.0.0.20",
        ),
        create_failed_login(
            4,
            "backup",
            "10.0.0.20",
        ),
    ]

    incidents = detect_password_spraying(events)

    assert incidents == []


def test_rejects_invalid_username_threshold() -> None:
    with pytest.raises(
            ValueError,
        match="Window must be greater than zero"
    ):
        detect_password_spraying(
            [],
            window=timedelta(0),
        )