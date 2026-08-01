from datetime import datetime, timedelta
import pytest
from app.detection.brute_force_detector import detect_brute_force
from app.models.alert import Severity
from app.models.event import EventType, SecurityEvent


def create_failed_login(
        minute: int,
        source_ip: str = "192.168.1.5",
) -> SecurityEvent:
    return SecurityEvent(
        timestamp=datetime(2026, 8, 1, 12, minute),
        source_ip=source_ip,
        username='admin',
        event_type=EventType.LOGIN_FAILURE,
        raw_log="Failed password for admin from {source_ip}",
    )


def test_detects_brute_force_attack() -> None:
    events = [
        create_failed_login(0),
        create_failed_login(1),
        create_failed_login(2),
        create_failed_login(3),
        create_failed_login(4),

    ]

    incidents = detect_brute_force(events)

    assert len(incidents)==1
    assert len(incidents[0].events)==5
    assert len(incidents[0].alerts)==1
    assert incidents[0].alerts[0].severity == Severity.HIGH



def test_does_not_detect_attack_below_threshold() -> None:
    events = [
        create_failed_login(0),
        create_failed_login(1),
        create_failed_login(2),
    ]

    incidents = detect_brute_force(events)

    assert incidents == []

def test_rejects_invalid_threshold() -> None:
    with pytest.raises(ValueError):
        detect_brute_force([], threshold=0)

def test_rejects_invalid_window() -> None:
    with pytest.raises(ValueError):
        detect_brute_force([], window=timedelta(0))



