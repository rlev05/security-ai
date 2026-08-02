from datetime import datetime, timedelta
import pytest
from app.detection.credential_compromise_detector import detect_success_after_failures
from app.models.alert import Severity
from app.models.event import EventType, SecurityEvent

BASE_TIME = datetime(2026, 8, 2, 12, 0)

def create_authentication_event(
        minute_offset: int,
        event_type: EventType,
        username: str = "admin",
        source_ip: str = "192.168.1.5",
) -> SecurityEvent:
    timestamp = BASE_TIME + timedelta(minutes=minute_offset)

    result = (
        "Failed"
        if event_type == EventType.LOGIN_FAILURE
        else "Accepted"
    )

    raw_log = (
        f"{timestamp.isoformat()}"
        f"{result} password for {username}"
        f"from {source_ip}"
    )

    return SecurityEvent(
        timestamp=timestamp,
        source_ip=source_ip,
        username=username,
        event_type=event_type,
        raw_log=raw_log,
    )


def test_detects_success_after_repeated_failures() -> None:
    events = [
        create_authentication_event(
            minute,
            EventType.LOGIN_FAILURE,
        )
        for minute in range(5)
    ]

    events.append(
        create_authentication_event(
            5,
            EventType.LOGIN_SUCCESS,
        )
    )

    incidents = detect_success_after_failures(events)

    assert len(incidents) == 1

    incident = incidents[0]
    alert = incident.alerts[0]

    assert len(incident.events) == 6
    assert alert.rule_id == (
        "AUTH-SUCCESS-AFTER-FAILURES-001"
    )
    assert alert.severity == Severity.CRITICAL
    assert alert.confidence == 0.98
    assert alert.mitre_technique_id == "T1078"
    assert alert.mitre_technique_name == "Valid Accounts"
    assert len(alert.evidence) == 6

def test_ignores_success_below_failure_threshold() -> None:
    events = [
        create_authentication_event(
            minute,
            EventType.LOGIN_FAILURE,
        )
        for minute in range(4)
    ]

    events.append(
        create_authentication_event(
            5,
            EventType.LOGIN_SUCCESS,
        )
    )

    incidents = detect_success_after_failures(events)

    assert incidents == []


def test_does_not_combine_different_source_addresses() -> None:
    events = [
        create_authentication_event(
            minute,
            event_type=EventType.LOGIN_FAILURE,
            source_ip="192.168.1.5",
        )
        for minute in range(5)
    ]

    events.append(
        create_authentication_event(
            5,
            EventType.LOGIN_SUCCESS,
            source_ip="10.0.0.20",
        )
    )

    incidents = detect_success_after_failures(events)

    assert incidents == []


def test_ignores_success_outside_follow_up_window() -> None:
    events = [
        create_authentication_event(
            minute, EventType.LOGIN_FAILURE,
        )
        for minute in range(5)
    ]

    events.append(
        create_authentication_event(
            20,
            EventType.LOGIN_SUCCESS
        )
    )

    incidents = detect_success_after_failures(events)
    assert incidents == []

@pytest.mark.parametrize(
    (
        "failure_threshold",
        "failure_window",
        "success_window",
        "expected_message",
    ),
    [
        (
            0,
            timedelta(minutes=5),
            timedelta(minutes=10),
            "Failure threshold must be at least 1",
        ),
        (
            5,
            timedelta(0),
            timedelta(minutes=10),
            "Failure window must be greater than zero",
        ),
        (
            5,
            timedelta(minutes=5),
            timedelta(0),
            "Success window must be greater than zero",
        ),
    ],
)
def test_rejects_invalid_configuration(
    failure_threshold: int,
    failure_window: timedelta,
    success_window: timedelta,
    expected_message: str,
) -> None:
    with pytest.raises(
        ValueError,
        match=expected_message,
    ):
        detect_success_after_failures(
            [],
            failure_threshold=failure_threshold,
            failure_window=failure_window,
            success_window=success_window,
        )


