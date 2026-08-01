from app.detection.auth_log_parser import parse_auth_log_line
from app.models.event import EventType, SecurityEvent


def test_parses_failed_login() -> None:
    line = ("2026-08-01T12:00:00 "
            "Failed password for admin from 192.168.1.5"
    )

    event = parse_auth_log_line(line)

    assert event is not None
    assert event.username == "admin"
    assert event.source_ip == "192.168.1.5"
    assert event.event_type == EventType.LOGIN_FAILURE


def test_parses_successful_login() -> None:
    line = ("2026-08-01T12:05:00 "
           "Accepted password for ryan from 192.168.1.10"
            )

    event = parse_auth_log_line(line)

    assert event is not None
    assert event.username == "ryan"
    assert event.source_ip == "192.168.1.10"
    assert event.event_type == EventType.LOGIN_SUCCESS



def test_parses_invalid_user_login() -> None:
    line = (
        "2026-08-01T12:00:00 "
        "Failed password for invalid user test from 10.0.0.25 "
    )
    event = parse_auth_log_line(line)

    assert event is not None
    assert event.username == "test"
    assert event.event_type == EventType.LOGIN_FAILURE

def test_rejects_invalid_ip_addresses() -> None:
    line = (
        "2026-08-01T12:00:00 "
        "Failed password for admin from not an IP"
    )
    assert parse_auth_log_line(line) is None

def test_ignores_unknown_log_line() -> None:
    assert parse_auth_log_line("Server started successfully") is None



