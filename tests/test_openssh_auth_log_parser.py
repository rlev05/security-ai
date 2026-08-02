from datetime import datetime
from sys import deactivate_stack_trampoline

from app.detection.auth_log_parser import parse_auth_log_line
from app.models.event import EventType

def test_parses_openssh_failed_password() -> None:
    line = (
        "Aug  2 12:30:15 server sshd[1234]: "
        "Failed password for admin from "
        "192.168.1.5 port 22 ssh2"
    )

    event = parse_auth_log_line(
        line,
        default_year=2026,
    )

    assert event is not None
    assert event.timestamp == datetime(
        2026,
        8,
        2,
        12,
        30,
        15
    )

    assert event.source_ip == "192.168.1.5"
    assert event.username == "admin"
    assert event.event_type == EventType.LOGIN_FAILURE


def test_parses_openssh_invalid_user() -> None:
    line = (
        "Aug  2 12:31:00 server sshd[1235]: "
        "Failed password for invalid user backup "
        "from 192.168.1.6 port 22 ssh2"
    )

    event = parse_auth_log_line(
        line,
        default_year=2026,
    )

    assert event is not None
    assert event.username == "backup"
    assert event.event_type == EventType.LOGIN_FAILURE


def test_parses_openssh_successful_password() -> None:
    line = (
        "Aug  2 12:32:00 server sshd[1236]: "
        "Accepted password for ryan from "
        "10.0.0.20 port 51234 ssh2"
    )

    event = parse_auth_log_line(
        line,
        default_year=2026,
    )

    assert event is not None
    assert event.username == "ryan"
    assert event.source_ip == "10.0.0.20"
    assert event.event_type == EventType.LOGIN_SUCCESS


def test_parses_openssh_successful_public_key() -> None:
    line = (
        "Aug  2 12:33:00 server sshd[1237]: "
        "Accepted publickey for deploy from "
        "10.0.0.21 port 51235 ssh2"
    )

    event = parse_auth_log_line(
        line,
        default_year=2026,
    )

    assert event is not None
    assert event.username == "deploy"
    assert event.event_type == EventType.LOGIN_SUCCESS


def test_rejects_openssh_log_with_invalid_ip() -> None:
    line = (
        "Aug  2 12:34:00 server sshd[1238]: "
        "Failed password for admin from"
        "invalid-address port 22 ssh2"
    )

    event = parse_auth_log_line(
        line, default_year=2026,
    )

    assert event is None







