import pytest
from app.services.analysis_service import analyse_auth_log

def test_analyses_complete_authentication_log() -> None:
    content = """
    2026-08-01T12:00:00 Failed password for admin from 192.168.1.5
    2026-08-01T12:01:00 Failed password for admin from 192.168.1.5
    2026-08-01T12:02:00 Failed password for admin from 192.168.1.5
    2026-08-01T12:03:00 Failed password for admin from 192.168.1.5
    2026-08-01T12:04:00 Failed password for admin from 192.168.1.5
    """

    result = analyse_auth_log(content)

    assert result.total_lines ==5
    assert result.ignored_lines == 0
    assert len(result.events) == 5
    assert len(result.incidents) == 1

    alert = result.incidents[0].alerts[0]

    assert alert.rule_id == "AUTH-BRUTE-FORCE-001"



def test_detects_password_spraying_attack() -> None:
    content = """
        2026-08-01T12:00:00 Failed password for admin from 192.168.1.5
        2026-08-01T12:01:00 Failed password for root from 192.168.1.5
        2026-08-01T12:02:00 Failed password for ryan from 192.168.1.5
        2026-08-01T12:03:00 Failed password for service from 192.168.1.5
        2026-08-01T12:04:00 Failed password for backup from 192.168.1.5
        """

    result = analyse_auth_log(content)
    assert len(result.events) == 5
    assert len(result.incidents) == 1

    alert = result.incidents[0].alerts[0]
    assert alert.rule_id == "AUTH-PASSWORD-SPRAY-001"
    assert alert.mitre_technique_id == "T1110.003"




def test_tracks_ignored_lines() -> None:
    content = """
     2026-08-01T12:00:00 Failed password for admin from 192.168.1.5
    Server started successfully
    Unsupported log entry
    """

    result = analyse_auth_log(content)

    assert result.total_lines == 3
    assert result.ignored_lines == 2
    assert len(result.events) == 1
    assert len(result.incidents) == 0

def test_rejects_empty_content() -> None:
    with pytest.raises(
            ValueError,
            match="Log content cannot be empty",
    ):
        analyse_auth_log("  ")

