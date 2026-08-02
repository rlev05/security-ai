from app.services.analysis_service import analyse_auth_log

def test_analysis_detects_brute_force_in_openssh_logs() -> None:
    content = """
    Aug  2 12:00:00 server sshd[1001]: Failed password for admin from 192.168.1.5 port 22 ssh2
    Aug  2 12:01:00 server sshd[1002]: Failed password for admin from 192.168.1.5 port 22 ssh2
    Aug  2 12:02:00 server sshd[1003]: Failed password for admin from 192.168.1.5 port 22 ssh2
    Aug  2 12:03:00 server sshd[1004]: Failed password for admin from 192.168.1.5 port 22 ssh2
    Aug  2 12:04:00 server sshd[1005]: Failed password for admin from 192.168.1.5 port 22 ssh2
    """

    result = analyse_auth_log(
        content, default_year=2026
    )

    assert result.total_lines ==5
    assert result.ignored_lines == 0
    assert len(result.events) ==5
    assert len(result.incidents) ==1
    assert (
        result.incidents[0].alerts[0].rule_id
        == "AUTH-BRUTE-FORCE-001"
    )


