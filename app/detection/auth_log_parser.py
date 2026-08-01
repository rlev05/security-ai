import re
from datetime import datetime
from ipaddress import ip_address

from app.models.event import EventType, SecurityEvent

AUTH_LOG_PATTERN = re.compile(
r"^(?P<timestamp>\S+)\s+"
    r"(?P<result>Failed|Accepted) password for "
    r"(?:(?:invalid user)\s+)?"
    r"(?P<username>\S+) from "
    r"(?P<source_ip>\S+)"
)

def parse_auth_log_line(line: str) -> SecurityEvent | None:
    """Convert an autheenticated log line into a SecurityEvent object."""
    cleaned_line = line.strip()
    match = AUTH_LOG_PATTERN.search(cleaned_line)

    if match is None:
        return None

    try:
        timestamp = datetime.fromisoformat(match.group("timestamp"))
        ip_address(match.group("source_ip"))
    except ValueError:
        return None

    event_type = (
        EventType.LOGIN_FAILURE
        if match.group("result") == "Failed"
        else EventType.LOGIN_SUCCESS

    )

    return SecurityEvent(
        timestamp=timestamp,
        source_ip=match.group("source_ip"),
        username=match.group("username"),
        event_type=event_type,
        raw_log=cleaned_line,
    )