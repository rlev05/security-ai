import re
from datetime import datetime
from ipaddress import ip_address

from app.models.event import EventType, SecurityEvent

ISO_AUTH_LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\S+)\s+"
    r"(?P<result>Failed|Accepted) password for "
    r"(?:(?:invalid user)\s+)?"
    r"(?P<username>\S+) from "
    r"(?P<source_ip>\S+)"
)
OPENSSH_AUTH_LOG_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"sshd\[\d+\]:\s+"
    r"(?P<result>Failed|Accepted)\s+"
    r"(?P<method>password|publickey)\s+for\s+"
    r"(?:(?:invalid user)\s+)?"
    r"(?P<username>\S+)\s+from\s+"
    r"(?P<source_ip>\S+)"
)

MONTH_NUMBERS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}

def create_security_event(
        *,
        timestamp: datetime,
        result: str,
        username: str,
        source_ip: str,
        raw_log: str,
) -> SecurityEvent | None:
    """Validate parsed values and create SecurityEvent object"""

    try:
        ip_address(source_ip)
    except ValueError:
        return None

    event_type = (
        EventType.LOGIN_FAILURE
        if result == "Failed"
        else EventType.LOGIN_SUCCESS
    )

    return SecurityEvent(
        timestamp=timestamp,
        source_ip=source_ip,
        username=username,
        event_type=event_type,
        raw_log=raw_log,
    )

def parse_iso_auth_log(
        line: str,
) -> SecurityEvent | None:
    """ Parse the simplified ISO authentication log"""

    match = ISO_AUTH_LOG_PATTERN.search(line)

    if match is None:
        return None

    try:
        timestamp = datetime.fromisoformat(
            match.group("timestamp")
        )
    except ValueError:
        return None

    return create_security_event(
        timestamp=timestamp,
        result=match.group("result"),
        username=match.group("username"),
        source_ip=match.group("source_ip"),
        raw_log=line,
    )

def parse_openssh_auth_log(
        line: str,
        default_year: int,
) -> SecurityEvent | None:
    """ Parse a standard OpenSSH authentication entry"""

    match = OPENSSH_AUTH_LOG_PATTERN.search(line)

    if match is None:
        return None

    month = MONTH_NUMBERS.get(match.group("month"))

    if month is None:
        return None

    try:
        hour, minute, second = (
            int(value)
            for value in match.group("time").split(":")
        )

        timestamp = datetime(
            year=default_year,
            month=month,
            day=int(match.group("day")),
            hour=hour,
            minute=minute,
            second=second,
        )
    except ValueError:
        return None

    return create_security_event(
        timestamp=timestamp,
        result=match.group("result"),
        username=match.group("username"),
        source_ip=match.group("source_ip"),
        raw_log=line,
    )



def parse_auth_log_line(
        line: str,
        default_year: int | None = None,
) -> SecurityEvent | None:

    """Convert an autheenticated log line into a SecurityEvent object."""
    cleaned_line = line.strip()

    if not cleaned_line:
        return None

    iso_event = parse_iso_auth_log(cleaned_line)

    if iso_event is not None:
        return iso_event

    resolved_year = (
        default_year
        if default_year is not None
        else datetime.now().year
    )

    return parse_openssh_auth_log(
        cleaned_line,
        resolved_year,
    )

