from app.detection.auth_log_parser import parse_auth_log_line
from app.detection.brute_force_detector import detect_brute_force
from app.models.analysis import AnalysisResult
from app.models.event import SecurityEvent


def analyse_auth_log(content: str) -> AnalysisResult:
    """Parse the authentication log and run all the detection rules"""

    if not content.strip():
        raise ValueError("Log content cannot be empty")

    lines = [
        line.strip()
        for line in content.splitlines()
        if line.strip()
    ]

    events: list[SecurityEvent] = []
    ignored_lines = 0

    for line in lines:
        event = parse_auth_log_line(line)

        if event is None:
            ignored_lines += 1
        else:
            events.append(event)

    incidents = detect_brute_force(events)

    return AnalysisResult(
        total_lines=len(lines),
        ignored_lines=ignored_lines,
        events=events,
        incidents=incidents,
    )
