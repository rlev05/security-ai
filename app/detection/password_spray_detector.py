from collections import defaultdict
from datetime import timedelta

from app.models.alert import Alert, Severity
from app.models.event import EventType, SecurityEvent
from app.models.incident import Incident


def detect_password_spraying(
    events: list[SecurityEvent],
    username_threshold: int = 5,
    window: timedelta = timedelta(minutes=10),
) -> list[Incident]:
    """
    Detect failed login attempts against multiple distinct accounts
    from the same IP address within a specified time window.
    """

    if username_threshold < 2:
        raise ValueError(
            "Username threshold must be at least 2"
        )

    if window <= timedelta(0):
        raise ValueError(
            "Window must be greater than zero"
        )

    failures_by_ip: dict[
        str,
        list[SecurityEvent],
    ] = defaultdict(list)

    for event in events:
        if event.event_type == EventType.LOGIN_FAILURE:
            failures_by_ip[event.source_ip].append(event)

    incidents: list[Incident] = []

    for source_ip, failed_events in failures_by_ip.items():
        ordered_events = sorted(
            failed_events,
            key=lambda event: event.timestamp,
        )

        left = 0

        for right, current_event in enumerate(ordered_events):
            while (
                current_event.timestamp
                - ordered_events[left].timestamp
                > window
            ):
                left += 1

            window_events = ordered_events[left:right + 1]

            events_by_username: dict[str, SecurityEvent] = {}

            for event in window_events:
                events_by_username.setdefault(
                    event.username,
                    event,
                )

            # Trigger when the threshold is reached or exceeded.
            if len(events_by_username) < username_threshold:
                continue

            matching_events = list(
                events_by_username.values()
            )

            window_minutes = int(
                window.total_seconds() // 60
            )

            alert = Alert(
                rule_id="AUTH-PASSWORD-SPRAY-001",
                title="Possible password-spraying attack",
                description=(
                    f"Failed login attempts targeted "
                    f"{len(matching_events)} distinct accounts "
                    f"from {source_ip} within "
                    f"{window_minutes} minutes."
                ),
                severity=Severity.HIGH,
                confidence=0.92,
                mitre_tactic="Credential Access",
                mitre_technique_id="T1110.003",
                mitre_technique_name="Password Spraying",
                evidence=[
                    event.raw_log
                    for event in matching_events
                ],
            )

            incidents.append(
                Incident(
                    events=matching_events.copy(),
                    alerts=[alert],
                )
            )

            break

    return incidents