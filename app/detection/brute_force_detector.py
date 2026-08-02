from collections import defaultdict
from datetime import timedelta

from app.api.schemas import SecurityEventResponse
from app.models.alert import Alert, Severity
from app.models.event import EventType, SecurityEvent
from app.models.incident import Incident


def detect_brute_force(
        events: list[SecurityEvent],
        threshold: int = 5,
        window: timedelta = timedelta(minutes=5),
) -> list[Incident]:
    """Detect repeated failed logins from the same IP address within a specified time window"""

    if threshold < 1:
        raise ValueError("threshold must be greater than 0")

    if window <= timedelta(0):
        raise ValueError("window must be greater than 0")

    failures_by_target: dict[
        tuple[str, str],
        list[SecurityEvent],
    ] = defaultdict(list)

    for event in events:
        if event.event_type == EventType.LOGIN_FAILURE:
            target = (event.source_ip, event.username)
            failures_by_target[target].append(event)

    incidents: list[Incident] = []

    for (
        source_ip,
        username,
    ), failed_events in failures_by_target.items():
        ordered_events = sorted(
            failed_events,
            key=lambda event: event.timestamp,
        )

        left = 0

        for right, current_event in enumerate(ordered_events):
            while current_event.timestamp - ordered_events[left].timestamp > window:
                left += 1

            matching_events = ordered_events[left : right + 1]

            if len(matching_events) >= threshold:
                window_minutes = int(window.total_seconds() // 60)

                alert = Alert(
                    rule_id="AUTH-BRUTE-FORCE-001",
                    title="Possible brute-force attack",
                    description=(
                        f"{len(matching_events)} failed login attempts "
                        f"targeted account '{username}' from "
                        f"{source_ip} within {window_minutes} minutes."
                    ),
                    severity=Severity.HIGH,
                    confidence=0.95,
                    mitre_tactic="Credential Access",
                    mitre_technique_id="T1110.001",
                    mitre_technique_name="Password Guessing",
                    evidence=[event.raw_log for event in matching_events],
                )

                incidents.append(
                    Incident(
                        events=matching_events.copy(),
                        alerts=[alert],
                    )
                )

                break

    return incidents







            
            


