from collections import defaultdict, deque
from datetime import timedelta

from app.models.alert import Alert, Severity
from app.models.event import EventType, SecurityEvent
from app.models.incident import Incident


def detect_success_after_failures(
    events: list[SecurityEvent],
    failure_threshold: int = 5,
    failure_window: timedelta = timedelta(minutes=5),
    success_window: timedelta = timedelta(minutes=10),
) -> list[Incident]:
    """
    Detect a successful login following repeated failures for the
    same account and source IP address.
    """

    if failure_threshold < 1:
        raise ValueError(
            "Failure threshold must be at least 1"
        )

    if failure_window <= timedelta(0):
        raise ValueError(
            "Failure window must be greater than zero"
        )

    if success_window <= timedelta(0):
        raise ValueError(
            "Success window must be greater than zero"
        )

    events_by_target: dict[
        tuple[str, str],
        list[SecurityEvent],
    ] = defaultdict(list)

    for event in events:
        target = (event.source_ip, event.username)
        events_by_target[target].append(event)

    incidents: list[Incident] = []

    for (
        source_ip,
        username,
    ), target_events in events_by_target.items():
        ordered_events = sorted(
            target_events,
            key=lambda event: event.timestamp,
        )

        recent_failures: deque[SecurityEvent] = deque()

        for event in ordered_events:
            if event.event_type == EventType.LOGIN_FAILURE:
                recent_failures.append(event)

                while (
                    recent_failures[-1].timestamp
                    - recent_failures[0].timestamp
                    > failure_window
                ):
                    recent_failures.popleft()

                continue

            if event.event_type != EventType.LOGIN_SUCCESS:
                continue

            if len(recent_failures) < failure_threshold:
                continue

            time_since_last_failure = (
                event.timestamp
                - recent_failures[-1].timestamp
            )

            if time_since_last_failure > success_window:
                continue

            matching_failures = list(recent_failures)
            matching_events = [
                *matching_failures,
                event,
            ]

            failure_window_minutes = int(
                failure_window.total_seconds() // 60
            )

            success_window_minutes = int(
                success_window.total_seconds() // 60
            )

            alert = Alert(
                rule_id="AUTH-SUCCESS-AFTER-FAILURES-001",
                title="Possible account compromise",
                description=(
                    f"A successful login for account '{username}' "
                    f"from {source_ip} followed "
                    f"{len(matching_failures)} failed attempts "
                    f"within a {failure_window_minutes}-minute "
                    f"failure window. The successful login occurred "
                    f"within {success_window_minutes} minutes of "
                    f"the final failure."
                ),
                severity=Severity.CRITICAL,
                confidence=0.98,
                mitre_tactic="Initial Access",
                mitre_technique_id="T1078",
                mitre_technique_name="Valid Accounts",
                evidence=[
                    matching_event.raw_log
                    for matching_event in matching_events
                ],
            )

            incidents.append(
                Incident(
                    events=matching_events,
                    alerts=[alert],
                )
            )

            # Produce one compromise incident per account and IP pair.
            break

    return incidents