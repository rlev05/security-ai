from collections import defaultdict
from datetime import timedelta
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

     failures_by_ip: dict[str, list[SecurityEvent]] = defaultdict(list)

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
             while(
                 current_event.timestamp - ordered_events[left].timestamp
                 > window
             ):
                 left += 1

             matching_events = ordered_events[left: right + 1]

             if len(matching_events) >= threshold:
                 alert = Alert(
                     title="Possible brute force attack",
                     description=(
                         f"{len(matching_events)} failed login attempts"
                         f"were detected from {source_ip} within {window}"
                     ),

                     severity=Severity.HIGH,
                 )

                 incidents.append(
                     Incident(
                         events=matching_events.copy(),
                         alerts=[alert],
                     )
                 )

                 #Only create one incident per IP
                 break
     return incidents




            
            


