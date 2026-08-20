import math
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any

FEATURE_NAMES = [
    "hour_sin",
    "hour_cos",
    "is_login_failure",
    "is_login_success",
    "ip_event_count",
    "user_event_count",
    "ip_failure_count",
    "user_failure_count",
    "distinct_users_for_ip",
    "seconds_since_previous_ip_event",
    "seconds_since_previous_user_event",
]


def _get_first(
        event: dict[str, Any],
        *keys: str
) -> Any:
    for key in keys:
        value = event.get(key)

        if value is not None:
            return value

    return None

def _normalise_text(
        value: Any
) -> str:
    if value is None:
        return ""

    return str(value).strip().lower()

def _event_type(
        event: dict[str, Any],
) -> str:
    return _normalise_text(
        _get_first(
            event,
            "event_type",
            "type"
        )
    )

def _username(
        event: dict[str, Any],
) -> str:
    return _normalise_text(
        _get_first(
            event,
            "username",
            "user",
            "account"
        )
    )

def _ip_address(
        event: dict[str, Any],
) -> str:
    return _normalise_text(
        _get_first(
            event,
            "ip_address",
            "source_ip",
            "ip"
        )
    )

def _parse_timestamp(
        event: dict[str, Any],
) -> datetime | None:
    value = _get_first(
        event,
        "timestamp",
        "event_time",
        "time"
    )

    if isinstance(value, datetime):
        timestamp = value

    elif isinstance(value, str):
        raw = value.strip()

        if not raw:
            return None

        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"

        try:
            timestamp = datetime.fromisoformat(raw)
        except ValueError:
            return None

    else:
        return None

    if timestamp.tzinfo is None:
        return timestamp.replace(tzinfo=timezone.utc)

    return timestamp.astimezone(timezone.utc)


def _is_failure(
        event_type: str
) -> bool:

    return ("failure" in event_type) or ("failed" in event_type)


def _is_success(
        event_type: str
) -> bool:
    return ("success" in event_type) or ("successful" in event_type)


def build_event_features(
        events: list[dict[str, Any]],
) -> list[dict[str, float]]:

    """
    Convert security events into numeric behavioural features.

    The feature extractor intentionally avoids using raw usernames,
    IP addresses or log text directly as ML inputs. Instead it models
    behavioural characteristics such as frequency, failure density,
    time of day and event spacing.
    """

    event_types = [_event_type(event) for event in events]

    usernames = [_username(event) for event in events]

    ip_addresses = [_ip_address(event) for event in events]

    timestamps = [_parse_timestamp(event) for event in events]

    ip_event_counts = Counter(ip for ip in ip_addresses if ip)

    user_event_counts = Counter(user for user in usernames if user)

    ip_failure_counts: Counter[str] = Counter()

    user_failure_counts: Counter[str] = Counter()

    users_by_ip: dict[
        str,
        set[str],
    ] = defaultdict(set)

    for (
        event_type,
        username,
        ip_address,
    ) in zip(
        event_types,
        usernames,
        ip_addresses,
        strict=True,
    ):
        if ip_address and username:
            users_by_ip[ip_address].add(username)

        if _is_failure(event_type):
            if ip_address:
                ip_failure_counts[ip_address] += 1

            if username:
                user_failure_counts[username] += 1

    previous_ip_time: dict[
        str,
        datetime,
    ] = {}

    previous_user_time: dict[
        str,
        datetime,
    ] = {}

    feature_rows: list[dict[str, float]] = []

    for index, event in enumerate(events):
        event_type = event_types[index]

        username = usernames[index]

        ip_address = ip_addresses[index]

        timestamp = timestamps[index]

        hour = (
            float(timestamp.hour) + (float(timestamp.minute) / 60.0)
            if timestamp is not None
            else 12.0
        )

        angle = 2.0 * math.pi * hour / 24.0

        seconds_since_ip = 0.0

        seconds_since_user = 0.0

        if timestamp is not None and ip_address:
            previous = previous_ip_time.get(ip_address)

            if previous is not None:
                seconds_since_ip = max(
                    (timestamp - previous).total_seconds(),
                    0.0,
                )

            previous_ip_time[ip_address] = timestamp

        if timestamp is not None and username:
            previous = previous_user_time.get(username)

            if previous is not None:
                seconds_since_user = max(
                    (timestamp - previous).total_seconds(),
                    0.0,
                )

            previous_user_time[username] = timestamp

        feature_rows.append(
            {
                "hour_sin": math.sin(angle),
                "hour_cos": math.cos(angle),
                "is_login_failure": (1.0 if _is_failure(event_type) else 0.0),
                "is_login_success": (1.0 if _is_success(event_type) else 0.0),
                "ip_event_count": float(
                    ip_event_counts.get(
                        ip_address,
                        0,
                    )
                ),
                "user_event_count": float(
                    user_event_counts.get(
                        username,
                        0,
                    )
                ),
                "ip_failure_count": float(
                    ip_failure_counts.get(
                        ip_address,
                        0,
                    )
                ),
                "user_failure_count": float(
                    user_failure_counts.get(
                        username,
                        0,
                    )
                ),
                "distinct_users_for_ip": float(
                    len(
                        users_by_ip.get(
                            ip_address,
                            set(),
                        )
                    )
                ),
                "seconds_since_previous_ip_event": (seconds_since_ip),
                "seconds_since_previous_user_event": (seconds_since_user),
            }
        )

    return feature_rows


