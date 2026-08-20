from datetime import datetime, timedelta, timezone
import pytest
from app.anomaly.detector import MINIMUM_EVENTS, detect_event_anomalies
from app.anomaly.features import FEATURE_NAMES, build_event_features


def build_event(
    *,
    timestamp: datetime,
    event_type: str = "LOGIN_SUCCESS",
    username: str = "alice",
    ip_address: str = "192.0.2.10",
) -> dict:
    return {
        "timestamp": timestamp.isoformat(),
        "event_type": event_type,
        "username": username,
        "ip_address": ip_address,
    }


def test_feature_extractor_builds_expected_features():
    start = datetime(
        2026,
        8,
        20,
        9,
        0,
        tzinfo=timezone.utc,
    )

    events = [
        build_event(
            timestamp=start,
        ),
        build_event(
            timestamp=(
                start
                + timedelta(
                    seconds=10,
                )
            ),
            event_type="LOGIN_FAILURE",
        ),
    ]

    features = build_event_features(
        events
    )

    assert len(features) == 2

    assert (
        set(features[0])
        == set(FEATURE_NAMES)
    )

    assert (
        features[1][
            "is_login_failure"
        ]
        == 1.0
    )

    assert (
        features[1][
            "seconds_since_previous_ip_event"
        ]
        == 10.0
    )


def test_detector_skips_small_event_sets():
    now = datetime.now(
        timezone.utc
    )

    events = [
        build_event(
            timestamp=(
                now
                + timedelta(
                    minutes=index,
                )
            )
        )
        for index
        in range(
            MINIMUM_EVENTS - 1
        )
    ]

    result = detect_event_anomalies(
        events
    )

    assert (
        result.total_events
        == MINIMUM_EVENTS - 1
    )

    assert (
        result.analysed_events
        == 0
    )

    assert (
        result.anomaly_count
        == 0
    )

    assert (
        result.skipped_reason
        is not None
    )

    assert (
        result.feature_names
        == FEATURE_NAMES
    )


def test_detector_identifies_anomalous_authentication_activity():
    start = datetime(
        2026,
        8,
        20,
        9,
        0,
        tzinfo=timezone.utc,
    )

    events: list[dict] = []

    for index in range(60):
        events.append(
            build_event(
                timestamp=(
                    start
                    + timedelta(
                        minutes=index,
                    )
                ),
                username=(
                    f"user{index % 5}"
                ),
                ip_address=(
                    f"192.0.2."
                    f"{10 + (index % 5)}"
                ),
            )
        )

    attack_time = datetime(
        2026,
        8,
        20,
        3,
        0,
        tzinfo=timezone.utc,
    )

    for index in range(8):
        events.append(
            build_event(
                timestamp=(
                    attack_time
                    + timedelta(
                        seconds=index,
                    )
                ),
                event_type=(
                    "LOGIN_FAILURE"
                ),
                username=(
                    f"target{index}"
                ),
                ip_address=(
                    "203.0.113.250"
                ),
            )
        )

    result = detect_event_anomalies(
        events,
        contamination=0.1,
    )

    assert (
        result.skipped_reason
        is None
    )

    assert (
        result.analysed_events
        == len(events)
    )

    assert (
        result.anomaly_count
        > 0
    )

    suspicious = [
        anomaly
        for anomaly
        in result.anomalies
        if anomaly.event[
            "ip_address"
        ]
        == "203.0.113.250"
    ]

    assert suspicious

    assert any(
        anomaly.features[
            "ip_failure_count"
        ]
        >= 5.0
        for anomaly
        in suspicious
    )

    assert any(
        anomaly.features[
            "distinct_users_for_ip"
        ]
        >= 5.0
        for anomaly
        in suspicious
    )


def test_detector_is_deterministic():
    start = datetime(
        2026,
        8,
        20,
        10,
        0,
        tzinfo=timezone.utc,
    )

    events = [
        build_event(
            timestamp=(
                start
                + timedelta(
                    seconds=(
                        index * 30
                    ),
                )
            ),
            username=(
                f"user{index % 4}"
            ),
            ip_address=(
                f"192.0.2."
                f"{index % 4 + 1}"
            ),
            event_type=(
                "LOGIN_FAILURE"
                if index % 7 == 0
                else "LOGIN_SUCCESS"
            ),
        )
        for index
        in range(50)
    ]

    first = detect_event_anomalies(
        events
    )

    second = detect_event_anomalies(
        events
    )

    assert (
        first.model_dump()
        == second.model_dump()
    )


def test_detector_rejects_invalid_contamination():
    with pytest.raises(
        ValueError,
        match="contamination",
    ):
        detect_event_anomalies(
            [],
            contamination=0.5,
        )

