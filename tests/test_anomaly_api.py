from datetime import datetime, timedelta, timezone
from uuid import uuid4
from fastapi.testclient import TestClient


PASSWORD = "AnomalyTests-StrongPassword-123!"


def register_and_login(
    client: TestClient,
) -> dict[str, str]:
    unique = uuid4().hex[:10]

    username = f"anomaly_{unique}"
    email = f"{username}@example.com"

    register_response = client.post(
        "/auth/register",
        json={
            "email": email,
            "username": username,
            "password": PASSWORD,
        },
    )

    assert register_response.status_code in {
        200,
        201,
    }, register_response.text

    token_response = client.post(
        "/auth/token",
        data={
            "username": username,
            "password": PASSWORD,
        },
    )

    assert (
        token_response.status_code
        == 200
    ), token_response.text

    token = token_response.json()[
        "access_token"
    ]

    return {
        "Authorization": (
            f"Bearer {token}"
        )
    }


def build_auth_log(
    *,
    normal_events: int = 60,
    anomalous_events: int = 8,
) -> str:
    lines: list[str] = []

    start = datetime(
        2026,
        8,
        20,
        9,
        0,
        tzinfo=timezone.utc,
    )

    for index in range(
        normal_events
    ):
        timestamp = (
            start
            + timedelta(
                minutes=index,
            )
        )

        username = (
            f"user{index % 5}"
        )

        ip_address = (
            f"192.0.2."
            f"{10 + (index % 5)}"
        )

        lines.append(
            (
                f"{timestamp.strftime('%Y-%m-%dT%H:%M:%S')} "
                f"Accepted password for {username} "
                f"from {ip_address}"
            )
        )

    attack_start = datetime(
        2026,
        8,
        20,
        3,
        0,
        tzinfo=timezone.utc,
    )

    for index in range(
        anomalous_events
    ):
        timestamp = (
            attack_start
            + timedelta(
                seconds=index,
            )
        )

        username = (
            f"target{index}"
        )

        lines.append(
            (
                f"{timestamp.strftime('%Y-%m-%dT%H:%M:%S')} "
                f"Failed password for {username} "
                "from 203.0.113.250"
            )
        )

    return "\n".join(
        lines
    )

def create_analysis(
        client: TestClient,
        headers: dict[str, str],
        content: str,
) -> str:
    response = client.post(
        "/analysis/auth-log",
        headers=headers,
        json={
            "content": content,
            "source_name": ("anomaly-api-test.log")
        },
    )

    assert response.status_code == 200, response.text

    body = response.json()

    analysis_id = body.get("analysis_id") or body.get("id")

    if analysis_id is not None:
        return analysis_id


    history_response = client.get(
        "/analysis/history",
        headers=headers,
    )

    assert history_response.status_code == 200, history_response.text

    history = history_response.json()

    assert history

    record = history[0]

    analysis_id = record.get("analysis_id") or record.get("id")

    assert analysis_id is not None

    return analysis_id

def test_user_can_run_anomaly_detection_on_owned_analysis(
        client: TestClient,
):
    headers = register_and_login(client)

    analysis_id = create_analysis(client, headers, build_auth_log())

    response = client.get((f"/analysis/{analysis_id}/anomalies"),
                          headers=headers)

    assert response.status_code == 200, response.text

    result = response.json()

    assert result["model_name"] == "IsolationForest"

    assert result["total_events"] == 68

    assert result["anomaly_count"] > 0
    assert result["skipped_reason"] is None

    assert result["feature_names"]

    assert result["anomalies"]


def test_anomaly_endpoint_supports_custom_contamination(
        client: TestClient,
):
    headers = register_and_login(client)

    analysis_id = create_analysis(
        client,
        headers,
        build_auth_log(),
    )

    response = client.get(
        (f"/analysis/{analysis_id}/anomalies?contamination=0.1"),
        headers=headers,
    )

    assert response.status_code == 200, response.text

    result = response.json()

    assert result["contamination"] == 0.1


def test_anomaly_detection_skips_small_analysis(
    client: TestClient,
):
    headers = register_and_login(client)

    analysis_id = create_analysis(
        client,
        headers,
        build_auth_log(
            normal_events=10,
            anomalous_events=0,
        ),
    )

    response = client.get(
        (f"/analysis/{analysis_id}/anomalies"),
        headers=headers,
    )

    assert response.status_code == 200, response.text

    result = response.json()

    assert result["total_events"] == 10

    assert result["analysed_events"] == 0

    assert result["anomaly_count"] == 0

    assert result["skipped_reason"] is not None


def test_user_cannot_analyse_another_users_analysis(
    client: TestClient,
):
    owner_headers = register_and_login(client)

    other_headers = register_and_login(client)

    analysis_id = create_analysis(
        client,
        owner_headers,
        build_auth_log(),
    )

    response = client.get(
        (f"/analysis/{analysis_id}/anomalies"),
        headers=other_headers,
    )

    assert response.status_code == 404


def test_anomaly_endpoint_requires_authentication(
    client: TestClient,
):
    headers = register_and_login(client)

    analysis_id = create_analysis(
        client,
        headers,
        build_auth_log(),
    )

    response = client.get((f"/analysis/{analysis_id}/anomalies"))

    assert response.status_code == 401


def test_invalid_contamination_is_rejected(
    client: TestClient,
):
    headers = register_and_login(client)

    analysis_id = create_analysis(
        client,
        headers,
        build_auth_log(),
    )

    response = client.get(
        (f"/analysis/{analysis_id}/anomalies?contamination=0.5"),
        headers=headers,
    )

    assert response.status_code == 422






