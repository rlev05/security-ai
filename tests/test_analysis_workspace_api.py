from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi.testclient import TestClient

PASSWORD = "WorkspaceTests-StrongPassword-123!"


def register_and_login(
    client: TestClient,
) -> dict[str, str]:
    unique = uuid4().hex[:10]

    username = f"workspace_{unique}"

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

    assert token_response.status_code == 200, token_response.text

    token = token_response.json()["access_token"]

    return {"Authorization": (f"Bearer {token}")}


def build_auth_log() -> str:
    lines: list[str] = []

    normal_start = datetime(
        2026,
        8,
        20,
        9,
        0,
        tzinfo=timezone.utc,
    )

    for index in range(60):
        timestamp = normal_start + timedelta(
            minutes=index,
        )

        username = f"user{index % 5}"

        ip_address = f"192.0.2." f"{10 + (index % 5)}"

        lines.append(
            f"{timestamp.strftime('%Y-%m-%dT%H:%M:%S')} "
            f"Accepted password for "
            f"{username} from "
            f"{ip_address}"
        )

    attack_start = datetime(
        2026,
        8,
        20,
        3,
        0,
        tzinfo=timezone.utc,
    )

    for index in range(8):
        timestamp = attack_start + timedelta(
            seconds=index,
        )

        lines.append(
            f"{timestamp.strftime('%Y-%m-%dT%H:%M:%S')} "
            f"Failed password for "
            f"target{index} from "
            "203.0.113.250"
        )

    return "\n".join(lines)


def create_analysis(
    client: TestClient,
    headers: dict[str, str],
) -> str:
    response = client.post(
        "/analysis/auth-log",
        headers=headers,
        json={
            "content": build_auth_log(),
        },
    )

    assert response.status_code == 200, response.text

    body = response.json()

    analysis_id = body.get("analysis_id") or body.get("id")

    assert analysis_id is not None

    return analysis_id


def test_workspace_returns_owned_analysis(
    client: TestClient,
) -> None:
    headers = register_and_login(client)

    analysis_id = create_analysis(
        client,
        headers,
    )

    response = client.get(
        (f"/analysis/{analysis_id}" "/workspace"),
        headers=headers,
    )

    assert response.status_code == 200, response.text

    body = response.json()

    assert body["analysis"]["id"] == analysis_id

    assert body["analysis"]["total_lines"] == 68

    assert body["analysis"]["event_count"] == 68

    assert body["analysis"]["result"]["events"]

    assert body["latest_anomaly_run"] is None

    assert body["latest_investigation_report"] is None


def test_workspace_contains_latest_anomaly_run(
    client: TestClient,
) -> None:
    headers = register_and_login(client)

    analysis_id = create_analysis(
        client,
        headers,
    )

    anomaly_response = client.post(
        (f"/analysis/{analysis_id}" "/anomalies"),
        headers=headers,
    )

    assert anomaly_response.status_code == 201, anomaly_response.text

    anomaly = anomaly_response.json()

    response = client.get(
        (f"/analysis/{analysis_id}" "/workspace"),
        headers=headers,
    )

    assert response.status_code == 200, response.text

    body = response.json()

    workspace_anomaly = body["latest_anomaly_run"]

    assert workspace_anomaly is not None

    assert workspace_anomaly["id"] == anomaly["id"]

    assert workspace_anomaly["analysis_id"] == analysis_id

    assert workspace_anomaly["result"]["model_name"] == "IsolationForest"

    assert workspace_anomaly["result"]["anomaly_count"] > 0


def test_workspace_does_not_expose_another_users_analysis(
    client: TestClient,
) -> None:
    owner_headers = register_and_login(client)

    other_headers = register_and_login(client)

    analysis_id = create_analysis(
        client,
        owner_headers,
    )

    response = client.get(
        (f"/analysis/{analysis_id}" "/workspace"),
        headers=other_headers,
    )

    assert response.status_code == 404


def test_workspace_requires_authentication(
    client: TestClient,
) -> None:
    headers = register_and_login(client)

    analysis_id = create_analysis(
        client,
        headers,
    )

    response = client.get(f"/analysis/{analysis_id}" "/workspace")

    assert response.status_code == 401
