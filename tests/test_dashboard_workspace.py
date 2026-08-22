from datetime import datetime, timedelta, timezone
from uuid import uuid4
from fastapi.testclient import TestClient


PASSWORD = (
    "Dashboard-Workspace-Password-123!"
)


def register_user_and_get_token(
    client: TestClient,
) -> tuple[str, str]:
    unique = uuid4().hex[:10]

    username = (
        f"workspace_{unique}"
    )

    email = (
        f"{username}@example.com"
    )

    register_response = client.post(
        "/auth/register",
        json={
            "email": email,
            "username": username,
            "password": PASSWORD,
        },
    )

    assert (
        register_response.status_code
        == 201
    ), register_response.text

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

    token = (
        token_response.json()[
            "access_token"
        ]
    )

    return username, token


def dashboard_login(
    client: TestClient,
    *,
    username: str,
) -> None:
    response = client.post(
        "/login",
        data={
            "login": username,
            "password": PASSWORD,
        },
        follow_redirects=False,
    )

    assert (
        response.status_code
        == 303
    ), response.text


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
        timestamp = (
            normal_start
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
                f"Accepted password for "
                f"{username} from "
                f"{ip_address}"
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

    for index in range(8):
        timestamp = (
            attack_start
            + timedelta(
                seconds=index,
            )
        )

        lines.append(
            (
                f"{timestamp.strftime('%Y-%m-%dT%H:%M:%S')} "
                f"Failed password for "
                f"target{index} from "
                "203.0.113.250"
            )
        )

    return "\n".join(
        lines
    )


def create_analysis(
    client: TestClient,
    *,
    token: str,
) -> str:
    response = client.post(
        "/analysis/auth-log",
        headers={
            "Authorization": (
                f"Bearer {token}"
            )
        },
        json={
            "content": build_auth_log(),
        },
    )

    assert (
        response.status_code
        == 200
    ), response.text

    body = response.json()

    analysis_id = (
        body.get("analysis_id")
        or body.get("id")
    )

    assert analysis_id is not None

    return analysis_id


def test_workspace_requires_dashboard_authentication(
    client: TestClient,
) -> None:
    response = client.get(
        (
            "/dashboard/analysis/"
            "00000000-0000-0000-0000-000000000001"
        ),
        follow_redirects=False,
    )

    assert (
        response.status_code
        == 303
    )

    assert (
        response.headers[
            "location"
        ]
        == "/login"
    )


def test_workspace_displays_analysis_evidence(
    client: TestClient,
) -> None:
    username, token = (
        register_user_and_get_token(
            client
        )
    )

    analysis_id = create_analysis(
        client,
        token=token,
    )

    dashboard_login(
        client,
        username=username,
    )

    response = client.get(
        (
            f"/dashboard/analysis/"
            f"{analysis_id}"
        )
    )

    assert (
        response.status_code
        == 200
    ), response.text

    assert (
        "Deterministic Detections"
        in response.text
    )

    assert (
        "Parsed Security Events"
        in response.text
    )

    assert (
        "ML Anomaly Detection"
        in response.text
    )

    assert (
        "Investigation Report"
        in response.text
    )

    assert (
        "203.0.113.250"
        in response.text
    )

    assert (
        "No AI investigation report"
        in response.text
    )


def test_workspace_displays_latest_ml_anomaly_run(
    client: TestClient,
) -> None:
    username, token = (
        register_user_and_get_token(
            client
        )
    )

    analysis_id = create_analysis(
        client,
        token=token,
    )

    anomaly_response = client.post(
        (
            f"/analysis/"
            f"{analysis_id}/anomalies"
        ),
        headers={
            "Authorization": (
                f"Bearer {token}"
            )
        },
    )

    assert (
        anomaly_response.status_code
        == 201
    ), anomaly_response.text

    dashboard_login(
        client,
        username=username,
    )

    response = client.get(
        (
            f"/dashboard/analysis/"
            f"{analysis_id}"
        )
    )

    assert (
        response.status_code
        == 200
    ), response.text

    assert (
        "IsolationForest"
        in response.text
    )

    assert (
        "Model run"
        in response.text
    )

    assert (
        "ANOMALY"
        in response.text
    )


def test_workspace_does_not_expose_another_users_analysis(
    client: TestClient,
) -> None:
    owner_username, owner_token = (
        register_user_and_get_token(
            client
        )
    )

    analysis_id = create_analysis(
        client,
        token=owner_token,
    )

    other_username, _ = (
        register_user_and_get_token(
            client
        )
    )

    assert (
        owner_username
        != other_username
    )

    dashboard_login(
        client,
        username=other_username,
    )

    response = client.get(
        (
            f"/dashboard/analysis/"
            f"{analysis_id}"
        )
    )

    assert (
        response.status_code
        == 404
    )