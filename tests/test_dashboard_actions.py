from collections.abc import Generator
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.tasks.dependencies import get_report_enqueuer

PASSWORD = "Dashboard-Actions-Password-123!"


@pytest.fixture
def captured_report_ids() -> Generator[list[str], None, None]:
    captured: list[str] = []

    previous_override = app.dependency_overrides.get(get_report_enqueuer)

    def override_report_enqueuer():
        def enqueue(
            report_id: str,
        ) -> None:
            captured.append(report_id)

        return enqueue

    app.dependency_overrides[get_report_enqueuer] = override_report_enqueuer

    try:
        yield captured
    finally:
        if previous_override is None:
            app.dependency_overrides.pop(
                get_report_enqueuer,
                None,
            )
        else:
            app.dependency_overrides[get_report_enqueuer] = previous_override


def register_user_and_get_token(
    client: TestClient,
) -> tuple[str, str]:
    unique = uuid4().hex[:10]

    username = f"actions_{unique}"

    email = f"{username}@example.com"

    response = client.post(
        "/auth/register",
        json={
            "email": email,
            "username": username,
            "password": PASSWORD,
        },
    )

    assert response.status_code == 201, response.text

    token_response = client.post(
        "/auth/token",
        data={
            "username": username,
            "password": PASSWORD,
        },
    )

    assert token_response.status_code == 200, token_response.text

    return (
        username,
        token_response.json()["access_token"],
    )


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

    assert response.status_code == 303


def auth_headers(
    token: str,
) -> dict[str, str]:
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
    *,
    token: str,
) -> str:
    response = client.post(
        "/analysis/auth-log",
        headers=auth_headers(token),
        json={
            "content": build_auth_log(),
        },
    )

    assert response.status_code == 200, response.text

    body = response.json()

    analysis_id = body.get("analysis_id") or body.get("id")

    assert analysis_id is not None

    return analysis_id


def test_dashboard_can_run_anomaly_detection(
    client: TestClient,
) -> None:
    username, token = register_user_and_get_token(client)

    analysis_id = create_analysis(
        client,
        token=token,
    )

    dashboard_login(
        client,
        username=username,
    )

    response = client.post(
        f"/dashboard/analysis/" f"{analysis_id}/actions/" "run-anomaly"
    )

    assert response.status_code == 200, response.text

    assert "Anomaly detection completed" in response.text

    assert "IsolationForest" in response.text

    api_response = client.get(
        (f"/analysis/" f"{analysis_id}/anomalies"),
        headers=auth_headers(token),
    )

    assert api_response.status_code == 200

    assert api_response.json()["result"]["anomaly_count"] > 0


def test_dashboard_can_queue_ai_investigation(
    client: TestClient,
    captured_report_ids: list[str],
) -> None:
    username, token = register_user_and_get_token(client)

    analysis_id = create_analysis(
        client,
        token=token,
    )

    dashboard_login(
        client,
        username=username,
    )

    response = client.post(
        f"/dashboard/analysis/" f"{analysis_id}/actions/" "generate-report"
    )

    assert response.status_code == 200, response.text

    assert len(captured_report_ids) == 1

    assert "AI investigation queued" in response.text

    api_response = client.get(
        (f"/analysis/history/" f"{analysis_id}/ai-report"),
        headers=auth_headers(token),
    )

    assert api_response.status_code == 200

    assert api_response.json()["status"] == "pending"


def test_dashboard_can_create_and_link_case(
    client: TestClient,
) -> None:
    username, token = register_user_and_get_token(client)

    analysis_id = create_analysis(
        client,
        token=token,
    )

    dashboard_login(
        client,
        username=username,
    )

    case_title = "Suspicious authentication activity"

    response = client.post(
        (f"/dashboard/analysis/" f"{analysis_id}/actions/" "create-case"),
        data={
            "title": case_title,
            "severity": "high",
        },
    )

    assert response.status_code == 200, response.text

    assert case_title in response.text

    assert "created and linked" in response.text

    cases_response = client.get(
        "/cases",
        headers=auth_headers(token),
    )

    assert cases_response.status_code == 200

    cases = cases_response.json()

    created = next(case for case in cases if case["title"] == case_title)

    detail_response = client.get(
        (f"/cases/" f"{created['case_id']}"),
        headers=auth_headers(token),
    )

    assert detail_response.status_code == 200

    linked_ids = {
        analysis["analysis_id"] for analysis in detail_response.json()["analyses"]
    }

    assert analysis_id in linked_ids


def test_dashboard_actions_respect_analysis_ownership(
    client: TestClient,
) -> None:
    (
        owner_username,
        owner_token,
    ) = register_user_and_get_token(client)

    analysis_id = create_analysis(
        client,
        token=owner_token,
    )

    (
        other_username,
        _,
    ) = register_user_and_get_token(client)

    assert owner_username != other_username

    dashboard_login(
        client,
        username=other_username,
    )

    response = client.post(
        f"/dashboard/analysis/" f"{analysis_id}/actions/" "run-anomaly"
    )

    assert response.status_code == 404
