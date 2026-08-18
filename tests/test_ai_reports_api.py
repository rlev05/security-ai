import uuid

import pytest
from fastapi.testclient import TestClient

from app.api.auth_dependencies import get_current_user
from app.main import app
from app.models.user import UserRole
from app.models.user_record import UserRecord
from app.tasks.dependencies import get_report_enqueuer


AUTH_LOG_CONTENT = """
2026-08-01T12:00:00 Failed password for admin from 192.168.1.5
2026-08-01T12:01:00 Failed password for admin from 192.168.1.5
2026-08-01T12:02:00 Failed password for admin from 192.168.1.5
2026-08-01T12:03:00 Failed password for admin from 192.168.1.5
2026-08-01T12:04:00 Failed password for admin from 192.168.1.5
"""


@pytest.fixture()
def queued_report_ids() -> list[str]:
    """Capture queued report IDs without contacting Redis."""

    queued: list[str] = []

    def fake_enqueue(
        report_id: str,
    ) -> None:
        queued.append(report_id)

    app.dependency_overrides[
        get_report_enqueuer
    ] = lambda: fake_enqueue

    try:
        yield queued
    finally:
        app.dependency_overrides.pop(
            get_report_enqueuer,
            None,
        )


def register_and_login(
    client: TestClient,
    prefix: str,
) -> tuple[dict[str, object], dict[str, str]]:
    suffix = uuid.uuid4().hex[:10]

    username = f"{prefix}_{suffix}"

    payload = {
        "email": f"{username}@example.com",
        "username": username,
        "password": "StrongPassword123!",
    }

    registration_response = client.post(
        "/auth/register",
        json=payload,
    )

    assert registration_response.status_code == 201

    token_response = client.post(
        "/auth/token",
        data={
            "username": payload["username"],
            "password": payload["password"],
        },
    )

    assert token_response.status_code == 200

    access_token = token_response.json()[
        "access_token"
    ]

    headers = {
        "Authorization": f"Bearer {access_token}",
    }

    return (
        registration_response.json(),
        headers,
    )


def submit_analysis(
    client: TestClient,
    headers: dict[str, str],
) -> str:
    response = client.post(
        "/analysis/auth-log",
        json={
            "content": AUTH_LOG_CONTENT,
        },
        headers=headers,
    )

    assert response.status_code == 200

    return response.json()["analysis_id"]


def test_user_can_queue_ai_report(
    client: TestClient,
    queued_report_ids: list[str],
) -> None:
    _, headers = register_and_login(
        client,
        "ai_queue",
    )

    analysis_id = submit_analysis(
        client,
        headers,
    )

    response = client.post(
        f"/analysis/history/{analysis_id}/ai-report",
        headers=headers,
    )

    assert response.status_code == 202

    body = response.json()

    assert body["analysis_id"] == analysis_id
    assert body["status"] == "pending"

    assert body["report"] is None
    assert body["grounding"] is None
    assert body["error_message"] is None

    assert len(queued_report_ids) == 1

    assert (
        queued_report_ids[0]
        == body["report_id"]
    )


def test_pending_report_can_be_retrieved(
    client: TestClient,
    queued_report_ids: list[str],
) -> None:
    _, headers = register_and_login(
        client,
        "pending_report",
    )

    analysis_id = submit_analysis(
        client,
        headers,
    )

    creation_response = client.post(
        f"/analysis/history/{analysis_id}/ai-report",
        headers=headers,
    )

    assert creation_response.status_code == 202

    retrieval_response = client.get(
        f"/analysis/history/{analysis_id}/ai-report",
        headers=headers,
    )

    assert retrieval_response.status_code == 200

    creation_body = creation_response.json()
    retrieval_body = retrieval_response.json()

    assert (
        retrieval_body["report_id"]
        == creation_body["report_id"]
    )

    assert retrieval_body["status"] == "pending"
    assert retrieval_body["report"] is None
    assert retrieval_body["grounding"] is None

    assert len(queued_report_ids) == 1


def test_ai_report_requires_authentication(
    client: TestClient,
    queued_report_ids: list[str],
) -> None:
    _, headers = register_and_login(
        client,
        "report_owner",
    )

    analysis_id = submit_analysis(
        client,
        headers,
    )

    response = client.post(
        f"/analysis/history/{analysis_id}/ai-report"
    )

    assert response.status_code == 401

    assert queued_report_ids == []


def test_user_cannot_queue_report_for_another_user(
    client: TestClient,
    queued_report_ids: list[str],
) -> None:
    _, owner_headers = register_and_login(
        client,
        "queue_owner",
    )

    _, other_headers = register_and_login(
        client,
        "queue_other",
    )

    analysis_id = submit_analysis(
        client,
        owner_headers,
    )

    response = client.post(
        f"/analysis/history/{analysis_id}/ai-report",
        headers=other_headers,
    )

    assert response.status_code == 404

    assert queued_report_ids == []


def test_admin_can_queue_report_for_any_analysis(
    client: TestClient,
    queued_report_ids: list[str],
) -> None:
    _, owner_headers = register_and_login(
        client,
        "admin_report_owner",
    )

    admin_response, _ = register_and_login(
        client,
        "admin_candidate",
    )

    analysis_id = submit_analysis(
        client,
        owner_headers,
    )

    admin_user = UserRecord(
        id=str(
            admin_response["id"]
        ),
        email=str(
            admin_response["email"]
        ),
        username=str(
            admin_response["username"]
        ),
        password_hash=(
            "not-used-by-this-test"
        ),
        role=UserRole.ADMIN.value,
        is_active=True,
    )

    app.dependency_overrides[
        get_current_user
    ] = lambda: admin_user

    try:
        response = client.post(
            f"/analysis/history/{analysis_id}/ai-report"
        )
    finally:
        app.dependency_overrides.pop(
            get_current_user,
            None,
        )

    assert response.status_code == 202

    body = response.json()

    assert body["status"] == "pending"

    assert len(queued_report_ids) == 1

    assert (
        queued_report_ids[0]
        == body["report_id"]
    )


def test_missing_report_returns_not_found(
    client: TestClient,
    queued_report_ids: list[str],
) -> None:
    _, headers = register_and_login(
        client,
        "missing_report",
    )

    analysis_id = submit_analysis(
        client,
        headers,
    )

    response = client.get(
        f"/analysis/history/{analysis_id}/ai-report",
        headers=headers,
    )

    assert response.status_code == 404

    assert queued_report_ids == []


def test_queue_failure_marks_report_failed(
    client: TestClient,
) -> None:
    def broken_enqueue(
        report_id: str,
    ) -> None:
        raise RuntimeError(
            "Redis unavailable"
        )

    app.dependency_overrides[
        get_report_enqueuer
    ] = lambda: broken_enqueue

    try:
        _, headers = register_and_login(
            client,
            "queue_failure",
        )

        analysis_id = submit_analysis(
            client,
            headers,
        )

        response = client.post(
            f"/analysis/history/{analysis_id}/ai-report",
            headers=headers,
        )

        assert response.status_code == 503

        assert response.json()["detail"] == (
            "The background job queue is unavailable."
        )

        retrieval_response = client.get(
            f"/analysis/history/{analysis_id}/ai-report",
            headers=headers,
        )

    finally:
        app.dependency_overrides.pop(
            get_report_enqueuer,
            None,
        )

    assert retrieval_response.status_code == 200

    body = retrieval_response.json()

    assert body["status"] == "failed"
    assert body["report"] is None

    assert body["error_message"] == (
        "The investigation could not be queued "
        "for background processing."
    )


def test_multiple_requests_create_separate_jobs(
    client: TestClient,
    queued_report_ids: list[str],
) -> None:
    _, headers = register_and_login(
        client,
        "multiple_jobs",
    )

    analysis_id = submit_analysis(
        client,
        headers,
    )

    first_response = client.post(
        f"/analysis/history/{analysis_id}/ai-report",
        headers=headers,
    )

    second_response = client.post(
        f"/analysis/history/{analysis_id}/ai-report",
        headers=headers,
    )

    assert first_response.status_code == 202
    assert second_response.status_code == 202

    first_id = first_response.json()[
        "report_id"
    ]

    second_id = second_response.json()[
        "report_id"
    ]

    assert first_id != second_id

    assert queued_report_ids == [
        first_id,
        second_id,
    ]