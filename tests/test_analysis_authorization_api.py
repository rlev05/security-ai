from fastapi.testclient import TestClient

from app.api.auth_dependencies import get_current_user
from app.main import app
from app.models.user import UserRole
from app.models.user_record import UserRecord


AUTH_LOG_CONTENT = """
2026-08-01T12:00:00 Failed password for admin from 192.168.1.5
2026-08-01T12:01:00 Failed password for admin from 192.168.1.5
2026-08-01T12:02:00 Failed password for admin from 192.168.1.5
2026-08-01T12:03:00 Failed password for admin from 192.168.1.5
2026-08-01T12:04:00 Failed password for admin from 192.168.1.5
"""


def register_and_login(
    client: TestClient,
    identifier: str,
) -> tuple[dict[str, object], dict[str, str]]:
    """Register a user and return their profile and authorization header."""

    registration_payload = {
        "email": f"{identifier}@example.com",
        "username": identifier,
        "password": "StrongPassword123!",
    }

    registration_response = client.post(
        "/auth/register",
        json=registration_payload,
    )

    assert registration_response.status_code == 201

    token_response = client.post(
        "/auth/token",
        data={
            "username": registration_payload["username"],
            "password": registration_payload["password"],
        },
    )

    assert token_response.status_code == 200

    access_token = token_response.json()["access_token"]

    headers = {
        "Authorization": f"Bearer {access_token}",
    }

    return registration_response.json(), headers


def submit_analysis(
    client: TestClient,
    headers: dict[str, str],
) -> str:
    """Submit an analysis as the user represented by the headers."""

    response = client.post(
        "/analysis/auth-log",
        json={
            "content": AUTH_LOG_CONTENT,
        },
        headers=headers,
    )

    assert response.status_code == 200

    return response.json()["analysis_id"]


def test_analysis_submission_requires_authentication(
    client: TestClient,
) -> None:
    response = client.post(
        "/analysis/auth-log",
        json={
            "content": AUTH_LOG_CONTENT,
        },
    )

    assert response.status_code == 401


def test_analysis_file_upload_requires_authentication(
    client: TestClient,
) -> None:
    response = client.post(
        "/analysis/auth-log/file",
        files={
            "file": (
                "auth.log",
                AUTH_LOG_CONTENT.encode("utf-8"),
                "text/plain",
            ),
        },
    )

    assert response.status_code == 401


def test_users_only_list_their_own_analyses(
    client: TestClient,
) -> None:
    _, first_headers = register_and_login(
        client,
        "history_user_one",
    )

    _, second_headers = register_and_login(
        client,
        "history_user_two",
    )

    first_analysis_id = submit_analysis(
        client,
        first_headers,
    )

    second_analysis_id = submit_analysis(
        client,
        second_headers,
    )

    first_history_response = client.get(
        "/analysis/history",
        headers=first_headers,
    )

    second_history_response = client.get(
        "/analysis/history",
        headers=second_headers,
    )

    assert first_history_response.status_code == 200
    assert second_history_response.status_code == 200

    first_history_ids = {
        record["analysis_id"]
        for record in first_history_response.json()
    }

    second_history_ids = {
        record["analysis_id"]
        for record in second_history_response.json()
    }

    assert first_analysis_id in first_history_ids
    assert second_analysis_id not in first_history_ids

    assert second_analysis_id in second_history_ids
    assert first_analysis_id not in second_history_ids


def test_user_cannot_retrieve_another_users_analysis(
    client: TestClient,
) -> None:
    _, owner_headers = register_and_login(
        client,
        "analysis_owner",
    )

    _, other_headers = register_and_login(
        client,
        "different_user",
    )

    analysis_id = submit_analysis(
        client,
        owner_headers,
    )

    response = client.get(
        f"/analysis/history/{analysis_id}",
        headers=other_headers,
    )

    assert response.status_code == 404
    assert response.json() == {
        "detail": "Analysis record not found.",
    }


def test_admin_can_view_every_analysis(
    client: TestClient,
) -> None:
    _, first_headers = register_and_login(
        client,
        "admin_visible_one",
    )

    _, second_headers = register_and_login(
        client,
        "admin_visible_two",
    )

    first_analysis_id = submit_analysis(
        client,
        first_headers,
    )

    second_analysis_id = submit_analysis(
        client,
        second_headers,
    )

    admin_user = UserRecord(
        id="00000000-0000-0000-0000-000000000001",
        email="admin@example.com",
        username="test_admin",
        password_hash="not-used-by-this-test",
        role=UserRole.ADMIN.value,
        is_active=True,
    )

    app.dependency_overrides[get_current_user] = (
        lambda: admin_user
    )

    try:
        history_response = client.get(
            "/analysis/history",
        )

        detail_response = client.get(
            f"/analysis/history/{first_analysis_id}",
        )
    finally:
        app.dependency_overrides.pop(
            get_current_user,
            None,
        )

    assert history_response.status_code == 200
    assert detail_response.status_code == 200

    history_ids = {
        record["analysis_id"]
        for record in history_response.json()
    }

    assert first_analysis_id in history_ids
    assert second_analysis_id in history_ids
    assert detail_response.json()["analysis_id"] == first_analysis_id