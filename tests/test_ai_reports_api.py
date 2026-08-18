import uuid

import pytest
from fastapi.testclient import TestClient

from app.ai.dependencies import get_ai_provider
from app.api.auth_dependencies import get_current_user
from app.knowledge.dependencies import get_attack_repository
from app.main import app
from app.models.user import UserRole
from app.models.user_record import UserRecord
from tests.fake_ai_provider import (
    FakeInvestigationProvider,
    HallucinatingInvestigationProvider,
    UnavailableInvestigationProvider,
)
from tests.fake_attack_knowledge import (
    build_fake_attack_repository,
)


AUTH_LOG_CONTENT = """
2026-08-01T12:00:00 Failed password for admin from 192.168.1.5
2026-08-01T12:01:00 Failed password for admin from 192.168.1.5
2026-08-01T12:02:00 Failed password for admin from 192.168.1.5
2026-08-01T12:03:00 Failed password for admin from 192.168.1.5
2026-08-01T12:04:00 Failed password for admin from 192.168.1.5
"""


@pytest.fixture(autouse=True)
def fake_attack_repository():
    repository = build_fake_attack_repository()

    app.dependency_overrides[
        get_attack_repository
    ] = lambda: repository

    try:
        yield repository
    finally:
        app.dependency_overrides.pop(
            get_attack_repository,
            None,
        )


@pytest.fixture()
def fake_ai_provider() -> FakeInvestigationProvider:
    provider = FakeInvestigationProvider()

    app.dependency_overrides[
        get_ai_provider
    ] = lambda: provider

    try:
        yield provider
    finally:
        app.dependency_overrides.pop(
            get_ai_provider,
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


def test_user_can_generate_structured_ai_report(
    client: TestClient,
    fake_ai_provider: FakeInvestigationProvider,
) -> None:
    _, headers = register_and_login(
        client,
        "ai_report",
    )

    analysis_id = submit_analysis(
        client,
        headers,
    )

    response = client.post(
        f"/analysis/history/{analysis_id}/ai-report",
        headers=headers,
    )

    assert response.status_code == 201

    body = response.json()

    assert body["analysis_id"] == analysis_id
    assert body["status"] == "completed"
    assert body["provider"] == "fake"
    assert body["model"] == "fake-investigator-v1"

    assert body["report"] is not None

    assert (
        body["report"]["risk_level"]
        == "high"
    )

    assert (
        body["report"]["risk_score"]
        == 82
    )

    assert (
        body["report"]["confidence"]
        == 0.94
    )

    assert (
        body["report"][
            "mitre_assessment"
        ][0]["technique_id"]
        == "T1110.001"
    )

    assert body["grounding"] is not None

    grounded_ids = {
        technique["technique_id"]
        for technique
        in body["grounding"]["techniques"]
    }

    assert "T1110.001" in grounded_ids

    assert (
        body["grounding"]["attack_version"]
        == "test"
    )


def test_generated_report_can_be_retrieved(
    client: TestClient,
    fake_ai_provider: FakeInvestigationProvider,
) -> None:
    _, headers = register_and_login(
        client,
        "saved_report",
    )

    analysis_id = submit_analysis(
        client,
        headers,
    )

    creation_response = client.post(
        f"/analysis/history/{analysis_id}/ai-report",
        headers=headers,
    )

    assert creation_response.status_code == 201

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

    assert (
        retrieval_body["grounding"]
        == creation_body["grounding"]
    )


def test_ai_report_requires_authentication(
    client: TestClient,
    fake_ai_provider: FakeInvestigationProvider,
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


def test_user_cannot_generate_report_for_another_user(
    client: TestClient,
    fake_ai_provider: FakeInvestigationProvider,
) -> None:
    _, owner_headers = register_and_login(
        client,
        "ai_owner",
    )

    _, other_headers = register_and_login(
        client,
        "ai_other",
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


def test_admin_can_generate_report_for_any_analysis(
    client: TestClient,
    fake_ai_provider: FakeInvestigationProvider,
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

    assert response.status_code == 201

    body = response.json()

    assert body["status"] == "completed"
    assert body["grounding"] is not None


def test_provider_failure_is_recorded(
    client: TestClient,
) -> None:
    provider = (
        UnavailableInvestigationProvider()
    )

    app.dependency_overrides[
        get_ai_provider
    ] = lambda: provider

    try:
        _, headers = register_and_login(
            client,
            "failed_report",
        )

        analysis_id = submit_analysis(
            client,
            headers,
        )

        generation_response = client.post(
            f"/analysis/history/{analysis_id}/ai-report",
            headers=headers,
        )

        assert (
            generation_response.status_code
            == 503
        )

        retrieval_response = client.get(
            f"/analysis/history/{analysis_id}/ai-report",
            headers=headers,
        )
    finally:
        app.dependency_overrides.pop(
            get_ai_provider,
            None,
        )

    assert retrieval_response.status_code == 200

    body = retrieval_response.json()

    assert body["status"] == "failed"
    assert body["report"] is None


def test_missing_report_returns_not_found(
    client: TestClient,
    fake_ai_provider: FakeInvestigationProvider,
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


def test_ai_cannot_reference_unretrieved_attack_technique(
    client: TestClient,
) -> None:
    provider = (
        HallucinatingInvestigationProvider()
    )

    app.dependency_overrides[
        get_ai_provider
    ] = lambda: provider

    try:
        _, headers = register_and_login(
            client,
            "grounding_attack",
        )

        analysis_id = submit_analysis(
            client,
            headers,
        )

        response = client.post(
            (
                f"/analysis/history/"
                f"{analysis_id}/ai-report"
            ),
            headers=headers,
        )

        assert response.status_code == 502

        saved_response = client.get(
            (
                f"/analysis/history/"
                f"{analysis_id}/ai-report"
            ),
            headers=headers,
        )
    finally:
        app.dependency_overrides.pop(
            get_ai_provider,
            None,
        )

    assert saved_response.status_code == 200

    body = saved_response.json()

    assert body["status"] == "failed"
    assert body["report"] is None

    assert (
        "T1059"
        in body["error_message"]
    )