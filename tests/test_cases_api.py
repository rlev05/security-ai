from uuid import uuid4
from fastapi.testclient import TestClient
from app.api.auth_dependencies import get_current_user
from app.main import app
from app.models.case import CaseStatus, CaseSeverity, CaseTimelineEventType
from app.models.user import UserRole
from app.models.user_record import UserRecord

from uuid import uuid4

from fastapi.testclient import TestClient

from app.api.auth_dependencies import get_current_user
from app.main import app
from app.models.case import (
    CaseSeverity,
    CaseStatus,
    CaseTimelineEventType,
)
from app.models.user import UserRole
from app.models.user_record import UserRecord


PASSWORD = "CaseTests-StrongPassword-123!"

AUTH_LOG = """\
2026-08-20T10:00:00Z LOGIN_FAILURE user=alice ip=8.8.8.8
2026-08-20T10:01:00Z LOGIN_FAILURE user=alice ip=8.8.8.8
2026-08-20T10:02:00Z LOGIN_FAILURE user=alice ip=8.8.8.8
2026-08-20T10:03:00Z LOGIN_FAILURE user=alice ip=8.8.8.8
2026-08-20T10:04:00Z LOGIN_FAILURE user=alice ip=8.8.8.8
"""


def register_user(
    client: TestClient,
) -> dict:
    unique = uuid4().hex[:10]

    response = client.post(
        "/auth/register",
        json={
            "email": f"user-{unique}@example.com",
            "username": f"user_{unique}",
            "password": PASSWORD,
        },
    )

    assert response.status_code in {
        200,
        201,
    }, response.text

    return response.json()


def user_id_from_response(
    user: dict,
) -> str:
    user_id = (
        user.get("user_id")
        or user.get("id")
    )

    assert user_id is not None, user

    return user_id


def login_user(
    client: TestClient,
    user: dict,
) -> dict[str, str]:
    username = user.get("username")

    assert username is not None, user

    response = client.post(
        "/auth/token",
        data={
            "username": username,
            "password": PASSWORD,
        },
    )

    assert response.status_code == 200, response.text

    token = response.json()[
        "access_token"
    ]

    return {
        "Authorization": (
            f"Bearer {token}"
        )
    }


def create_authenticated_user(
    client: TestClient,
) -> tuple[dict, dict[str, str]]:
    user = register_user(
        client
    )

    headers = login_user(
        client,
        user,
    )

    return user, headers


def create_case(
    client: TestClient,
    headers: dict[str, str],
    *,
    title: str = "Suspicious authentication activity",
    description: str | None = (
        "Investigate repeated authentication failures."
    ),
    severity: str = CaseSeverity.HIGH.value,
    assigned_to_user_id: str | None = None,
) -> dict:
    response = client.post(
        "/cases",
        headers=headers,
        json={
            "title": title,
            "description": description,
            "severity": severity,
            "assigned_to_user_id": (
                assigned_to_user_id
            ),
        },
    )

    assert response.status_code == 201, response.text

    return response.json()


def create_analysis(
    client: TestClient,
    headers: dict[str, str],
) -> str:
    response = client.post(
        "/analysis/auth-log",
        headers=headers,
        json={
            "content": AUTH_LOG,
            "source_name": (
                "case-test-auth.log"
            ),
        },
    )

    assert response.status_code == 200, response.text

    result = response.json()

    analysis_id = (
        result.get("analysis_id")
        or result.get("id")
    )

    if analysis_id is not None:
        return analysis_id

    history_response = client.get(
        "/analysis/history",
        headers=headers,
    )

    assert (
        history_response.status_code
        == 200
    ), history_response.text

    history = history_response.json()

    assert history

    latest = history[0]

    analysis_id = (
        latest.get("analysis_id")
        or latest.get("id")
    )

    assert analysis_id is not None, latest

    return analysis_id


def test_user_can_create_and_view_case(
    client: TestClient,
):
    user, headers = (
        create_authenticated_user(
            client
        )
    )

    user_id = (
        user_id_from_response(
            user
        )
    )

    created = create_case(
        client,
        headers,
    )

    assert created["title"] == (
        "Suspicious authentication activity"
    )

    assert (
        created["severity"]
        == CaseSeverity.HIGH.value
    )

    assert (
        created["status"]
        == CaseStatus.OPEN.value
    )

    assert (
        created["created_by_user_id"]
        == user_id
    )

    case_id = created[
        "case_id"
    ]

    response = client.get(
        f"/cases/{case_id}",
        headers=headers,
    )

    assert response.status_code == 200

    detail = response.json()

    assert (
        detail["case_id"]
        == case_id
    )

    assert detail["analyses"] == []
    assert detail["notes"] == []

    assert len(
        detail["timeline"]
    ) == 1

    assert (
        detail["timeline"][0][
            "event_type"
        ]
        == CaseTimelineEventType.CASE_CREATED.value
    )


def test_other_user_cannot_view_case(
    client: TestClient,
):
    _, owner_headers = (
        create_authenticated_user(
            client
        )
    )

    _, other_headers = (
        create_authenticated_user(
            client
        )
    )

    case = create_case(
        client,
        owner_headers,
    )

    response = client.get(
        f"/cases/{case['case_id']}",
        headers=other_headers,
    )

    assert response.status_code == 404


def test_user_can_link_own_analysis_to_case(
    client: TestClient,
):
    _, headers = (
        create_authenticated_user(
            client
        )
    )

    analysis_id = create_analysis(
        client,
        headers,
    )

    case = create_case(
        client,
        headers,
    )

    response = client.post(
        (
            f"/cases/{case['case_id']}"
            "/analyses"
        ),
        headers=headers,
        json={
            "analysis_id": analysis_id,
        },
    )

    assert response.status_code == 200, response.text

    detail = response.json()

    assert len(
        detail["analyses"]
    ) == 1

    assert (
        detail["analyses"][0][
            "analysis_id"
        ]
        == analysis_id
    )

    event_types = {
        event["event_type"]
        for event
        in detail["timeline"]
    }

    assert (
        CaseTimelineEventType.ANALYSIS_LINKED.value
        in event_types
    )


def test_duplicate_analysis_link_returns_conflict(
    client: TestClient,
):
    _, headers = (
        create_authenticated_user(
            client
        )
    )

    analysis_id = create_analysis(
        client,
        headers,
    )

    case = create_case(
        client,
        headers,
    )

    path = (
        f"/cases/{case['case_id']}"
        "/analyses"
    )

    request = {
        "analysis_id": analysis_id,
    }

    first = client.post(
        path,
        headers=headers,
        json=request,
    )

    assert first.status_code == 200

    duplicate = client.post(
        path,
        headers=headers,
        json=request,
    )

    assert (
        duplicate.status_code
        == 409
    )


def test_user_cannot_link_another_users_analysis(
    client: TestClient,
):
    _, owner_headers = (
        create_authenticated_user(
            client
        )
    )

    _, other_headers = (
        create_authenticated_user(
            client
        )
    )

    case = create_case(
        client,
        owner_headers,
    )

    other_analysis_id = (
        create_analysis(
            client,
            other_headers,
        )
    )

    response = client.post(
        (
            f"/cases/{case['case_id']}"
            "/analyses"
        ),
        headers=owner_headers,
        json={
            "analysis_id": (
                other_analysis_id
            ),
        },
    )

    assert response.status_code == 404


def test_assigned_user_can_access_case(
    client: TestClient,
):
    _, owner_headers = (
        create_authenticated_user(
            client
        )
    )

    analyst, analyst_headers = (
        create_authenticated_user(
            client
        )
    )

    analyst_id = (
        user_id_from_response(
            analyst
        )
    )

    case = create_case(
        client,
        owner_headers,
    )

    assignment = client.patch(
        (
            f"/cases/{case['case_id']}"
            "/assignment"
        ),
        headers=owner_headers,
        json={
            "assigned_to_user_id": (
                analyst_id
            ),
        },
    )

    assert assignment.status_code == 200

    assert (
        assignment.json()[
            "assigned_to_user_id"
        ]
        == analyst_id
    )

    response = client.get(
        f"/cases/{case['case_id']}",
        headers=analyst_headers,
    )

    assert response.status_code == 200


def test_assigned_user_can_add_case_note(
    client: TestClient,
):
    _, owner_headers = (
        create_authenticated_user(
            client
        )
    )

    analyst, analyst_headers = (
        create_authenticated_user(
            client
        )
    )

    analyst_id = (
        user_id_from_response(
            analyst
        )
    )

    case = create_case(
        client,
        owner_headers,
        assigned_to_user_id=(
            analyst_id
        ),
    )

    response = client.post(
        (
            f"/cases/{case['case_id']}"
            "/notes"
        ),
        headers=analyst_headers,
        json={
            "content": (
                "Confirmed repeated failures "
                "originated from one source IP."
            ),
        },
    )

    assert response.status_code == 201, response.text

    note = response.json()

    assert (
        note["author_user_id"]
        == analyst_id
    )

    detail_response = client.get(
        f"/cases/{case['case_id']}",
        headers=owner_headers,
    )

    assert detail_response.status_code == 200

    detail = detail_response.json()

    assert len(
        detail["notes"]
    ) == 1

    assert (
        detail["notes"][0][
            "content"
        ]
        == (
            "Confirmed repeated failures "
            "originated from one source IP."
        )
    )

    event_types = {
        event["event_type"]
        for event
        in detail["timeline"]
    }

    assert (
        CaseTimelineEventType.NOTE_ADDED.value
        in event_types
    )


def test_status_and_severity_changes_are_tracked(
    client: TestClient,
):
    _, headers = (
        create_authenticated_user(
            client
        )
    )

    case = create_case(
        client,
        headers,
        severity=(
            CaseSeverity.MEDIUM.value
        ),
    )

    case_id = case[
        "case_id"
    ]

    status_response = client.patch(
        f"/cases/{case_id}/status",
        headers=headers,
        json={
            "status": (
                CaseStatus.INVESTIGATING.value
            ),
        },
    )

    assert (
        status_response.status_code
        == 200
    )

    assert (
        status_response.json()[
            "status"
        ]
        == CaseStatus.INVESTIGATING.value
    )

    severity_response = client.patch(
        f"/cases/{case_id}/severity",
        headers=headers,
        json={
            "severity": (
                CaseSeverity.CRITICAL.value
            ),
        },
    )

    assert (
        severity_response.status_code
        == 200
    )

    assert (
        severity_response.json()[
            "severity"
        ]
        == CaseSeverity.CRITICAL.value
    )

    detail_response = client.get(
        f"/cases/{case_id}",
        headers=headers,
    )

    assert detail_response.status_code == 200

    event_types = [
        event["event_type"]
        for event
        in detail_response.json()[
            "timeline"
        ]
    ]

    assert (
        CaseTimelineEventType.STATUS_CHANGED.value
        in event_types
    )

    assert (
        CaseTimelineEventType.SEVERITY_CHANGED.value
        in event_types
    )


def test_closing_case_sets_closed_at(
    client: TestClient,
):
    _, headers = (
        create_authenticated_user(
            client
        )
    )

    case = create_case(
        client,
        headers,
    )

    response = client.patch(
        (
            f"/cases/{case['case_id']}"
            "/status"
        ),
        headers=headers,
        json={
            "status": (
                CaseStatus.CLOSED.value
            ),
        },
    )

    assert response.status_code == 200

    updated = response.json()

    assert (
        updated["status"]
        == CaseStatus.CLOSED.value
    )

    assert (
        updated["closed_at"]
        is not None
    )


def test_admin_can_access_another_users_case(
    client: TestClient,
):
    _, owner_headers = (
        create_authenticated_user(
            client
        )
    )

    case = create_case(
        client,
        owner_headers,
    )

    admin = UserRecord(
        id=str(uuid4()),
        email=(
            f"admin-{uuid4().hex[:8]}"
            "@example.com"
        ),
        username=(
            f"admin_{uuid4().hex[:8]}"
        ),
        password_hash="unused",
        role=UserRole.ADMIN.value,
        is_active=True,
    )

    def override_current_user() -> UserRecord:
        return admin

    app.dependency_overrides[
        get_current_user
    ] = override_current_user

    try:
        response = client.get(
            f"/cases/{case['case_id']}"
        )

        assert (
            response.status_code
            == 200
        )

        assert (
            response.json()[
                "case_id"
            ]
            == case["case_id"]
        )

    finally:
        app.dependency_overrides.pop(
            get_current_user,
            None,
        )

