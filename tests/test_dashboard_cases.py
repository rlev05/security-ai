from uuid import uuid4
from fastapi.testclient import TestClient

PASSWORD = (
    "Dashboard-Cases-Password-123!"
)


def register_user_and_token(
    client: TestClient,
) -> tuple[str, str]:
    unique = uuid4().hex[:10]

    username = (
        f"cases_{unique}"
    )

    response = client.post(
        "/auth/register",
        json={
            "email": (
                f"{username}@example.com"
            ),
            "username": username,
            "password": PASSWORD,
        },
    )

    assert (
        response.status_code
        == 201
    ), response.text

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

    return (
        username,
        token_response.json()[
            "access_token"
        ],
    )


def login_dashboard(
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


def headers(
    token: str,
) -> dict[str, str]:
    return {
        "Authorization": (
            f"Bearer {token}"
        )
    }


def create_case_via_api(
    client: TestClient,
    *,
    token: str,
    title: str,
) -> str:
    response = client.post(
        "/cases",
        headers=headers(
            token
        ),
        json={
            "title": title,
            "description": (
                "Dashboard test case"
            ),
            "severity": "medium",
        },
    )

    assert (
        response.status_code
        == 201
    ), response.text

    return response.json()[
        "case_id"
    ]


def test_cases_page_requires_authentication(
    client: TestClient,
) -> None:
    response = client.get(
        "/dashboard/cases",
        follow_redirects=False,
    )

    assert response.status_code == 303

    assert (
        response.headers["location"]
        == "/login"
    )


def test_cases_page_lists_visible_cases(
    client: TestClient,
) -> None:
    username, token = (
        register_user_and_token(
            client
        )
    )

    title = (
        "Credential compromise investigation"
    )

    create_case_via_api(
        client,
        token=token,
        title=title,
    )

    login_dashboard(
        client,
        username=username,
    )

    response = client.get(
        "/dashboard/cases"
    )

    assert response.status_code == 200
    assert title in response.text
    assert "Investigation Cases" in response.text


def test_dashboard_can_create_case(
    client: TestClient,
) -> None:
    username, token = (
        register_user_and_token(
            client
        )
    )

    login_dashboard(
        client,
        username=username,
    )

    response = client.post(
        "/dashboard/cases/create",
        data={
            "title": (
                "New dashboard case"
            ),
            "description": (
                "Created from the UI."
            ),
            "severity": "high",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303

    location = (
        response.headers["location"]
    )

    assert location.startswith(
        "/dashboard/cases/"
    )

    api_response = client.get(
        "/cases",
        headers=headers(
            token
        ),
    )

    assert api_response.status_code == 200

    assert any(
        case["title"]
        == "New dashboard case"
        for case
        in api_response.json()
    )


def test_case_dashboard_updates_workflow_and_notes(
    client: TestClient,
) -> None:
    username, token = (
        register_user_and_token(
            client
        )
    )

    case_id = create_case_via_api(
        client,
        token=token,
        title="Workflow test case",
    )

    login_dashboard(
        client,
        username=username,
    )

    severity_response = client.post(
        (
            f"/dashboard/cases/"
            f"{case_id}/actions/severity"
        ),
        data={
            "severity": "critical",
        },
    )

    assert (
        severity_response.status_code
        == 200
    )

    assert (
        "critical"
        in severity_response.text.lower()
    )

    status_response = client.post(
        (
            f"/dashboard/cases/"
            f"{case_id}/actions/status"
        ),
        data={
            "status": "investigating",
        },
    )

    assert (
        status_response.status_code
        == 200
    )

    note_response = client.post(
        (
            f"/dashboard/cases/"
            f"{case_id}/actions/note"
        ),
        data={
            "content": (
                "Reviewed authentication "
                "evidence and escalated."
            ),
        },
    )

    assert (
        note_response.status_code
        == 200
    )

    assert (
        "Reviewed authentication"
        in note_response.text
    )

    api_response = client.get(
        f"/cases/{case_id}",
        headers=headers(
            token
        ),
    )

    assert api_response.status_code == 200

    body = api_response.json()

    assert body["severity"] == "critical"
    assert body["status"] == "investigating"

    assert any(
        note["content"].startswith(
            "Reviewed authentication"
        )
        for note in body["notes"]
    )

    timeline_types = {
        event["event_type"]
        for event in body["timeline"]
    }

    assert "severity_changed" in timeline_types
    assert "status_changed" in timeline_types
    assert "note_added" in timeline_types


def test_case_dashboard_respects_visibility(
    client: TestClient,
) -> None:
    owner_username, owner_token = (
        register_user_and_token(
            client
        )
    )

    case_id = create_case_via_api(
        client,
        token=owner_token,
        title="Private investigation",
    )

    other_username, _ = (
        register_user_and_token(
            client
        )
    )

    assert (
        owner_username
        != other_username
    )

    login_dashboard(
        client,
        username=other_username,
    )

    response = client.get(
        (
            f"/dashboard/cases/"
            f"{case_id}"
        )
    )

    assert response.status_code == 404