from uuid import uuid4

from fastapi.testclient import TestClient


PASSWORD = (
    "Dashboard-Test-Password-123!"
)


def register_user(
    client: TestClient,
) -> tuple[str, str]:
    unique = uuid4().hex[:10]

    username = (
        f"dashboard_{unique}"
    )

    email = (
        f"{username}@example.com"
    )

    response = client.post(
        "/auth/register",
        json={
            "email": email,
            "username": username,
            "password": PASSWORD,
        },
    )

    assert response.status_code == 201

    return username, email


def test_dashboard_redirects_to_login_when_unauthenticated(
    client: TestClient,
) -> None:
    response = client.get(
        "/dashboard",
        follow_redirects=False,
    )

    assert response.status_code == 303

    assert (
        response.headers["location"]
        == "/login"
    )


def test_user_can_login_to_dashboard(
    client: TestClient,
) -> None:
    username, _ = register_user(
        client
    )

    response = client.post(
        "/login",
        data={
            "login": username,
            "password": PASSWORD,
        },
        follow_redirects=False,
    )

    assert response.status_code == 303

    assert (
        response.headers["location"]
        == "/dashboard"
    )

    assert (
        "security_ai_session"
        in response.cookies
    )


def test_dashboard_displays_authenticated_user(
    client: TestClient,
) -> None:
    username, _ = register_user(
        client
    )

    login_response = client.post(
        "/login",
        data={
            "login": username,
            "password": PASSWORD,
        },
        follow_redirects=False,
    )

    assert (
        login_response.status_code
        == 303
    )

    response = client.get(
        "/dashboard"
    )

    assert response.status_code == 200

    assert username in response.text

    assert (
        "Recent Analyses"
        in response.text
    )


def test_invalid_dashboard_login_is_rejected(
    client: TestClient,
) -> None:
    username, _ = register_user(
        client
    )

    response = client.post(
        "/login",
        data={
            "login": username,
            "password": (
                "wrong-password"
            ),
        },
        follow_redirects=False,
    )

    assert response.status_code == 401

    assert (
        "Incorrect username"
        in response.text
    )


def test_dashboard_logout_removes_session(
    client: TestClient,
) -> None:
    username, _ = register_user(
        client
    )

    client.post(
        "/login",
        data={
            "login": username,
            "password": PASSWORD,
        },
    )

    response = client.post(
        "/logout",
        follow_redirects=False,
    )

    assert response.status_code == 303

    assert (
        response.headers["location"]
        == "/login"
    )

    dashboard_response = client.get(
        "/dashboard",
        follow_redirects=False,
    )

    assert (
        dashboard_response.status_code
        == 303
    )