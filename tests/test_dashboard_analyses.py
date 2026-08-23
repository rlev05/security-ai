from uuid import uuid4
from fastapi.testclient import TestClient

PASSWORD = (
    "Dashboard-Analyses-Password-123!"
)


def register_user_and_token(
    client: TestClient,
) -> tuple[str, str]:
    unique = uuid4().hex[:10]

    username = (
        f"analyses_{unique}"
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

    assert (
        response.status_code
        == 303
    ), response.text


def auth_headers(
    token: str,
) -> dict[str, str]:
    return {
        "Authorization": (
            f"Bearer {token}"
        )
    }


def build_auth_log(
    *,
    username: str = "analyst",
    ip_address: str = "192.0.2.10",
) -> str:
    return (
        "2026-08-20T09:00:00Z "
        "LOGIN_SUCCESS "
        f"user={username} "
        f"ip={ip_address}"
    )


def create_file_analysis(
    client: TestClient,
    *,
    token: str,
    filename: str,
) -> str:
    response = client.post(
        "/analysis/auth-log/file",
        headers=auth_headers(
            token
        ),
        files={
            "file": (
                filename,
                build_auth_log(),
                "text/plain",
            )
        },
    )

    assert (
        response.status_code
        == 200
    ), response.text

    return response.json()[
        "analysis_id"
    ]


def test_analyses_page_requires_authentication(
    client: TestClient,
) -> None:
    response = client.get(
        "/dashboard/analyses",
        follow_redirects=False,
    )

    assert (
        response.status_code
        == 303
    )

    assert (
        response.headers["location"]
        == "/login"
    )


def test_analyses_page_lists_user_analyses(
    client: TestClient,
) -> None:
    username, token = (
        register_user_and_token(
            client
        )
    )

    analysis_id = create_file_analysis(
        client,
        token=token,
        filename="authentication.log",
    )

    login_dashboard(
        client,
        username=username,
    )

    response = client.get(
        "/dashboard/analyses"
    )

    assert (
        response.status_code
        == 200
    ), response.text

    assert (
        "Security Analyses"
        in response.text
    )

    assert (
        "authentication.log"
        in response.text
    )

    assert (
        analysis_id
        in response.text
    )

    assert (
        "Investigate"
        in response.text
    )


def test_analyses_page_supports_pagination(
    client: TestClient,
) -> None:
    username, token = (
        register_user_and_token(
            client
        )
    )

    create_file_analysis(
        client,
        token=token,
        filename="first.log",
    )

    create_file_analysis(
        client,
        token=token,
        filename="second.log",
    )

    create_file_analysis(
        client,
        token=token,
        filename="third.log",
    )

    login_dashboard(
        client,
        username=username,
    )

    first_page = client.get(
        (
            "/dashboard/analyses"
            "?page=1&page_size=2"
        )
    )

    assert (
        first_page.status_code
        == 200
    ), first_page.text

    assert (
        "third.log"
        in first_page.text
    )

    assert (
        "second.log"
        in first_page.text
    )

    assert (
        "first.log"
        not in first_page.text
    )

    assert (
        "Page"
        in first_page.text
    )

    second_page = client.get(
        (
            "/dashboard/analyses"
            "?page=2&page_size=2"
        )
    )

    assert (
        second_page.status_code
        == 200
    ), second_page.text

    assert (
        "first.log"
        in second_page.text
    )


def test_analyses_page_respects_ownership(
    client: TestClient,
) -> None:
    (
        owner_username,
        owner_token,
    ) = register_user_and_token(
        client
    )

    create_file_analysis(
        client,
        token=owner_token,
        filename="private-owner.log",
    )

    (
        other_username,
        other_token,
    ) = register_user_and_token(
        client
    )

    create_file_analysis(
        client,
        token=other_token,
        filename="other-user.log",
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
        "/dashboard/analyses"
    )

    assert (
        response.status_code
        == 200
    ), response.text

    assert (
        "other-user.log"
        in response.text
    )

    assert (
        "private-owner.log"
        not in response.text
    )