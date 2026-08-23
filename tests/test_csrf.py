from fastapi.testclient import (
    TestClient,
)


def test_cross_site_origin_is_rejected(
    client: TestClient,
) -> None:
    response = client.post(
        "/login",
        headers={
            "Origin": ("https://attacker.example"),
        },
        data={
            "login": "nobody",
            "password": "invalid",
        },
    )

    assert response.status_code == 403

    assert response.json() == {
        "detail": ("Cross-site dashboard " "request rejected."),
    }


def test_cross_site_fetch_metadata_is_rejected(
    client: TestClient,
) -> None:
    response = client.post(
        "/logout",
        headers={
            "Sec-Fetch-Site": ("cross-site"),
        },
        follow_redirects=False,
    )

    assert response.status_code == 403


def test_cross_site_referer_is_rejected(
    client: TestClient,
) -> None:
    response = client.post(
        "/login",
        headers={
            "Referer": ("https://attacker.example/" "malicious-form"),
        },
        data={
            "login": "nobody",
            "password": "invalid",
        },
    )

    assert response.status_code == 403


def test_same_origin_request_is_allowed(
    client: TestClient,
) -> None:
    response = client.post(
        "/login",
        headers={
            "Origin": ("http://testserver"),
            "Sec-Fetch-Site": ("same-origin"),
        },
        data={
            "login": "nobody",
            "password": "invalid",
        },
    )

    # Authentication should fail normally.
    # The CSRF middleware must not reject it.
    assert response.status_code == 401


def test_bearer_api_is_not_subject_to_dashboard_csrf(
    client: TestClient,
) -> None:
    response = client.post(
        "/auth/token",
        headers={
            "Origin": ("https://attacker.example"),
            "Sec-Fetch-Site": ("cross-site"),
        },
        data={
            "username": "nobody",
            "password": "invalid",
        },
    )

    # The authentication endpoint may reject the credentials,
    # but it must not be rejected by dashboard CSRF middleware.
    assert response.status_code != 403
