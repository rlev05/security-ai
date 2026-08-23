from fastapi.testclient import TestClient
from app.core.config import Settings


JWT_SECRET = (
    "a" * 64
)


def test_health_endpoint(
    client: TestClient,
) -> None:
    response = client.get(
        "/health"
    )

    assert (
        response.status_code
        == 200
    )

    assert response.json() == {
        "status": "healthy",
    }


def test_security_headers_are_added(
    client: TestClient,
) -> None:
    response = client.get(
        "/dashboard",
        follow_redirects=False,
    )

    assert (
        response.headers[
            "x-content-type-options"
        ]
        == "nosniff"
    )

    assert (
        response.headers[
            "x-frame-options"
        ]
        == "DENY"
    )

    assert (
        response.headers[
            "referrer-policy"
        ]
        == "no-referrer"
    )

    assert (
        "camera=()"
        in response.headers[
            "permissions-policy"
        ]
    )

    assert (
        "default-src 'self'"
        in response.headers[
            "content-security-policy"
        ]
    )

    assert (
        response.headers[
            "cache-control"
        ]
        == "no-store, max-age=0"
    )


def test_development_cookies_are_not_secure(
) -> None:
    settings = Settings(
        _env_file=None,
        database_url=(
            "postgresql+psycopg://"
            "user:password@localhost/test"
        ),
        jwt_secret_key=JWT_SECRET,
        app_environment="development",
    )

    assert (
        settings.dashboard_cookie_secure
        is False
    )


def test_test_environment_cookies_are_not_secure(
) -> None:
    settings = Settings(
        _env_file=None,
        database_url=(
            "postgresql+psycopg://"
            "user:password@localhost/test"
        ),
        jwt_secret_key=JWT_SECRET,
        app_environment="test",
    )

    assert (
        settings.dashboard_cookie_secure
        is False
    )


def test_production_cookies_are_secure(
) -> None:
    settings = Settings(
        _env_file=None,
        database_url=(
            "postgresql+psycopg://"
            "user:password@localhost/test"
        ),
        jwt_secret_key=JWT_SECRET,
        app_environment="production",
    )

    assert (
        settings.dashboard_cookie_secure
        is True
    )