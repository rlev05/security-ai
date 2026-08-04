from fastapi.testclient import TestClient

def build_user_payload(
        identifier: str,
) -> dict[str, str]:
    return {
        "email": f"{identifier}@example.com",
        "username": identifier,
        "password": "StrongPassword123!",
    }


def register_user(
        client: TestClient,
        identifier: str,
) -> dict[str, str]:
    payload = build_user_payload(identifier)

    response = client.post("/auth/register", json=payload)

    assert response.status_code == 201

    return payload


def test_register_user(
        client: TestClient,
) -> None:
    response = client.post("/auth/register", json=build_user_payload("register_user"),)

    assert response.status_code == 201

    body = response.json()
    assert body["email"] == "register_user@example.com"
    assert body["username"] == "register_user"
    assert body["role"] == "user"
    assert body["is_active"] == True
    assert "id" in body
    assert "password" not in body
    assert "password_hash" not in body


def test_registration_rejects_duplicate_email(
        client: TestClient,
) -> None:
    first_payload = build_user_payload("duplicate_email")

    first_reponse = client.post("/auth/register", json=first_payload)

    second_payload = {
        **build_user_payload("different_username"),
        "email": first_payload["email"],
    }

    second_response = client.post("/auth/register", json=second_payload)

    assert first_reponse.status_code == 201
    assert second_response.status_code == 409


def test_registration_rejects_duplicate_username(
        client: TestClient,
) -> None:

    first_payload = build_user_payload("duplicate_username")

    first_reponse = client.post("/auth/register", json=first_payload)

    second_payload = {
        **build_user_payload("different_email"),
        "username": first_payload["username"],
    }

    second_response = client.post("/auth/register", json=second_payload)

    assert first_reponse.status_code == 201
    assert second_response.status_code == 409


def test_user_can_log_in_with_email(
        client: TestClient,
) -> None:
    payload = register_user(
        client,
        "login_email",
    )

    response = client.post(
        "/auth/token",
        data={
            "username": payload["email"],
            "password": payload["password"],
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["token_type"] == "bearer"
    assert isinstance(
        body["access_token"],
        str,
    )
    assert body["access_token"]


def test_user_can_log_in_with_username(
        client: TestClient,
) -> None:
    payload = register_user(
        client,
        "login_username",
    )

    response = client.post(
        "/auth/token",
        data={
            "username": payload["username"],
            "password": payload["password"],
        },
    )

    assert response.status_code == 200
    assert response.json()["access_token"]

def test_login_rejects_incorrect_password(
        client: TestClient,
) -> None:
    payload = register_user(
        client,
        "incorrect_password"
    )

    response = client.post(
        "/auth/token",
        data={
            "username": payload["email"],
            "password": "ThisPasswordIsIncorrect!",
        },
    )

    assert response.status_code == 401

def test_login_rejects_unknown_user(
        client: TestClient,
) -> None:
    response = client.post(
        "/auth/token",
        data={
            "username": "missing@example.com",
            "password": "StrongPassword123!",
        }
    )

    assert response.status_code == 401


def test_authenticated_user_can_read_profile(
        client: TestClient,
) -> None:
    payload = register_user(
        client,
        "current_profile",
    )

    token_reponse = client.post(
        "/auth/token",
        data={
            "username": payload["username"],
            "password": payload["password"],
        }
    )

    assert token_reponse.status_code == 200

    access_token = token_reponse.json()["access_token"]

    profile_response = client.get(
        "/auth/me",
        headers={
            "Authorization": f"Bearer {access_token}",
        },
    )

    assert profile_response.status_code == 200

    body = profile_response.json()

    assert body["email"] == payload["email"]
    assert body["username"] == payload["username"]
    assert body["role"] == "user"


def test_profile_requires_authentication(
        client: TestClient,
) -> None:
    response = client.get("/auth/me")

    assert response.status_code == 401

def test_profile_rejects_invalid_token(
        client: TestClient,
) -> None:

    response = client.get("/auth/me",
                          headers={
                              "Authorization": "Bearer invalid-token",
                          },
                          )

    assert response.status_code == 401



