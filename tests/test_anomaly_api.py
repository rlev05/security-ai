from datetime import (
    datetime,
    timedelta,
    timezone,
)
from uuid import uuid4

from fastapi.testclient import (
    TestClient,
)


PASSWORD = (
    "AnomalyTests-StrongPassword-123!"
)


def register_and_login(
    client: TestClient,
) -> dict[str, str]:
    unique = uuid4().hex[:10]

    username = (
        f"anomaly_{unique}"
    )

    email = (
        f"{username}@example.com"
    )

    register_response = client.post(
        "/auth/register",
        json={
            "email": email,
            "username": username,
            "password": PASSWORD,
        },
    )

    assert register_response.status_code in {
        200,
        201,
    }, register_response.text

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

    token = token_response.json()[
        "access_token"
    ]

    return {
        "Authorization": (
            f"Bearer {token}"
        )
    }


def build_auth_log(
    *,
    normal_events: int = 60,
    anomalous_events: int = 8,
) -> str:
    lines: list[str] = []

    start = datetime(
        2026,
        8,
        20,
        9,
        0,
        tzinfo=timezone.utc,
    )

    for index in range(
        normal_events
    ):
        timestamp = (
            start
            + timedelta(
                minutes=index,
            )
        )

        username = (
            f"user{index % 5}"
        )

        ip_address = (
            f"192.0.2."
            f"{10 + (index % 5)}"
        )

        lines.append(
            (
                f"{timestamp.strftime('%Y-%m-%dT%H:%M:%S')} "
                f"Accepted password for {username} "
                f"from {ip_address}"
            )
        )

    attack_start = datetime(
        2026,
        8,
        20,
        3,
        0,
        tzinfo=timezone.utc,
    )

    for index in range(
        anomalous_events
    ):
        timestamp = (
            attack_start
            + timedelta(
                seconds=index,
            )
        )

        lines.append(
            (
                f"{timestamp.strftime('%Y-%m-%dT%H:%M:%S')} "
                f"Failed password for target{index} "
                "from 203.0.113.250"
            )
        )

    return "\n".join(
        lines
    )


def create_analysis(
    client: TestClient,
    headers: dict[str, str],
    content: str,
) -> str:
    response = client.post(
        "/analysis/auth-log",
        headers=headers,
        json={
            "content": content,
        },
    )

    assert (
        response.status_code
        == 200
    ), response.text

    body = response.json()

    analysis_id = (
        body.get("analysis_id")
        or body.get("id")
    )

    assert analysis_id is not None

    return analysis_id


def test_user_can_create_anomaly_run(
    client: TestClient,
):
    headers = register_and_login(
        client
    )

    analysis_id = create_analysis(
        client,
        headers,
        build_auth_log(),
    )

    response = client.post(
        (
            f"/analysis/{analysis_id}"
            "/anomalies"
        ),
        headers=headers,
    )

    assert (
        response.status_code
        == 201
    ), response.text

    body = response.json()

    assert body["id"]

    assert (
        body["analysis_id"]
        == analysis_id
    )

    result = body["result"]

    assert (
        result["model_name"]
        == "IsolationForest"
    )

    assert (
        result["total_events"]
        == 68
    )

    assert (
        result["analysed_events"]
        == 68
    )

    assert (
        result["anomaly_count"]
        > 0
    )

    assert (
        result["anomalies"]
    )


def test_get_returns_saved_run_without_retraining(
    client: TestClient,
):
    headers = register_and_login(
        client
    )

    analysis_id = create_analysis(
        client,
        headers,
        build_auth_log(),
    )

    create_response = client.post(
        (
            f"/analysis/{analysis_id}"
            "/anomalies"
            "?contamination=0.1"
        ),
        headers=headers,
    )

    assert (
        create_response.status_code
        == 201
    )

    created = (
        create_response.json()
    )

    get_response = client.get(
        (
            f"/analysis/{analysis_id}"
            "/anomalies"
        ),
        headers=headers,
    )

    assert (
        get_response.status_code
        == 200
    ), get_response.text

    loaded = get_response.json()

    assert (
        loaded["id"]
        == created["id"]
    )

    assert (
        loaded["created_at"]
        == created["created_at"]
    )

    assert (
        loaded["result"]
        == created["result"]
    )


def test_get_returns_404_before_model_has_run(
    client: TestClient,
):
    headers = register_and_login(
        client
    )

    analysis_id = create_analysis(
        client,
        headers,
        build_auth_log(),
    )

    response = client.get(
        (
            f"/analysis/{analysis_id}"
            "/anomalies"
        ),
        headers=headers,
    )

    assert (
        response.status_code
        == 404
    )


def test_small_analysis_run_is_persisted(
    client: TestClient,
):
    headers = register_and_login(
        client
    )

    analysis_id = create_analysis(
        client,
        headers,
        build_auth_log(
            normal_events=10,
            anomalous_events=0,
        ),
    )

    response = client.post(
        (
            f"/analysis/{analysis_id}"
            "/anomalies"
        ),
        headers=headers,
    )

    assert (
        response.status_code
        == 201
    ), response.text

    result = response.json()[
        "result"
    ]

    assert (
        result["total_events"]
        == 10
    )

    assert (
        result["analysed_events"]
        == 0
    )

    assert (
        result["anomaly_count"]
        == 0
    )

    assert (
        result["skipped_reason"]
        is not None
    )


def test_history_lists_multiple_runs(
    client: TestClient,
):
    headers = register_and_login(
        client
    )

    analysis_id = create_analysis(
        client,
        headers,
        build_auth_log(),
    )

    first = client.post(
        (
            f"/analysis/{analysis_id}"
            "/anomalies"
            "?contamination=0.05"
        ),
        headers=headers,
    )

    second = client.post(
        (
            f"/analysis/{analysis_id}"
            "/anomalies"
            "?contamination=0.1"
        ),
        headers=headers,
    )

    assert first.status_code == 201
    assert second.status_code == 201

    response = client.get(
        (
            f"/analysis/{analysis_id}"
            "/anomalies/history"
        ),
        headers=headers,
    )

    assert (
        response.status_code
        == 200
    ), response.text

    history = response.json()

    assert len(history) == 2

    ids = {
        item["id"]
        for item in history
    }

    assert first.json()["id"] in ids
    assert second.json()["id"] in ids


def test_user_cannot_run_model_on_another_users_analysis(
    client: TestClient,
):
    owner_headers = (
        register_and_login(
            client
        )
    )

    other_headers = (
        register_and_login(
            client
        )
    )

    analysis_id = create_analysis(
        client,
        owner_headers,
        build_auth_log(),
    )

    response = client.post(
        (
            f"/analysis/{analysis_id}"
            "/anomalies"
        ),
        headers=other_headers,
    )

    assert (
        response.status_code
        == 404
    )


def test_user_cannot_read_another_users_anomaly_runs(
    client: TestClient,
):
    owner_headers = (
        register_and_login(
            client
        )
    )

    other_headers = (
        register_and_login(
            client
        )
    )

    analysis_id = create_analysis(
        client,
        owner_headers,
        build_auth_log(),
    )

    created = client.post(
        (
            f"/analysis/{analysis_id}"
            "/anomalies"
        ),
        headers=owner_headers,
    )

    assert (
        created.status_code
        == 201
    )

    latest_response = client.get(
        (
            f"/analysis/{analysis_id}"
            "/anomalies"
        ),
        headers=other_headers,
    )

    history_response = client.get(
        (
            f"/analysis/{analysis_id}"
            "/anomalies/history"
        ),
        headers=other_headers,
    )

    assert (
        latest_response.status_code
        == 404
    )

    assert (
        history_response.status_code
        == 404
    )


def test_anomaly_endpoints_require_authentication(
    client: TestClient,
):
    headers = register_and_login(
        client
    )

    analysis_id = create_analysis(
        client,
        headers,
        build_auth_log(),
    )

    run_response = client.post(
        (
            f"/analysis/{analysis_id}"
            "/anomalies"
        )
    )

    latest_response = client.get(
        (
            f"/analysis/{analysis_id}"
            "/anomalies"
        )
    )

    assert (
        run_response.status_code
        == 401
    )

    assert (
        latest_response.status_code
        == 401
    )


def test_invalid_contamination_is_rejected(
    client: TestClient,
):
    headers = register_and_login(
        client
    )

    analysis_id = create_analysis(
        client,
        headers,
        build_auth_log(),
    )

    response = client.post(
        (
            f"/analysis/{analysis_id}"
            "/anomalies"
            "?contamination=0.5"
        ),
        headers=headers,
    )

    assert (
        response.status_code
        == 422
    )