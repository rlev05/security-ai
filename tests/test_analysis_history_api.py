from fastapi.testclient import TestClient


BRUTE_FORCE_LOG = """
2026-08-01T12:00:00 Failed password for admin from 192.168.1.5
2026-08-01T12:01:00 Failed password for admin from 192.168.1.5
2026-08-01T12:02:00 Failed password for admin from 192.168.1.5
2026-08-01T12:03:00 Failed password for admin from 192.168.1.5
2026-08-01T12:04:00 Failed password for admin from 192.168.1.5
"""


def store_analysis(
    client: TestClient,
) -> str:
    response = client.post(
        "/analysis/auth-log",
        json={
            "content": BRUTE_FORCE_LOG,
        },
    )

    assert response.status_code == 200

    return response.json()["analysis_id"]


def test_retrieves_stored_analysis(
    client: TestClient,
) -> None:
    analysis_id = store_analysis(client)

    response = client.get(
        f"/analysis/history/{analysis_id}",
    )

    assert response.status_code == 200

    data = response.json()

    assert data["analysis_id"] == analysis_id
    assert data["source_type"] == "text"
    assert data["source_name"] is None
    assert data["event_count"] == 5
    assert data["incident_count"] == 1

    stored_alert = (
        data["result"]["incidents"][0]["alerts"][0]
    )

    assert (
        stored_alert["rule_id"]
        == "AUTH-BRUTE-FORCE-001"
    )


def test_lists_analysis_history(
    client: TestClient,
) -> None:
    first_id = store_analysis(client)
    second_id = store_analysis(client)

    response = client.get(
        "/analysis/history",
    )

    assert response.status_code == 200

    records = response.json()

    record_ids = {
        record["analysis_id"]
        for record in records
    }

    assert len(records) == 2
    assert first_id in record_ids
    assert second_id in record_ids

    assert all(
        record["event_count"] == 5
        for record in records
    )

    assert all(
        record["incident_count"] == 1
        for record in records
    )


def test_returns_not_found_for_unknown_analysis(
    client: TestClient,
) -> None:
    response = client.get(
        "/analysis/history/"
        "00000000-0000-0000-0000-000000000000",
    )

    assert response.status_code == 404
    assert response.json()["detail"] == (
        "Analysis record not found."
    )