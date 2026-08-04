from fastapi.testclient import TestClient


BRUTE_FORCE_LOG = """
2026-08-01T12:00:00 Failed password for admin from 192.168.1.5
2026-08-01T12:01:00 Failed password for admin from 192.168.1.5
2026-08-01T12:02:00 Failed password for admin from 192.168.1.5
2026-08-01T12:03:00 Failed password for admin from 192.168.1.5
2026-08-01T12:04:00 Failed password for admin from 192.168.1.5
"""


def store_analysis(
    analysis_client: TestClient,
) -> str:
    """Submit and store an analysis using an authenticated user."""

    response = analysis_client.post(
        "/analysis/auth-log",
        json={
            "content": BRUTE_FORCE_LOG,
        },
    )

    assert response.status_code == 200

    return response.json()["analysis_id"]


def test_retrieves_stored_analysis(
    analysis_client: TestClient,
) -> None:
    analysis_id = store_analysis(analysis_client)

    response = analysis_client.get(
        f"/analysis/history/{analysis_id}",
    )

    assert response.status_code == 200

    body = response.json()

    assert body["analysis_id"] == analysis_id
    assert body["source_type"] == "text"
    assert body["source_name"] is None
    assert body["total_lines"] == 5
    assert body["ignored_lines"] == 0
    assert body["event_count"] == 5
    assert body["incident_count"] >= 1
    assert "result" in body


def test_lists_analysis_history(
    analysis_client: TestClient,
) -> None:
    first_id = store_analysis(analysis_client)
    second_id = store_analysis(analysis_client)

    response = analysis_client.get(
        "/analysis/history",
    )

    assert response.status_code == 200

    records = response.json()

    record_ids = {
        record["analysis_id"]
        for record in records
    }

    assert first_id in record_ids
    assert second_id in record_ids


def test_missing_analysis_returns_not_found(
    analysis_client: TestClient,
) -> None:
    response = analysis_client.get(
        "/analysis/history/missing-analysis-id",
    )

    assert response.status_code == 404
    assert response.json() == {
        "detail": "Analysis record not found.",
    }