from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_analysis_endpoint_detects_brute_force() -> None:
    content = """
    2026-08-01T12:00:00 Failed password for admin from 192.168.1.5
    2026-08-01T12:01:00 Failed password for admin from 192.168.1.5
    2026-08-01T12:02:00 Failed password for admin from 192.168.1.5
    2026-08-01T12:03:00 Failed password for admin from 192.168.1.5
    2026-08-01T12:04:00 Failed password for admin from 192.168.1.5
    """

    response = client.post(
        "/analysis/auth-log",
        json={"content": content},
    )

    assert response.status_code == 200

    body = response.json()

    assert body["total_lines"] == 5
    assert body["ignored_lines"] == 0
    assert len(body["events"]) == 5
    assert len(body["incidents"]) == 1
    assert body["incidents"][0]["alerts"][0]["severity"] =="high"

def test_analysis_endpoint_rejects_empty_content() -> None:
    response = client.post(
        "/analysis/auth-log",
        json={"content": "  "},
    )

    assert response.status_code == 422

