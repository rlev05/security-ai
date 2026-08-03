from fastapi.testclient import TestClient
from app.main import app


def test_analysis_endpoint_detects_brute_force(
        client: TestClient,
) -> None:
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

def test_analysis_endpoint_rejects_empty_content(
        client: TestClient,
) -> None:
    response = client.post(
        "/analysis/auth-log",
        json={"content": "  "},
    )

    assert response.status_code == 422

def test_file_upload_endpoint_detects_brute_force(
        client: TestClient,
) -> None:
    content = """
    2026-08-01T12:00:00 Failed password for admin from 192.168.1.5
    2026-08-01T12:01:00 Failed password for admin from 192.168.1.5
    2026-08-01T12:02:00 Failed password for admin from 192.168.1.5
    2026-08-01T12:03:00 Failed password for admin from 192.168.1.5
    2026-08-01T12:04:00 Failed password for admin from 192.168.1.5
    """

    response = client.post(
        "/analysis/auth-log/file",
        files={
            "file": (
                "auth.log",
                content.encode("utf-8"),
                "text/plain",
            )
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["total_lines"] == 5
    assert body["ignored_lines"] == 0
    assert len(body["events"]) == 5
    assert len(body["incidents"]) == 1
    assert body["incidents"][0]["alerts"][0]["severity"] =="high"

def test_file_upload_rejects_invalid_encoding(
        client: TestClient
) -> None:
    response = client.post(
        "/analysis/auth-log/file",
        files={
            "file": (
                "auth.log",
                b"\xff\xfe\xfd",
                "text/plain",
            )
        },
    )

    assert response.status_code == 422
    assert response.json()["detail"] == (
        "Uploaded file must contain valid UTF-8 text."
    )

def test_file_upload_rejects_oversized_file(
        client: TestClient,
) -> None:
    response = client.post(
        "/analysis/auth-log/file",
        files={
            "file": (
                "auth.log",
                b"a" *1_000_001,
                "text/plain",
            )
        },
    )

    assert response.status_code == 413
    assert response.json()["detail"] == (
        "Uploaded file must not exceed 1 MB."
    )

def test_file_upload_rejects_unsupported_extension(
        client: TestClient,
) -> None:
    response = client.post(
        "analysis/auth-log/file",
        files={
            "file": (
                "auth.csv",
                b"test content",
                "text/csv"
            ),
        },
    )

    assert response.status_code == 415
    assert response.json()["detail"] == (
        "Only .log and .txt files are supported."
    )
