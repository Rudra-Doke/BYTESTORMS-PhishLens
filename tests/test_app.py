import os

import pytest


# Use an isolated SQLite database for tests.
os.environ["PHISHLENS_DATABASE_URL"] = "sqlite:///instance/test_phishlens.db"


from app import app


@pytest.fixture
def client():
    app.config.update(
        TESTING=True
    )

    with app.test_client() as client:
        yield client


def test_healthz(client):
    response = client.get("/healthz")

    assert response.status_code == 200

    data = response.get_json()

    assert data["status"] == "OK"
    assert data["service"] == "PhishLens"


def test_analyze_missing_data(client):
    response = client.post(
        "/analyze",
        json={}
    )

    assert response.status_code == 400


def test_analyze_google(client):
    response = client.post(
        "/analyze",
        json={
            "url": "https://google.com"
        }
    )

    assert response.status_code == 200

    data = response.get_json()

    assert "verdict" in data
    assert "risk_score" in data
    assert "scan_id" in data
    assert "storage" in data


def test_analyze_qr_missing_payload(client):
    response = client.post(
        "/analyze-qr",
        json={}
    )

    assert response.status_code == 400


def test_security_headers(client):
    response = client.get("/healthz")

    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == (
        "strict-origin-when-cross-origin"
    )


def test_oversized_request(client):
    large_url = (
            "https://example.com/"
            + ("x" * 300000)
    )

    response = client.post(
        "/analyze",
        json={
            "url": large_url
        }
    )

    assert response.status_code == 413