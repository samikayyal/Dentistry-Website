"""
Pytest configuration and shared fixtures
"""

import os
from unittest.mock import MagicMock, patch

import pytest

# Set test environment variables before importing app
os.environ["FLASK_SECRET_KEY"] = "test-secret-key-for-testing-only"
os.environ["DEBUG"] = "True"
os.environ["SUPABASE_URL"] = "https://test.supabase.co"
os.environ["SUPABASE_KEY"] = "test-key"
os.environ["CLOUDFLARE_TURNSTILE_SECRET_KEY"] = "test-turnstile-key"

from app import app


@pytest.fixture
def client():
    """Create a test client for the Flask application."""
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    # Disable rate limiting during tests
    app.config["RATELIMIT_ENABLED"] = False
    with app.test_client() as client:
        with app.app_context():
            yield client


@pytest.fixture
def auth_client(client):
    """Create a test client with an authenticated session."""
    with client.session_transaction() as sess:
        sess["user"] = {
            "id": "test-user-id",
            "email": "test@example.com",
        }
    return client


@pytest.fixture
def guest_client(client):
    """Create a test client with a guest session."""
    with client.session_transaction() as sess:
        sess["guest"] = {
            "id": "test-guest-id",
            "daily_topic": "Periodontics",
            "is_guest": True,
            "attempts": 0,
            "date": "2025-01-01",
        }
    return client


@pytest.fixture
def mock_supabase_client():
    """Mock Supabase client for testing."""
    mock_client = MagicMock()
    mock_auth = MagicMock()
    mock_client.auth = mock_auth

    # Mock user object
    mock_user = MagicMock()
    mock_user.id = "test-user-id"
    mock_user.email = "test@example.com"

    # Mock auth responses
    mock_signup_response = MagicMock()
    mock_signup_response.user = mock_user
    mock_auth.sign_up.return_value = mock_signup_response

    mock_signin_response = MagicMock()
    mock_signin_response.user = mock_user
    mock_auth.sign_in_with_password.return_value = mock_signin_response

    mock_verify_response = MagicMock()
    mock_verify_response.user = mock_user
    mock_auth.verify_otp.return_value = mock_verify_response

    # Mock database responses
    mock_client.rpc.return_value.execute.return_value.data = []
    mock_client.table.return_value.select.return_value.eq.return_value.execute.return_value.data = (
        []
    )
    mock_client.table.return_value.insert.return_value.execute.return_value.data = [
        {"id": 1}
    ]

    return mock_client


@pytest.fixture
def mock_turnstile_success(monkeypatch):
    """Mock successful Turnstile verification."""

    def mock_verify(*args, **kwargs):
        return True

    monkeypatch.setattr("app.verify_turnstile", mock_verify)


@pytest.fixture
def mock_turnstile_failure(monkeypatch):
    """Mock failed Turnstile verification."""

    def mock_verify(*args, **kwargs):
        return False

    monkeypatch.setattr("app.verify_turnstile", mock_verify)


@pytest.fixture
def mock_get_all_topics(monkeypatch):
    """Mock get_all_topics to return test topics."""

    def mock_topics():
        return ["Periodontics", "Endodontics", "Orthodontics"]

    monkeypatch.setattr("app.get_all_topics", mock_topics)


@pytest.fixture
def mock_questions(monkeypatch):
    """Mock questions for testing."""
    test_questions = [
        {
            "id": 1,
            "topic": "Periodontics",
            "question": "What is periodontics?",
            "options": [
                {"id": 1, "option": "Option A", "is_correct": True},
                {"id": 2, "option": "Option B", "is_correct": False},
            ],
        },
        {
            "id": 2,
            "topic": "Periodontics",
            "question": "What is gingivitis?",
            "options": [
                {"id": 3, "option": "Option C", "is_correct": False},
                {"id": 4, "option": "Option D", "is_correct": True},
            ],
        },
    ]

    def mock_get_questions_by_topic(topic, limit=10, include_options=True):
        return (
            test_questions[:limit]
            if include_options
            else [
                {"id": q["id"], "topic": q["topic"], "question": q["question"]}
                for q in test_questions[:limit]
            ]
        )

    def mock_get_questions_by_ids(ids):
        return [q for q in test_questions if q["id"] in ids]

    monkeypatch.setattr("app.get_questions_by_topic", mock_get_questions_by_topic)
    monkeypatch.setattr("app.get_questions_by_ids", mock_get_questions_by_ids)
