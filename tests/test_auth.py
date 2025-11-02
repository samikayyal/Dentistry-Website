"""
Tests for authentication routes
"""

from unittest.mock import MagicMock, patch

import pytest


class TestSignup:
    """Test user signup functionality."""

    def test_signup_get_not_allowed(self, client):
        """Test that GET requests to signup are not allowed."""
        response = client.get("/auth/signup")
        assert response.status_code == 405  # Method Not Allowed

    def test_signup_missing_fields(self, client, mock_turnstile_success):
        """Test signup with missing required fields."""
        response = client.post(
            "/auth/signup",
            data={},
            follow_redirects=True,
        )
        assert response.status_code == 200
        # Should redirect to auth page with error flash

    def test_signup_password_mismatch(self, client, mock_turnstile_success):
        """Test signup with mismatched passwords."""
        response = client.post(
            "/auth/signup",
            data={
                "email": "test@example.com",
                "password": "password123",
                "confirm_password": "different123",
            },
            follow_redirects=True,
        )
        assert response.status_code == 200

    def test_signup_short_password(self, client, mock_turnstile_success):
        """Test signup with password shorter than 8 characters."""
        response = client.post(
            "/auth/signup",
            data={
                "email": "test@example.com",
                "password": "short",
                "confirm_password": "short",
            },
            follow_redirects=True,
        )
        assert response.status_code == 200

    def test_signup_turnstile_failure(self, client, mock_turnstile_failure):
        """Test signup with failed CAPTCHA verification."""
        response = client.post(
            "/auth/signup",
            data={
                "email": "test@example.com",
                "password": "password123",
                "confirm_password": "password123",
            },
            follow_redirects=True,
        )
        assert response.status_code == 200

    @patch("app.get_active_supabase_client")
    def test_signup_success(
        self, mock_client, client, mock_turnstile_success, mock_supabase_client
    ):
        """Test successful user signup."""
        mock_client.return_value = mock_supabase_client

        response = client.post(
            "/auth/signup",
            data={
                "email": "test@example.com",
                "password": "password123",
                "confirm_password": "password123",
            },
            follow_redirects=True,
        )
        assert response.status_code == 200


class TestLogin:
    """Test user login functionality."""

    def test_login_get_not_allowed(self, client):
        """Test that GET requests to login are not allowed."""
        response = client.get("/auth/login")
        assert response.status_code == 405

    def test_login_missing_fields(self, client, mock_turnstile_success):
        """Test login with missing email or password."""
        response = client.post(
            "/auth/login",
            data={},
            follow_redirects=True,
        )
        assert response.status_code == 200

    def test_login_turnstile_failure(self, client, mock_turnstile_failure):
        """Test login with failed CAPTCHA verification."""
        response = client.post(
            "/auth/login",
            data={
                "email": "test@example.com",
                "password": "password123",
            },
            follow_redirects=True,
        )
        assert response.status_code == 200

    @patch("app.get_active_supabase_client")
    def test_login_invalid_credentials(
        self, mock_client, client, mock_turnstile_success, mock_supabase_client
    ):
        """Test login with invalid credentials."""
        mock_client.return_value = mock_supabase_client
        mock_supabase_client.auth.sign_in_with_password.side_effect = Exception(
            "Invalid credentials"
        )

        response = client.post(
            "/auth/login",
            data={
                "email": "test@example.com",
                "password": "wrongpassword",
            },
            follow_redirects=True,
        )
        assert response.status_code == 200

    @patch("app.get_active_supabase_client")
    def test_login_success(
        self, mock_client, client, mock_turnstile_success, mock_supabase_client
    ):
        """Test successful login."""
        mock_client.return_value = mock_supabase_client

        response = client.post(
            "/auth/login",
            data={
                "email": "test@example.com",
                "password": "password123",
            },
            follow_redirects=True,
        )
        assert response.status_code == 200
        # Check that session was created
        with client.session_transaction() as sess:
            assert "user" in sess


class TestLogout:
    """Test user logout functionality."""

    def test_logout_without_auth(self, client):
        """Test logout when not authenticated."""
        response = client.get("/auth/logout", follow_redirects=True)
        assert response.status_code == 200

    def test_logout_success(self, auth_client):
        """Test successful logout."""
        response = auth_client.get("/auth/logout", follow_redirects=True)
        assert response.status_code == 200
        # Check that session was cleared
        with auth_client.session_transaction() as sess:
            assert "user" not in sess


class TestGuestLogin:
    """Test guest login functionality."""

    @patch("app.get_random_daily_topic")
    def test_guest_login_success(self, mock_topic, client):
        """Test successful guest login."""
        mock_topic.return_value = "Periodontics"

        response = client.get("/auth/guest", follow_redirects=True)
        assert response.status_code == 200
        # Check that guest session was created
        with client.session_transaction() as sess:
            assert "guest" in sess
            assert sess["guest"]["is_guest"] is True
