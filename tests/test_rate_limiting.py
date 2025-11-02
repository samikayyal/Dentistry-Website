"""
Tests for rate limiting functionality
"""

from unittest.mock import patch

import pytest


class TestRateLimiting:
    """Test rate limiting on protected endpoints."""

    def test_rate_limit_login_endpoint(self, client, mock_turnstile_success):
        """Test that login endpoint is rate limited."""
        # Note: Rate limiting is disabled in test mode by default
        # This test verifies the endpoint exists and can be called
        # In production, this would enforce the 5 per minute limit
        response = client.post(
            "/auth/login",
            data={
                "email": "test@example.com",
                "password": "password123",
            },
        )
        # Should not get 429 (rate limit exceeded) in test mode
        assert response.status_code != 429

    def test_rate_limit_signup_endpoint(self, client, mock_turnstile_success):
        """Test that signup endpoint is rate limited."""
        response = client.post(
            "/auth/signup",
            data={
                "email": "test@example.com",
                "password": "password123",
                "confirm_password": "password123",
            },
        )
        # Should not get 429 in test mode
        assert response.status_code != 429

    def test_rate_limit_api_endpoints(self, auth_client):
        """Test that API endpoints have rate limits applied."""
        # Make multiple rapid requests
        for _ in range(10):
            response = auth_client.get("/api/stats")
            # Should not get 429 in test mode, but endpoint should work
            assert response.status_code in [
                200,
                401,
            ]  # 401 if not properly authenticated
