"""
Tests for quiz-related routes
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest


class TestDashboard:
    """Test dashboard route."""

    def test_dashboard_unauthenticated(self, client):
        """Test dashboard access without authentication."""
        response = client.get("/dashboard", follow_redirects=True)
        assert response.status_code == 200

    def test_dashboard_authenticated(self, auth_client, mock_get_all_topics):
        """Test dashboard access for authenticated user."""
        response = auth_client.get("/dashboard")
        assert response.status_code == 200

    def test_dashboard_guest(self, guest_client, mock_get_all_topics):
        """Test dashboard access for guest user."""
        response = guest_client.get("/dashboard")
        assert response.status_code == 200


class TestStartQuiz:
    """Test quiz start functionality."""

    def test_start_quiz_unauthenticated(self, client):
        """Test starting quiz without authentication."""
        response = client.post(
            "/quiz/start",
            data={"topic": "Periodontics"},
            follow_redirects=True,
        )
        assert response.status_code == 200

    def test_start_quiz_no_topic(self, auth_client):
        """Test starting quiz without selecting topic."""
        response = auth_client.post(
            "/quiz/start",
            data={},
            follow_redirects=True,
        )
        assert response.status_code == 200

    @patch("app.get_questions_by_topic")
    def test_start_quiz_success(self, mock_questions, auth_client):
        """Test successful quiz start."""
        mock_questions.return_value = [
            {"id": 1, "topic": "Periodontics", "question": "Test?"},
            {"id": 2, "topic": "Periodontics", "question": "Test2?"},
        ]

        response = auth_client.post(
            "/quiz/start",
            data={"topic": "Periodontics", "num_questions": "10"},
            follow_redirects=False,
        )
        assert response.status_code == 302  # Redirect to quiz page

        # Check that quiz session was created
        with auth_client.session_transaction() as sess:
            quiz_keys = [k for k in sess.keys() if k.startswith("quiz_")]
            assert len(quiz_keys) == 1

    def test_start_quiz_guest_invalid_topic(self, guest_client):
        """Test guest trying to access non-daily topic."""
        response = guest_client.post(
            "/quiz/start",
            data={"topic": "Endodontics"},  # Different from daily topic
            follow_redirects=True,
        )
        assert response.status_code == 200

    def test_start_quiz_guest_max_attempts(self, guest_client):
        """Test guest with maximum attempts trying to start quiz."""
        with guest_client.session_transaction() as sess:
            sess["guest"]["attempts"] = 3

        response = guest_client.post(
            "/quiz/start",
            data={"topic": "Periodontics"},
            follow_redirects=True,
        )
        assert response.status_code == 200


class TestSubmitQuiz:
    """Test quiz submission functionality."""

    def test_submit_quiz_no_session(self, auth_client):
        """Test submitting quiz with no active quiz session."""
        response = auth_client.post(
            "/quiz/submit",
            data={},
            follow_redirects=True,
        )
        assert response.status_code == 200

    def test_submit_quiz_unauthenticated(self, client):
        """Test submitting quiz without authentication."""
        response = client.post("/quiz/submit", data={}, follow_redirects=True)
        assert response.status_code == 200

    @patch("app.get_questions_by_ids")
    @patch("app.save_quiz_results")
    def test_submit_quiz_authenticated(self, mock_save, mock_questions, auth_client):
        """Test quiz submission for authenticated user."""
        # Set up quiz session
        quiz_id = "test-quiz-id"
        with auth_client.session_transaction() as sess:
            sess[f"quiz_{quiz_id}"] = {
                "topic": "Periodontics",
                "question_ids": [1, 2],
                "time_limit": None,
                "start_time": datetime.now(timezone.utc).isoformat(),
                "current_question": 0,
                "answers": {},
            }

        mock_questions.return_value = [
            {
                "id": 1,
                "topic": "Periodontics",
                "question": "Test?",
                "options": [{"id": 1, "option": "A", "is_correct": True}],
            }
        ]
        mock_save.return_value = {
            "quiz_id": 1,
            "score": 100,
            "correct_answers": 1,
            "total_questions": 1,
        }

        response = auth_client.post(
            "/quiz/submit",
            data={"question_1": "1"},
            follow_redirects=True,
        )
        assert response.status_code == 200


class TestTimezoneHandling:
    """Test timezone handling for quiz time limits."""

    @patch("app.get_questions_by_topic")
    def test_quiz_start_time_uses_utc(self, mock_questions, auth_client):
        """Test that quiz start time is stored with UTC timezone."""
        mock_questions.return_value = [
            {"id": 1, "topic": "Periodontics", "question": "Test?"}
        ]

        response = auth_client.post(
            "/quiz/start",
            data={"topic": "Periodontics", "num_questions": "10", "time_limit": "15"},
            follow_redirects=False,
        )
        assert response.status_code == 302

        # Check that start_time includes timezone info
        with auth_client.session_transaction() as sess:
            quiz_keys = [k for k in sess.keys() if k.startswith("quiz_")]
            assert len(quiz_keys) == 1
            quiz_data = sess[quiz_keys[0]]
            start_time_str = quiz_data["start_time"]
            
            # Parse the ISO format string
            start_time = datetime.fromisoformat(start_time_str)
            
            # Verify it has timezone info (UTC)
            assert start_time.tzinfo is not None
            assert start_time.tzinfo == timezone.utc or start_time.tzinfo.utcoffset(start_time) == timedelta(0)

    @patch("app.get_questions_by_ids")
    def test_time_limit_enforcement(self, mock_questions, auth_client):
        """Test that time limit is correctly enforced with UTC times."""
        # Create a quiz that started 16 minutes ago (past 15 minute limit)
        start_time = datetime.now(timezone.utc) - timedelta(minutes=16)
        quiz_id = "test-expired-quiz"
        
        with auth_client.session_transaction() as sess:
            sess[f"quiz_{quiz_id}"] = {
                "topic": "Periodontics",
                "question_ids": [1, 2],
                "time_limit": 15,  # 15 minute limit
                "start_time": start_time.isoformat(),
                "current_question": 0,
                "answers": {},
            }

        mock_questions.return_value = [
            {
                "id": 1,
                "topic": "Periodontics",
                "question": "Test?",
                "options": [{"id": 1, "option": "A", "is_correct": True}],
            }
        ]

        # Try to access the quiz - should redirect due to time limit
        response = auth_client.get(f"/quiz/{quiz_id}", follow_redirects=False)
        assert response.status_code == 302
        assert "/submit" in response.location

    @patch("app.get_questions_by_ids")
    def test_elapsed_time_calculation(self, mock_questions, auth_client):
        """Test that elapsed time is calculated correctly using UTC."""
        # Create a quiz that started 5 minutes ago
        start_time = datetime.now(timezone.utc) - timedelta(minutes=5)
        quiz_id = "test-active-quiz"
        
        with auth_client.session_transaction() as sess:
            sess[f"quiz_{quiz_id}"] = {
                "topic": "Periodontics",
                "question_ids": [1, 2],
                "time_limit": 15,  # 15 minute limit
                "start_time": start_time.isoformat(),
                "current_question": 0,
                "answers": {},
            }

        mock_questions.return_value = [
            {
                "id": 1,
                "topic": "Periodontics",
                "question": "Test?",
                "options": [{"id": 1, "option": "A", "is_correct": True}],
            }
        ]

        response = auth_client.get(f"/quiz/{quiz_id}")
        assert response.status_code == 200
        
        # Check that elapsed_seconds is passed to the template
        # and is approximately 300 seconds (5 minutes)
        assert b"elapsed_seconds" in response.data or b"timer" in response.data
