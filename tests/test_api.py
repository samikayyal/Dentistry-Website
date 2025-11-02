"""
Tests for API endpoints
"""

import pytest
from unittest.mock import patch, MagicMock


class TestAPITopics:
    """Test /api/topics endpoint."""

    def test_api_topics_success(self, client, mock_get_all_topics):
        """Test successful topics retrieval."""
        response = client.get("/api/topics")
        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True
        assert "topics" in data

    @patch("app.get_all_topics")
    def test_api_topics_error(self, mock_topics, client):
        """Test topics endpoint with error."""
        mock_topics.side_effect = Exception("Database error")
        response = client.get("/api/topics")
        assert response.status_code == 500
        data = response.get_json()
        assert data["success"] is False


class TestAPIQuestions:
    """Test /api/questions endpoint."""

    def test_api_questions_no_topic(self, client):
        """Test questions endpoint without topic parameter."""
        response = client.get("/api/questions")
        assert response.status_code == 400
        data = response.get_json()
        assert data["success"] is False

    @patch("app.get_questions_by_topic")
    def test_api_questions_success(self, mock_questions, client):
        """Test successful questions retrieval."""
        mock_questions.return_value = [
            {
                "id": 1,
                "topic": "Periodontics",
                "question": "Test?",
                "options": [],
            }
        ]
        response = client.get("/api/questions?topic=Periodontics&limit=10")
        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True
        assert "questions" in data

    @patch("app.get_questions_by_topic")
    def test_api_questions_error(self, mock_questions, client):
        """Test questions endpoint with error."""
        mock_questions.side_effect = Exception("Database error")
        response = client.get("/api/questions?topic=Periodontics")
        assert response.status_code == 500


class TestAPISubmitQuiz:
    """Test /api/quiz/submit endpoint."""

    def test_api_submit_no_auth(self, client):
        """Test quiz submission without authentication."""
        response = client.post(
            "/api/quiz/submit",
            json={"quiz_id": "test", "answers": {}},
        )
        assert response.status_code == 401
        data = response.get_json()
        assert data["success"] is False

    def test_api_submit_no_quiz_session(self, auth_client):
        """Test quiz submission without quiz session."""
        response = auth_client.post(
            "/api/quiz/submit",
            json={"quiz_id": "nonexistent", "answers": {}},
        )
        assert response.status_code == 404

    @patch("app.get_questions_by_ids")
    @patch("app.save_quiz_results")
    def test_api_submit_success(
        self, mock_save, mock_questions, auth_client
    ):
        """Test successful quiz submission via API."""
        quiz_id = "test-quiz-id"
        with auth_client.session_transaction() as sess:
            sess[f"quiz_{quiz_id}"] = {
                "topic": "Periodontics",
                "question_ids": [1],
                "time_limit": None,
                "start_time": "2025-01-01T00:00:00",
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
            "/api/quiz/submit",
            json={"quiz_id": quiz_id, "answers": {1: 1}},
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True
        assert "results" in data


class TestAPIStats:
    """Test /api/stats endpoint."""

    def test_api_stats_no_auth(self, client):
        """Test stats endpoint without authentication."""
        response = client.get("/api/stats")
        assert response.status_code == 401

    @patch("app.get_user_statistics")
    def test_api_stats_success(self, mock_stats, auth_client):
        """Test successful stats retrieval."""
        mock_stats.return_value = {
            "total_quizzes": 5,
            "average_score": 85,
            "best_score": 100,
            "worst_score": 60,
        }
        response = auth_client.get("/api/stats")
        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True
        assert "stats" in data

