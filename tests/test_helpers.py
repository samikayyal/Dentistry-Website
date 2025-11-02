"""
Tests for helper functions
"""

import pytest
from utils.helpers import format_time, generate_quiz_id, validate_quiz_submission


class TestFormatTime:
    """Test format_time function."""

    def test_format_time_zero(self):
        """Test formatting zero seconds."""
        result = format_time(0)
        assert result == "00:00"

    def test_format_time_under_hour(self):
        """Test formatting time under one hour."""
        result = format_time(125)  # 2 minutes 5 seconds
        assert result == "02:05"

    def test_format_time_over_hour(self):
        """Test formatting time over one hour."""
        result = format_time(3665)  # 1 hour 1 minute 5 seconds
        assert result == "01:01:05"

    def test_format_time_none(self):
        """Test formatting None value."""
        result = format_time(None)
        assert result == "00:00"

    def test_format_time_negative(self):
        """Test formatting negative value."""
        result = format_time(-10)
        assert result == "00:00"


class TestGenerateQuizId:
    """Test generate_quiz_id function."""

    def test_generate_quiz_id_unique(self):
        """Test that generated IDs are unique."""
        id1 = generate_quiz_id()
        id2 = generate_quiz_id()
        assert id1 != id2

    def test_generate_quiz_id_format(self):
        """Test that generated ID is a string."""
        quiz_id = generate_quiz_id()
        assert isinstance(quiz_id, str)
        assert len(quiz_id) > 0


class TestValidateQuizSubmission:
    """Test validate_quiz_submission function."""

    def test_validate_empty_answers(self):
        """Test validation with empty answers."""
        result = validate_quiz_submission([])
        assert result is False

    def test_validate_dict_format(self):
        """Test validation with dict format answers."""
        answers = {1: 2, 3: 4}
        result = validate_quiz_submission(answers)
        assert result is True

    def test_validate_list_format(self):
        """Test validation with list format answers."""
        answers = [
            {"question_id": 1, "selected_option_id": 2},
            {"question_id": 3, "selected_option_id": 4},
        ]
        result = validate_quiz_submission(answers)
        assert result is True

    def test_validate_invalid_list(self):
        """Test validation with invalid list format."""
        answers = [{"invalid": "data"}]
        result = validate_quiz_submission(answers)
        assert result is False

    def test_validate_none(self):
        """Test validation with None."""
        result = validate_quiz_submission(None)
        assert result is False

