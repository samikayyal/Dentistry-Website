"""
Helper functions for the Dentistry Quiz Application
"""

import uuid
from datetime import datetime
from typing import Any, Dict, List


def calculate_score(answers: List[Dict[str, Any]]) -> int:
    """
    Calculate the score based on user's answers

    Args:
        answers: List of answer dictionaries containing question_id, selected_option_id, and is_correct

    Returns:
        int: Score as percentage (0-100)
    """
    if not answers:
        return 0

    correct_count = sum(1 for answer in answers if answer.get("was_correct", False))
    total = len(answers)

    return int((correct_count / total) * 100) if total > 0 else 0


def format_time(seconds: int) -> str:
    """
    Format time in seconds to human-readable format (HH:MM:SS or MM:SS)

    Args:
        seconds: Time in seconds

    Returns:
        str: Formatted time string
    """
    if seconds is None:
        seconds = 0

    try:
        total_seconds = int(seconds)
    except (TypeError, ValueError):
        total_seconds = 0

    if total_seconds < 0:
        total_seconds = 0

    hours = total_seconds // 3600
    minutes = (total_seconds % 3600) // 60
    secs = total_seconds % 60

    if hours > 0:
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"
    else:
        return f"{minutes:02d}:{secs:02d}"


def validate_quiz_submission(answers: List[Dict[str, Any]]) -> bool:
    """
    Validate quiz submission data

    Args:
        answers: List of answer dictionaries

    Returns:
        bool: True if valid, False otherwise
    """
    if not answers:
        return False

    # Check if answers is a list or dict
    if isinstance(answers, dict):
        # Convert dict to list format for validation
        for key, value in answers.items():
            if not isinstance(key, (int, str)) or not isinstance(value, (int, str)):
                return False
        return True

    # Basic validation for list format
    for answer in answers:
        if not isinstance(answer, dict):
            return False
        if "question_id" not in answer or "selected_option_id" not in answer:
            return False

    return True


def generate_quiz_id() -> str:
    """
    Generate a unique quiz ID

    Returns:
        str: Unique quiz identifier
    """
    return str(uuid.uuid4())


def get_daily_seed() -> int:
    """
    Generate a daily seed based on current date (for guest topic selection)

    Returns:
        int: Daily seed value
    """
    today = datetime.now().date()
    return int(today.strftime("%Y%m%d"))
