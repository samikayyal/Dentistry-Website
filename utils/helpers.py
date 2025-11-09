"""
Helper functions for the Dentistry Quiz Application
"""

import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


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


def refresh_user_token(user_session: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Refresh an expired access token using the refresh token
    
    Args:
        user_session: The user session dict containing refresh_token
        
    Returns:
        Updated user session dict with new tokens, or None if refresh failed
    """
    from utils.database import get_supabase_client
    
    if not user_session or "refresh_token" not in user_session:
        return None
    
    try:
        supabase = get_supabase_client()
        response = supabase.auth.refresh_session(user_session["refresh_token"])
        
        if response.session:
            # Return updated session with new tokens
            return {
                "id": user_session["id"],
                "email": user_session["email"],
                "access_token": response.session.access_token,
                "refresh_token": response.session.refresh_token,
            }
        else:
            logger.warning("Token refresh failed: no session returned")
            return None
            
    except Exception as e:
        logger.exception("Error refreshing token: %s", e)
        return None
