"""
Database utility functions for interacting with Supabase
"""

import logging
import os
import random
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from supabase import Client, create_client

# Load environment variables
load_dotenv()

# Initialize Supabase client
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

# Logger
logger = logging.getLogger(__name__)


@lru_cache(25)
def get_supabase_client() -> Client:
    """
    Create and return a Supabase client instance (unauthenticated - for public operations)

    Returns:
        Client: Supabase client instance
    """
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise ValueError("Supabase credentials not found in environment variables")
    return create_client(SUPABASE_URL, SUPABASE_KEY)


def get_authenticated_supabase_client(access_token: str) -> Client:
    """
    Create and return an authenticated Supabase client instance for a specific user.
    This is required for operations that use Row Level Security (RLS) policies.

    IMPORTANT: When using RLS policies that check auth.uid(), you MUST use this function
    instead of get_supabase_client(). The access token allows Supabase to identify
    the user in RLS policies, preventing "new row violates row-level security policy" errors.

    Args:
        access_token: The user's JWT access token from their session

    Returns:
        Client: Authenticated Supabase client instance
    """
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise ValueError("Supabase credentials not found in environment variables")

    # Create a client with the user's access token
    client = create_client(SUPABASE_URL, SUPABASE_KEY)

    # Set the auth session with the access token to enable RLS
    # This ensures auth.uid() in RLS policies will correctly identify the user
    client.postgrest.auth(access_token)

    return client


def get_all_topics() -> List[str]:
    """
    Get all available topics from the database

    Returns:
        List of topic names
    """
    try:
        supabase = get_supabase_client()
        response = supabase.rpc("get_topics", {}).execute()
        return [row["topic"] for row in response.data]
    except Exception as e:
        logger.exception("Error fetching topics: %s", e)
        return []


def get_questions_by_topic(
    topic: str, limit: int = 10, include_options: bool = True
) -> List[Dict[str, Any]]:
    """
    Retrieve questions by topic from the database

    Args:
        topic: The topic to filter questions by
        limit: Maximum number of questions to retrieve
        include_options: Whether to include answer options for each question

    Returns:
        List of question dictionaries with their options
    """
    try:
        supabase = get_supabase_client()

        # Clamp limit to a safe range to protect database load
        try:
            limit = int(limit)
        except (TypeError, ValueError):
            limit = 10
        limit = max(1, min(limit, 100))

        # Get random questions for the topic
        response = supabase.rpc(
            "get_random_questions", {"p_topic": topic, "p_limit": limit}
        ).execute()

        questions = response.data or []

        if not include_options:
            return questions

        # Optimized: Batch fetch all options in a single query instead of N+1 queries
        if not questions:
            return questions

        # Extract question IDs
        question_ids = [q["id"] for q in questions]

        # Fetch all questions with their options in a single query
        # This uses Supabase's relationship syntax to join options
        batch_response = (
            supabase.table("questions")
            .select("id, topic, question, image_url, options(id, option, is_correct)")
            .in_("id", question_ids)
            .execute()
        )

        # Create a map of question_id -> question with options
        questions_with_options = {q["id"]: q for q in batch_response.data}

        # Attach options to original questions, preserving order from RPC call
        for question in questions:
            if question["id"] in questions_with_options:
                question_with_options = questions_with_options[question["id"]]
                # Sort options by ID for consistency
                options = question_with_options.get("options", [])
                options.sort(key=lambda opt: opt.get("id"))
                question["options"] = options
            else:
                # Fallback: if question not found in batch, use empty options
                question["options"] = []

        return questions

    except Exception as e:
        logger.exception("Error fetching questions: %s", e)
        return []


def get_questions_by_ids(question_ids: List[int]) -> List[Dict[str, Any]]:
    """Retrieve detailed question data (with options) for a list of question IDs."""

    if not question_ids:
        return []

    try:
        supabase = get_supabase_client()

        response = (
            supabase.table("questions")
            .select(
                "id, topic, question, image_url," " options(id, option, is_correct)"
            )
            .in_("id", question_ids)
            .execute()
        )

        data = response.data

        # Normalize options and re-order questions to match provided order
        question_map = {}
        for question in data:
            options = question.get("options", [])
            options.sort(key=lambda opt: opt.get("id"))
            question["options"] = options
            question_map[question["id"]] = question

        ordered_questions = [
            question_map[qid] for qid in question_ids if qid in question_map
        ]

        return ordered_questions

    except Exception as e:
        logger.exception("Error fetching questions by IDs: %s", e)
        return []


def get_random_daily_topic() -> str:
    """
    Get a random topic for guest users (same topic per day)

    Returns:
        str: Topic name
    """
    topics = get_all_topics()

    if not topics:
        raise ValueError("No topics available for selection")

    # Use current date as seed for consistent daily topic (UTC)
    today = datetime.now(timezone.utc).date()
    seed = int(today.strftime("%Y%m%d"))
    random.seed(seed)

    return random.choice(topics)


def save_quiz_results(
    user_id: str,
    topic: str,
    questions: List[Dict[str, Any]],
    answers: Dict[int, int],
    time_taken: Optional[int] = None,
    time_limit: Optional[int] = None,
    access_token: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    Save quiz results to the database

    Args:
        user_id: User's unique identifier
        topic: Quiz topic
        questions: List of questions with their options
        answers: Dict mapping question_id to selected_option_id
        time_taken: Time taken in seconds
        time_limit: Time limit in seconds (if any)
        access_token: User's JWT access token for authenticated operations (required for RLS)

    Returns:
        Dict containing quiz history ID and results
    """
    try:
        # Use authenticated client if access token is provided (required for RLS)
        if access_token:
            supabase = get_authenticated_supabase_client(access_token)
        else:
            supabase = get_supabase_client()

        # Calculate score
        total_questions = len(questions)
        correct_answers = 0
        user_answers_data = []

        normalized_answers: Dict[int, int] = {}
        if isinstance(answers, dict):
            for key, value in answers.items():
                try:
                    question_key = int(key)
                    normalized_answers[question_key] = int(value)
                except (TypeError, ValueError):
                    continue

        for question in questions:
            question_id = question["id"]
            selected_option_id = normalized_answers.get(int(question_id))

            options = question.get("options", [])
            correct_option = next(
                (opt for opt in options if opt.get("is_correct")), None
            )
            correct_option_id = None
            if correct_option is not None:
                try:
                    correct_option_id = int(correct_option.get("id"))
                except (TypeError, ValueError):
                    correct_option_id = correct_option.get("id")

            # If question was not answered, selected_option_id will be None
            if selected_option_id is None:
                was_correct = False
            else:
                was_correct = (
                    correct_option_id is not None
                    and correct_option_id == selected_option_id
                )

            if was_correct:
                correct_answers += 1

            # Save all questions, including unanswered ones (with NULL selected_option_id)
            user_answers_data.append(
                {
                    "question_id": question_id,
                    "selected_option_id": selected_option_id,  # Can be None for unanswered
                    "was_correct": was_correct,
                }
            )

        score = (
            int((correct_answers / total_questions) * 100) if total_questions > 0 else 0
        )

        # Insert quiz history
        quiz_data = {
            "user_id": user_id,
            "topic": topic,
            "total_questions": total_questions,
            "correct_answers": correct_answers,
            "score": score,
            "time_taken": time_taken,
            "time_limit": time_limit,
        }

        quiz_response = supabase.table("quiz_history").insert(quiz_data).execute()
        quiz_id = quiz_response.data[0]["id"]

        # Insert user answers
        for answer in user_answers_data:
            answer["quiz_history_id"] = quiz_id

        if user_answers_data:
            supabase.table("user_answers").insert(user_answers_data).execute()

        return {
            "quiz_id": quiz_id,
            "score": score,
            "correct_answers": correct_answers,
            "total_questions": total_questions,
        }

    except Exception as e:
        logger.exception("Error saving quiz results: %s", e)
        return None


def get_quiz_history(user_id: str, limit: int = 10) -> List[Dict[str, Any]]:
    """
    Retrieve quiz history for a user

    Args:
        user_id: User's unique identifier
        limit: Maximum number of records to retrieve

    Returns:
        List of quiz history records
    """
    try:
        supabase = get_supabase_client()
        response = supabase.rpc(
            "get_user_quiz_history", {"p_user_id": user_id}
        ).execute()

        return response.data[:limit] if response.data else []

    except Exception as e:
        logger.exception("Error fetching quiz history: %s", e)
        return []


def get_quiz_details(quiz_id: int, user_id: str) -> Optional[Dict[str, Any]]:
    """
    Get detailed results for a specific quiz

    Args:
        quiz_id: Quiz history ID
        user_id: User's unique identifier

    Returns:
        Dict containing quiz details with questions and answers
    """
    try:
        supabase = get_supabase_client()

        # Get quiz history
        quiz_response = (
            supabase.table("quiz_history")
            .select("*")
            .eq("id", quiz_id)
            .eq("user_id", user_id)
            .execute()
        )

        if not quiz_response.data:
            return None

        quiz = quiz_response.data[0]

        # Get user answers with question details (not options yet - options join only returns selected option)
        answers_response = (
            supabase.table("user_answers")
            .select("*, questions(*)")
            .eq("quiz_history_id", quiz_id)
            .execute()
        )

        # Get all question IDs from the answers to fetch complete question data with all options
        question_ids = list(
            set(
                answer["question_id"]
                for answer in answers_response.data
                if answer.get("question_id")
            )
        )

        # Fetch complete questions with ALL options (not just selected ones)
        questions_with_options = {}
        if question_ids:
            complete_questions = get_questions_by_ids(question_ids)
            questions_with_options = {q["id"]: q for q in complete_questions}

        # Enrich answers with complete question data including all options
        for answer in answers_response.data:
            question_id = answer.get("question_id")
            if question_id and question_id in questions_with_options:
                answer["questions"] = questions_with_options[question_id]

        quiz["answers"] = answers_response.data

        return quiz

    except Exception as e:
        logger.exception("Error fetching quiz details: %s", e)
        return None


def get_user_statistics(
    user_id: str, access_token: Optional[str] = None
) -> Dict[str, Any]:
    """
    Calculate and retrieve user statistics

    Args:
        user_id: User's unique identifier
        access_token: User's JWT access token for authenticated operations (required for RLS)

    Returns:
        Dict containing user statistics (total quizzes, average score, etc.)
    """
    try:
        # Use authenticated client if access token is provided (required for RLS on user_statistics view)
        if access_token:
            supabase = get_authenticated_supabase_client(access_token)
        else:
            supabase = get_supabase_client()

        # Get user statistics from view
        response = (
            supabase.from_("user_statistics")
            .select("*")
            .eq("user_id", user_id)
            .execute()
        )

        if response.data:
            stats = response.data[0]
            default_fields = {
                "total_quizzes": 0,
                "average_score": 0,
                "best_score": 0,
                "worst_score": 0,
                "total_questions_attempted": 0,
                "total_correct_answers": 0,
                "last_quiz_date": None,
            }

            for key, default_value in default_fields.items():
                stats[key] = stats.get(key, default_value)

            # Round average_score to 2 decimal places
            if stats["average_score"]:
                stats["average_score"] = round(float(stats["average_score"]), 2)

            # Calculate percentage of correct answers
            if stats["total_questions_attempted"] > 0:
                stats["overall_accuracy"] = int(
                    (
                        stats["total_correct_answers"]
                        / stats["total_questions_attempted"]
                    )
                    * 100
                )
            else:
                stats["overall_accuracy"] = 0

            return stats
        else:
            return {
                "total_quizzes": 0,
                "average_score": 0,
                "best_score": 0,
                "worst_score": 0,
                "total_questions_attempted": 0,
                "total_correct_answers": 0,
                "overall_accuracy": 0,
                "last_quiz_date": None,
            }

    except Exception as e:
        logger.exception("Error fetching user statistics: %s", e)
        return {
            "total_quizzes": 0,
            "average_score": 0,
            "best_score": 0,
            "worst_score": 0,
            "total_questions_attempted": 0,
            "total_correct_answers": 0,
            "overall_accuracy": 0,
            "last_quiz_date": None,
        }
