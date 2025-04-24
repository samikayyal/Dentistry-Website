from flask import Blueprint, flash, g, redirect, render_template, request, url_for

from routes.base_routes import login_required
from utils.local_db_utils import (
    get_num_questions_topic,
    get_questions_for_topic,
    get_topics,
)
from utils.question_class import QuestionType

# Create a blueprint for test routes
test_bp = Blueprint("test", __name__)


@test_bp.route("/test_config/<topic>", methods=["GET", "POST"])
@login_required
def test_config(topic):
    """
    Page to configure test settings for a selected topic.
    Allows user to choose number of questions and test duration.
    """
    topics = get_topics()
    if topic not in topics:
        flash("Invalid topic selected.", "danger")
        return redirect(url_for("base.index"))

    # Get the maximum number of questions available for this topic
    max_questions = get_num_questions_topic(topic)
    # Ensure we have at least 1 question available
    max_questions = max(1, max_questions)

    if request.method == "POST":
        num_questions = int(request.form.get("num_questions", 5))
        # Limit num_questions to available questions
        num_questions = min(num_questions, max_questions)
        duration = int(request.form.get("duration", 10))  # in minutes
        # Fetch questions for the topic
        questions = get_questions_for_topic(topic, num_questions)
        # Store config in session or pass to test page (not implemented here)
        return render_template(
            "test_page.html",
            topic=topic,
            questions=questions,
            duration=duration,
            user=g.user,
            QuestionType=QuestionType,
        )

    # Default values for form - ensure default is not greater than max
    default_num_questions = min(5, max_questions)
    return render_template(
        "test_config.html",
        topic=topic,
        user=g.user,
        default_num_questions=default_num_questions,
        default_duration=10,
        max_questions=max_questions,
    )
