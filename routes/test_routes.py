from flask import Blueprint, flash, g, redirect, render_template, request, url_for

from routes.base_routes import login_required
from utils.local_db_utils import (
    get_num_questions_topic,
    get_questions_for_topic,
    get_topics,
)
from utils.question_class import (  # Import selected_questions
    QuestionType,
    selected_questions,
)

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
        # Store questions in our global state manager
        selected_questions.add_questions(questions)
        # Store config in session or pass to test page (not implemented here)
        # TODO: Store duration in session or pass differently if needed across requests
        return render_template(
            "test_page.html",
            topic=topic,
            questions=selected_questions.get_selected_questions(),  # Get questions from state
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


@test_bp.route("/submit_test", methods=["POST"])
@login_required
def submit_test():
    """
    Processes the submitted test answers and redirects to the results page.
    """
    answers = request.form
    for question_id_str, answer_values in answers.lists():
        if question_id_str.startswith("question_"):
            try:
                question_id = int(question_id_str.split("_")[1])
                # Convert answer values to integers
                user_answer = [int(val) for val in answer_values]
                selected_questions.update_answer(question_id, user_answer)
            except (ValueError, IndexError):
                # Handle potential errors if form data is malformed
                flash(
                    f"Invalid answer format received for {question_id_str}.", "warning"
                )
                # Decide how to handle this - maybe redirect back to test?
                # For now, we'll just skip this answer.

    # Redirect to the results page
    return redirect(url_for("test.test_results"))


@test_bp.route("/test_results")
@login_required
def test_results():
    """
    Displays the test results page.
    """
    num_correct = selected_questions.get_num_correct_answers()
    total_questions = selected_questions.get_total_questions()

    if total_questions == 0:
        # Avoid division by zero if no questions were loaded
        percentage = 0
        flash("No questions found for this test.", "warning")
        # Maybe redirect home or to config?
        return redirect(url_for("base.index"))
    else:
        percentage = round((num_correct / total_questions) * 100)

    return render_template(
        "results.html",
        user=g.user,
        num_correct=num_correct,
        total_questions=total_questions,
        percentage=percentage,
    )


# Add route for reviewing completed test answers
@test_bp.route("/review")
@login_required
def review():
    """
    Displays the review page highlighting correct and incorrect answers.
    """
    questions = selected_questions.get_selected_questions()
    user_answers = selected_questions.get_user_answers()
    return render_template(
        "review.html",
        user=g.user,
        questions=questions,
        user_answers=user_answers,
        QuestionType=QuestionType,
    )
