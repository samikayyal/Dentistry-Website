from datetime import datetime
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
from utils.supabase_utils import get_test_history
from utils.utils import format_datetime

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

    # get the maximum number of questions available for this topic
    max_questions = get_num_questions_topic(topic)
    # make sure at least 1 question available
    max_questions = max(1, max_questions)

    if request.method == "POST":
        num_questions = int(request.form.get("num_questions", 5))
        num_questions = min(num_questions, max_questions)
        
        duration = int(request.form.get("duration", 10))  # in minutes
        
        questions = get_questions_for_topic(topic, num_questions)
        
        selected_questions.add_questions(questions)
        # TODO: what to do if time runs out
        return render_template(
            "test_page.html",
            topic=topic,
            questions=selected_questions.get_selected_questions(),
            duration=duration,
            user=g.user,
            QuestionType=QuestionType,
        )

    # Default values for form, ensure default is not greater than max
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
                # Handle potential errors if form data is fucked up
                flash(
                    f"Invalid answer format received for {question_id_str}.", "warning"
                )
                # TODO: Decide how to handle this, maybe redirect back to test?
                # now, we'll just skip this answer.

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

    # Store the test result in the database
    topic = selected_questions.get_selected_topic()
    try:
        user_id = g.user.id
        test_result = {
            "user_id": user_id,
            "topic": topic,
            "num_questions": total_questions,
            "num_correct_answers": num_correct,
        }
        g.supabase_client.table("user_test_results").insert(test_result).execute()
    except Exception as e:
        print(f"Error storing test result: {e}")
        flash("Error storing test result.", "danger")

    return render_template(
        "results.html",
        user=g.user,
        num_correct=num_correct,
        total_questions=total_questions,
        percentage=percentage,
    )


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


@test_bp.route("/test_history")
@login_required
def test_history():
    """
    Displays the test history page.
    """
    history = get_test_history(g.supabase_client)
    for record in history:
        record["submitted_at"] = format_datetime(record["submitted_at"], method='month day, year')
        percentage = record["num_correct_answers"] / record["num_questions"] * 100
        record["percentage"] = round(percentage) if percentage else 0

    history = sorted(
        history,
        key=lambda x: datetime.strptime(x["submitted_at"], "%B %d, %Y"),
        reverse=True,
    )

    return render_template(
        "test_history.html",
        user=g.user,
        history=history,
    )
