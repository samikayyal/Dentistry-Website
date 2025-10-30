"""
Dentistry Quiz Application - Main Flask Application
A web application for dentistry students to practice through interactive quizzes
"""

import os
from datetime import datetime, timedelta

from dotenv import load_dotenv
from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,  # noqa: F401
    session,
    url_for,
)
from flask_cors import CORS

# Load environment variables
load_dotenv()

# Import utility functions
from utils.database import (  # noqa: E402
    get_all_topics,
    get_questions_by_ids,
    get_questions_by_topic,  # noqa: E402
    get_quiz_details,
    get_random_daily_topic,  # noqa: E402
    get_supabase_client,  # noqa: E402
    get_user_statistics,
    save_quiz_results,
)
from utils.helpers import (  # noqa: E402
    format_time,
    generate_quiz_id,
)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-key-change-in-production")
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)

# Enable CORS if needed
CORS(app)

# Initialize Supabase client
try:
    supabase = get_supabase_client()
except Exception as e:
    print(f"Warning: Could not initialize Supabase client at startup: {e}")
    supabase = None


def get_active_supabase_client():
    """Return a Supabase client instance, attempting lazy reinitialization if needed."""

    global supabase

    if supabase is not None:
        return supabase

    try:
        supabase = get_supabase_client()
        return supabase
    except Exception as exc:  # pragma: no cover - logged for diagnostics
        print(f"Error obtaining Supabase client: {exc}")
        return None


# ============================================================================
# ROUTES - Landing Page
# ============================================================================


@app.route("/")
def index():
    """Landing page"""
    return render_template("index.html")


# ============================================================================
# ROUTES - Authentication
# ============================================================================


@app.route("/auth", methods=["GET"])
def auth():
    """Authentication page (login/signup)"""
    return render_template("auth.html")


@app.route("/auth/signup", methods=["POST"])
def signup():
    """Handle user registration"""
    try:
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        # Validate inputs
        if not email or not password or not confirm_password:
            flash("All fields are required.", "error")
            return redirect(url_for("auth"))

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for("auth"))

        if len(password) < 6:
            flash("Password must be at least 6 characters long.", "error")
            return redirect(url_for("auth"))

        # Register user with Supabase
        client = get_active_supabase_client()

        if client is None:
            flash(
                "Authentication service is temporarily unavailable. Please try again later.",
                "error",
            )
            return redirect(url_for("auth"))

        response = client.auth.sign_up({"email": email, "password": password})

        if response.user:
            # Store email in session for verification
            session["pending_verification"] = {
                "email": email,
                "user_id": response.user.id,
            }
            flash(
                "Almost There! Please check your email for a verification code.",
                "success",
            )
            return redirect(url_for("verify_email"))
        else:
            flash("Registration failed. Please try again.", "error")
            return redirect(url_for("auth"))

    except Exception as e:
        print(f"Signup error: {e}")
        error_message = str(e)
        if "User already registered" in error_message:
            flash("An account with this email already exists.", "error")
        else:
            flash(f"An error occurred: {error_message}", "error")
        return redirect(url_for("auth"))


@app.route("/auth/login", methods=["POST"])
def login():
    """Handle user login"""
    try:
        email = request.form.get("email")
        password = request.form.get("password")

        # Validate inputs
        if not email or not password:
            flash("Email and password are required.", "error")
            return redirect(url_for("auth"))

        # Authenticate with Supabase
        client = get_active_supabase_client()

        if client is None:
            flash(
                "Authentication service is temporarily unavailable. Please try again later.",
                "error",
            )
            return redirect(url_for("auth"))

        response = client.auth.sign_in_with_password(
            {"email": email, "password": password}
        )

        if response.user:
            session["user"] = {
                "id": response.user.id,
                "email": response.user.email,
            }
            session.permanent = True
            flash("Login successful! Welcome back!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid email or password.", "error")
            return redirect(url_for("auth"))

    except Exception as e:
        print(f"Login error: {e}")
        flash("Invalid email or password.", "error")
        return redirect(url_for("auth"))


@app.route("/auth/verify-email", methods=["GET", "POST"])
def verify_email():
    """Handle email verification with OTP"""
    pending = session.get("pending_verification")

    if not pending:
        flash("No pending verification found.", "error")
        return redirect(url_for("auth"))

    if request.method == "POST":
        otp_code = request.form.get("otp_code")

        if not otp_code:
            flash("Please enter the verification code.", "error")
            return render_template("verify_email.html", email=pending["email"])

        try:
            client = get_active_supabase_client()

            if client is None:
                flash(
                    "Authentication service is temporarily unavailable. Please try again later.",
                    "error",
                )
                return render_template("verify_email.html", email=pending["email"])

            # Verify OTP
            response = client.auth.verify_otp(
                {"email": pending["email"], "token": otp_code, "type": "email"}
            )

            if response.user:
                # Clear pending verification
                session.pop("pending_verification", None)

                # Set user session
                session["user"] = {
                    "id": response.user.id,
                    "email": response.user.email,
                }
                session.permanent = True
                flash("Email verified successfully! Welcome!", "success")
                return redirect(url_for("dashboard"))
            else:
                flash("Invalid or expired verification code.", "error")
                return render_template("verify_email.html", email=pending["email"])

        except Exception as e:
            print(f"Verification error: {e}")
            flash("Invalid or expired verification code. Please try again.", "error")
            return render_template("verify_email.html", email=pending["email"])

    return render_template("verify_email.html", email=pending["email"])


@app.route("/auth/resend-code", methods=["POST"])
def resend_verification_code():
    """Resend verification code"""
    pending = session.get("pending_verification")

    if not pending:
        flash("No pending verification found.", "error")
        return redirect(url_for("auth"))

    try:
        client = get_active_supabase_client()

        if client is None:
            flash(
                "Authentication service is temporarily unavailable. Please try again later.",
                "error",
            )
            return redirect(url_for("verify_email"))

        # Resend OTP
        client.auth.resend({"type": "signup", "email": pending["email"]})

        flash("Verification code resent! Please check your email.", "success")
        return redirect(url_for("verify_email"))

    except Exception as e:
        print(f"Resend error: {e}")
        flash("Failed to resend verification code. Please try again.", "error")
        return redirect(url_for("verify_email"))


@app.route("/auth/logout")
def logout():
    """Handle user logout"""
    session.clear()
    flash("You have been logged out successfully.", "success")
    return redirect(url_for("index"))


@app.route("/auth/guest")
def guest_login():
    """Handle guest login with daily topic restriction"""
    # Generate guest session
    guest_id = generate_quiz_id()

    try:
        daily_topic = get_random_daily_topic()
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("index"))

    session["guest"] = {
        "id": guest_id,
        "daily_topic": daily_topic,
        "is_guest": True,
        "attempts": 0,
        "date": datetime.now().date().isoformat(),
    }
    session.permanent = False  # Guest sessions expire when browser closes

    flash(
        f"Welcome, Guest! Today's topic is: {daily_topic}. You can attempt up to 3 quizzes today.",
        "info",
    )
    return redirect(url_for("dashboard"))


@app.route("/auth/guest/reset")
def reset_guest_attempts():
    """Reset guest attempts for testing purposes (remove in production)"""
    guest = session.get("guest")

    if guest:
        guest["attempts"] = 0
        guest["date"] = datetime.now().date().isoformat()
        session["guest"] = guest
        flash("Guest attempts have been reset to 0 for testing.", "success")
    else:
        flash("No active guest session found.", "error")

    return redirect(url_for("dashboard"))


# ============================================================================
# ROUTES - Dashboard
# ============================================================================


@app.route("/dashboard")
def dashboard():
    """User dashboard with topic selection"""

    # Check if user is authenticated or guest
    user = session.get("user")
    guest = session.get("guest")

    if not user and not guest:
        flash("Please login or continue as guest.", "info")
        return redirect(url_for("index"))

    # Get available topics
    topics = get_all_topics()

    # Get user statistics if authenticated
    stats = None
    if user:
        stats = get_user_statistics(user["id"])

    # For guests, limit to daily topic only
    guest_attempts = 0
    guest_attempts_remaining = 0
    if guest and not user:
        topics = [guest["daily_topic"]]
        guest_attempts = guest.get("attempts", 0)
        guest_attempts_remaining = max(0, 3 - guest_attempts)

    return render_template(
        "dashboard.html",
        topics=topics,
        stats=stats,
        is_guest=guest and not user,
        guest_attempts=guest_attempts,
        guest_attempts_remaining=guest_attempts_remaining,
    )


# ============================================================================
# ROUTES - Quiz
# ============================================================================


@app.route("/quiz/start", methods=["POST"])
def start_quiz():
    """Initialize a new quiz session"""
    # Check authentication
    user = session.get("user")
    guest = session.get("guest")

    if not user and not guest:
        flash("Please login to start a quiz.", "error")
        return redirect(url_for("auth"))

    # Get quiz parameters
    topic = request.form.get("topic")
    num_questions = int(request.form.get("num_questions", 10))
    time_limit = request.form.get("time_limit", None)

    # Validate topic exists
    if not topic:
        flash("Please select a topic.", "error")
        return redirect(url_for("dashboard"))

    if time_limit:
        time_limit = int(time_limit)

    # Validate topic for guests
    if guest and not user:
        today_iso = datetime.now().date().isoformat()
        guest_date = guest.get("date")
        if guest_date != today_iso:
            guest["date"] = today_iso
            guest["attempts"] = 0
            session["guest"] = guest

        if topic != guest["daily_topic"]:
            flash("Guests can only access today's topic.", "error")
            return redirect(url_for("dashboard"))

        if guest.get("attempts", 0) >= 3:
            flash(
                "Guest accounts are limited to 3 quiz attempts per day. Sign up for unlimited access.",
                "warning",
            )
            return redirect(url_for("dashboard"))

    # Get questions (store only IDs in session to keep cookie small)
    questions = get_questions_by_topic(topic, num_questions, include_options=False)

    if not questions:
        flash("No questions available for this topic.", "error")
        return redirect(url_for("dashboard"))

    # Create quiz session
    quiz_id = generate_quiz_id()
    question_ids = [question["id"] for question in questions]

    session[f"quiz_{quiz_id}"] = {
        "topic": topic,
        "question_ids": question_ids,
        "time_limit": time_limit,
        "start_time": datetime.now().isoformat(),
        "current_question": 0,
        "answers": {},
    }

    if guest and not user:
        guest["attempts"] = guest.get("attempts", 0) + 1
        session["guest"] = guest and not user

    return redirect(url_for("quiz", quiz_id=quiz_id))


@app.route("/quiz/<quiz_id>")
def quiz(quiz_id):
    """Display quiz interface"""
    # Get quiz data from session
    quiz_state = session.get(f"quiz_{quiz_id}")

    if not quiz_state:
        flash("Quiz session not found.", "error")
        return redirect(url_for("dashboard"))

    questions = get_questions_by_ids(quiz_state.get("question_ids", []))

    if not questions:
        flash("Unable to load quiz questions. Please try again.", "error")
        session.pop(f"quiz_{quiz_id}", None)
        return redirect(url_for("dashboard"))

    # Calculate elapsed time
    start_time = datetime.fromisoformat(quiz_state["start_time"])
    elapsed_seconds = int((datetime.now() - start_time).total_seconds())

    # Check if time limit exceeded
    if quiz_state["time_limit"] and elapsed_seconds >= quiz_state["time_limit"] * 60:
        flash("Time limit exceeded. Quiz auto-submitted.", "warning")
        return redirect(url_for("submit_quiz", quiz_id=quiz_id))

    quiz_data = dict(quiz_state)
    quiz_data["questions"] = questions
    quiz_data["answers"] = {
        int(key): value for key, value in quiz_data.get("answers", {}).items()
    }

    print("Quiz Data:", {**quiz_data, "questions": [q["id"] for q in questions]})

    return render_template(
        "quiz.html",
        quiz_id=quiz_id,
        quiz_data=quiz_data,
        elapsed_seconds=elapsed_seconds,
    )


@app.route("/quiz/<quiz_id>/submit", methods=["POST", "GET"])
def submit_quiz(quiz_id):
    """Submit quiz answers and calculate results"""
    # Get quiz data from session
    quiz_state = session.get(f"quiz_{quiz_id}")

    if not quiz_state:
        flash("Quiz session not found.", "error")
        return redirect(url_for("dashboard"))

    # Get user info
    user = session.get("user")

    # Get answers from form (if POST) or session
    if request.method == "POST":
        answers = {}
        for key, value in request.form.items():
            if key.startswith("question_"):
                question_id = int(key.replace("question_", ""))
                answers[question_id] = int(value)
        quiz_state["answers"] = answers
        session[f"quiz_{quiz_id}"] = quiz_state

    questions = get_questions_by_ids(quiz_state.get("question_ids", []))

    if not questions:
        flash("Unable to evaluate quiz due to missing question data.", "error")
        return redirect(url_for("dashboard"))

    # Calculate time taken
    start_time = datetime.fromisoformat(quiz_state["start_time"])
    time_taken = int((datetime.now() - start_time).total_seconds())

    # Save results for authenticated users
    results = None
    if user:
        results = save_quiz_results(
            user_id=user["id"],
            topic=quiz_state["topic"],
            questions=questions,
            answers=quiz_state["answers"],
            time_taken=time_taken,
            time_limit=quiz_state.get("time_limit"),
        )

        if results:
            # Store results in session for display
            session[f"results_{quiz_id}"] = results
            # Clean up quiz session
            session.pop(f"quiz_{quiz_id}", None)
            return redirect(url_for("quiz_results", quiz_id=results["quiz_id"]))
    else:
        # For guests, calculate results without saving
        total_questions = len(questions)
        correct_answers = 0

        for question in questions:
            question_id = question["id"]
            selected_option_id = quiz_state["answers"].get(question_id)

            if selected_option_id:
                correct_option = next(
                    (opt for opt in question["options"] if opt["is_correct"]),
                    None,
                )
                if correct_option and correct_option["id"] == selected_option_id:
                    correct_answers += 1

        score = (
            int((correct_answers / total_questions) * 100) if total_questions > 0 else 0
        )

        # Store results in session
        session[f"results_{quiz_id}"] = {
            "quiz_id": quiz_id,
            "score": score,
            "correct_answers": correct_answers,
            "total_questions": total_questions,
            "time_taken": time_taken,
            "is_guest": True,
        }

    return redirect(url_for("quiz_results", quiz_id=quiz_id))


@app.route("/quiz/<quiz_id>/results")
def quiz_results(quiz_id):
    """Display quiz results"""
    user = session.get("user")

    # Try to get results from session first (for immediate display)
    results = session.get(f"results_{quiz_id}")

    if results and results.get("is_guest"):
        # Guest results - rebuild quiz data with fresh question details
        quiz_state = session.get(f"quiz_{quiz_id}")
        if quiz_state:
            questions = get_questions_by_ids(quiz_state.get("question_ids", []))

            quiz_data = dict(quiz_state)
            quiz_data["questions"] = questions
            quiz_data["answers"] = {
                int(key): value for key, value in quiz_state.get("answers", {}).items()
            }

            return render_template(
                "results.html",
                results=results,
                quiz_data=quiz_data,
                is_guest=True,
                time_formatted=format_time(results.get("time_taken", 0)),
            )
    elif user:
        # Authenticated user - fetch from database
        try:
            quiz_id_int = int(quiz_id)
            quiz_details = get_quiz_details(quiz_id_int, user["id"])

            if quiz_details:
                return render_template(
                    "results.html",
                    results=quiz_details,
                    is_guest=False,
                    time_formatted=format_time(quiz_details.get("time_taken", 0)),
                )
        except ValueError:
            pass

    flash("Results not found.", "error")
    return redirect(url_for("dashboard"))


# ============================================================================
# ROUTES - History
# ============================================================================


@app.route("/history")
def history():
    """Display quiz history for authenticated user"""
    from utils.database import get_quiz_history

    user = session.get("user")

    if not user:
        flash("Please login to view your quiz history.", "error")
        return redirect(url_for("auth"))

    # Get quiz history
    history_data = get_quiz_history(user["id"], limit=50)

    return render_template("history.html", history=history_data)


@app.route("/history/<int:quiz_id>")
def history_detail(quiz_id):
    """Display detailed results for a specific quiz"""
    from utils.database import get_quiz_details
    from utils.helpers import format_time

    user = session.get("user")

    if not user:
        flash("Please login to view quiz details.", "error")
        return redirect(url_for("auth"))

    quiz_details = get_quiz_details(quiz_id, user["id"])

    if not quiz_details:
        flash("Quiz not found.", "error")
        return redirect(url_for("history"))

    return render_template(
        "results.html",
        results=quiz_details,
        is_history=True,
        time_formatted=format_time(quiz_details.get("time_taken", 0)),
    )


# ============================================================================
# API ENDPOINTS
# ============================================================================


@app.route("/api/topics")
def api_topics():
    """Get all available topics"""
    from utils.database import get_all_topics

    try:
        topics = get_all_topics()
        return jsonify({"success": True, "topics": topics})
    except Exception as e:
        print(f"Error fetching topics: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/questions")
def api_questions():
    """Get questions by topic"""
    from utils.database import get_questions_by_topic

    topic = request.args.get("topic")
    limit = request.args.get("limit", 10, type=int)

    if not topic:
        return jsonify({"success": False, "error": "Topic is required"}), 400

    try:
        questions = get_questions_by_topic(topic, limit)
        return jsonify({"success": True, "questions": questions})
    except Exception as e:
        print(f"Error fetching questions: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/quiz/submit", methods=["POST"])
def api_submit_quiz():
    """Submit quiz answers (AJAX endpoint)"""
    from utils.database import save_quiz_results

    try:
        data = request.get_json()
        quiz_id = data.get("quiz_id")
        answers = data.get("answers", {})

        # Get quiz data from session
        quiz_data = session.get(f"quiz_{quiz_id}")

        if not quiz_data:
            return jsonify({"success": False, "error": "Quiz not found"}), 404

        # Get user info
        user = session.get("user")

        if not user:
            return (
                jsonify({"success": False, "error": "Authentication required"}),
                401,
            )

        # Calculate time taken
        start_time = datetime.fromisoformat(quiz_data["start_time"])
        time_taken = int((datetime.now() - start_time).total_seconds())

        questions = get_questions_by_ids(quiz_data.get("question_ids", []))

        if not questions:
            return (
                jsonify({"success": False, "error": "Unable to load questions."}),
                500,
            )

        # Save results
        results = save_quiz_results(
            user_id=user["id"],
            topic=quiz_data["topic"],
            questions=questions,
            answers=answers,
            time_taken=time_taken,
            time_limit=quiz_data.get("time_limit"),
        )

        if results:
            # Clean up session
            session.pop(f"quiz_{quiz_id}", None)
            return jsonify({"success": True, "results": results})
        else:
            return (
                jsonify({"success": False, "error": "Failed to save results"}),
                500,
            )

    except Exception as e:
        print(f"Error submitting quiz: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/stats")
def api_stats():
    """Get user statistics"""
    from utils.database import get_user_statistics

    user = session.get("user")

    if not user:
        return jsonify({"success": False, "error": "Authentication required"}), 401

    try:
        stats = get_user_statistics(user["id"])
        return jsonify({"success": True, "stats": stats})
    except Exception as e:
        print(f"Error fetching stats: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================================================
# ERROR HANDLERS
# ============================================================================


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return render_template("404.html"), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    return render_template("500.html"), 500


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    debug_mode = os.getenv("DEBUG", "True") == "True"
    app.run(debug=debug_mode, host="0.0.0.0", port=5000)
