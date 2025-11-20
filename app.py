"""
Dentistry Quiz Application - Main Flask Application
A web application for dentistry students to practice through interactive quizzes
"""

import logging
import os
from datetime import datetime, timedelta, timezone

import requests
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
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

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
    refresh_user_token,
)
from utils.validation import validate_email  # noqa: E402

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")
if not app.secret_key:
    raise ValueError(
        "FLASK_SECRET_KEY environment variable is required. "
        "Set it in your .env file or environment variables."
    )
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)

# Request size limits (16MB max)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB

# Security: session cookie hardening
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

# Configure logging and debug mode
DEBUG_MODE = os.getenv("DEBUG", "False") == "True"
logging.basicConfig(
    level=logging.DEBUG if DEBUG_MODE else logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)

# Suppress extremely verbose HTTP/2 debug logs from dependencies
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("hpack").setLevel(logging.WARNING)

# Enable CORS: restrict to explicit origins in production
allowed_origins = os.getenv("ALLOWED_ORIGINS", "").strip()
if allowed_origins:
    origins = [o.strip() for o in allowed_origins.split(",") if o.strip()]
    CORS(app, resources={r"/*": {"origins": origins}}, supports_credentials=True)
else:
    # Default to enabling CORS only in debug for convenience
    if DEBUG_MODE:
        CORS(app)

# Initialize rate limiter
# Using in-memory storage (default) - suitable for single worker deployments
# Rate limiting is automatically disabled when app.config["TESTING"] is True
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per minute"],
    strategy="fixed-window",
    enabled=lambda: not app.config.get("TESTING", False),  # type: ignore
)

# Initialize Supabase client
try:
    supabase = get_supabase_client()
except Exception as e:
    logger.warning("Could not initialize Supabase client at startup: %s", e)
    supabase = None


def verify_turnstile(request):
    """Verify the Cloudflare Turnstile token."""
    token = request.form.get("cf-turnstile-response")
    ip = request.remote_addr
    if DEBUG_MODE:
        logger.debug("Verifying Turnstile token from IP: %s", ip)
    if not token:
        return False

    secret_key = os.getenv("CLOUDFLARE_TURNSTILE_SECRET_KEY", "").strip()
    if not secret_key:
        logger.error(
            "CLOUDFLARE_TURNSTILE_SECRET_KEY is not set; captcha cannot be verified"
        )
        return False

    try:
        response = requests.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data={
                "secret": secret_key,
                "response": token,
                "remoteip": ip,
            },
            timeout=5,
        )
        response.raise_for_status()
        result = response.json()
        if DEBUG_MODE:
            logger.debug("Turnstile verify result: %s", result)
        return result.get("success", False)
    except requests.RequestException as e:
        logger.warning("Turnstile verification failed: %s", e)
        return False


def get_active_supabase_client():
    """Return a Supabase client instance, attempting lazy reinitialization if needed."""

    global supabase

    if supabase is not None:
        return supabase

    try:
        supabase = get_supabase_client()
        return supabase
    except Exception as exc:  # pragma: no cover - logged for diagnostics
        logger.error("Error obtaining Supabase client: %s", exc)
        return None


# ============================================================================
# ROUTES - Landing Page
# ============================================================================


# ----------------------------------------------------------------------------
# Security headers
# ----------------------------------------------------------------------------


@app.after_request
def add_security_headers(response):
    """Add security-related HTTP headers and a conservative CSP.

    Update the CSP if additional third-party assets are used.
    """
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault(
        "Permissions-Policy", "geolocation=(), microphone=(), camera=()"
    )

    # Content Security Policy (CSP)
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://challenges.cloudflare.com https://*.challenges.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https://challenges.cloudflare.com https://*.challenges.cloudflare.com; "
        "frame-src https://challenges.cloudflare.com https://*.challenges.cloudflare.com; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    )
    if not DEBUG_MODE:
        response.headers.setdefault("Content-Security-Policy", csp)
    return response


@app.before_request
def redirect_signed_in_users_from_public_pages():
    """Redirect signed-in users (including guests) away from public pages to dashboard."""
    try:
        endpoint = request.endpoint
        if endpoint in {"index", "auth"}:
            if session.get("user"):
                # Only redirect on safe GETs to avoid interfering with non-idempotent actions
                if request.method == "GET":
                    return redirect(url_for("dashboard"))
    except Exception:
        # Do not block the request on any unexpected error here
        pass


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
    turnstile_site_key = os.getenv("CLOUDFLARE_TURNSTILE_SITE_KEY", "")
    if not turnstile_site_key:
        flash("Sign in is temporarily unavailable: captcha not configured.", "error")
    return render_template(
        "auth.html",
        turnstile_site_key=turnstile_site_key,
    )


@app.route("/auth/signup", methods=["POST"])
@limiter.limit("5 per minute")
def signup():
    """Handle user registration"""
    try:
        if not verify_turnstile(request):
            flash("Captcha verification failed. Please try again.", "error")
            return redirect(url_for("auth"))

        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        # Validate inputs
        if not email or not password or not confirm_password:
            flash("All fields are required.", "error")
            return redirect(url_for("auth"))

        # Validate email format
        if not validate_email(email):
            flash("Please enter a valid email address.", "error")
            return redirect(url_for("auth"))

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for("auth"))

        if len(password) < 8:
            flash("Password must be at least 8 characters long.", "error")
            return redirect(url_for("auth"))

        # Register user with Supabase
        client = get_active_supabase_client()

        if client is None:
            flash(
                "Authentication service is temporarily unavailable. Please try again later.",
                "error",
            )
            return redirect(url_for("auth"))

        # turnstile_token = request.form.get("cf-turnstile-response")

        response = client.auth.sign_up(
            {
                "email": email,
                "password": password,
                # "options": {
                #     "captcha_token": turnstile_token,
                # },
            }
        )

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
        logger.exception("Signup error: %s", e)
        error_message = str(e)
        if "User already registered" in error_message:
            flash("An account with this email already exists.", "error")
        else:
            # In production, show generic error; in debug, show details
            if DEBUG_MODE:
                flash(f"An error occurred: {error_message}", "error")
            else:
                flash("An error occurred. Please try again.", "error")
        return redirect(url_for("auth"))


@app.route("/auth/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    """Handle user login"""
    try:
        email = request.form.get("email")
        password = request.form.get("password")

        # Validate inputs
        if not email or not password:
            flash("Email and password are required.", "error")
            return redirect(url_for("auth"))

        # Validate email format
        if not validate_email(email):
            flash("Please enter a valid email address.", "error")
            return redirect(url_for("auth"))

        if not verify_turnstile(request):
            flash("Captcha verification failed. Please try again.", "error")
            return redirect(url_for("auth"))

        # Authenticate with Supabase
        client = get_active_supabase_client()

        if client is None:
            flash(
                "Authentication service is temporarily unavailable. Please try again later.",
                "error",
            )
            return redirect(url_for("auth"))

        turnstile_token = request.form.get("cf-turnstile-response")
        response = client.auth.sign_in_with_password(
            {
                "email": email,
                "password": password,
                "options": {
                    "captcha_token": turnstile_token,
                },
            }
        )

        if response.user and response.session:
            session["user"] = {
                "id": response.user.id,
                "email": response.user.email,
                "access_token": response.session.access_token,
                "refresh_token": response.session.refresh_token,
            }
            session.permanent = True
            flash("Login successful! Welcome back!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid email or password.", "error")
            return redirect(url_for("auth"))

    except Exception as e:
        logger.warning("Login error: %s", e)
        flash("Invalid email or password.", "error")
        return redirect(url_for("auth"))


@app.route("/auth/google")
def auth_google():
    """Initiate Google OAuth login"""
    client = get_active_supabase_client()
    if client is None:
        flash("Authentication service unavailable.", "error")
        return redirect(url_for("auth"))

    callback_url = url_for("auth_callback", _external=True)

    try:
        response = client.auth.sign_in_with_oauth(
            {"provider": "google", "options": {"redirect_to": callback_url}}
        )

        if response.url:
            return redirect(response.url)
        else:
            flash("Could not generate login URL.", "error")
            return redirect(url_for("auth"))

    except Exception as e:
        logger.exception("Google auth error: %s", e)
        flash("An error occurred initiating Google login.", "error")
        return redirect(url_for("auth"))


@app.route("/auth/callback")
def auth_callback():
    """Handle OAuth callback"""
    # Check for PKCE code flow (server-side exchange)
    code = request.args.get("code")
    if code:
        try:
            client = get_active_supabase_client()
            if not client:
                flash("Authentication service unavailable.", "error")
                return redirect(url_for("auth"))

            # Exchange code for session
            response = client.auth.exchange_code_for_session({"auth_code": code})

            if response.user and response.session:
                session["user"] = {
                    "id": response.user.id,
                    "email": response.user.email,
                    "access_token": response.session.access_token,
                    "refresh_token": response.session.refresh_token,
                }
                session.permanent = True
                flash("Successfully logged in with Google!", "success")
                return redirect(url_for("dashboard"))
            else:
                flash("Login failed. Please try again.", "error")
                return redirect(url_for("auth"))

        except Exception as e:
            logger.exception("OAuth callback error: %s", e)
            flash("An error occurred during login.", "error")
            return redirect(url_for("auth"))

    # Fallback to client-side hash handling (Implicit flow)
    return render_template("auth_callback.html")


@app.route("/auth/callback/exchange", methods=["POST"])
def auth_callback_exchange():
    """Exchange client-side tokens for server session"""
    try:
        data = request.get_json()
        access_token = data.get("access_token")
        refresh_token = data.get("refresh_token")

        if not access_token:
            return jsonify({"success": False, "error": "No access token provided"}), 400

        # Verify the token by getting the user
        client = get_active_supabase_client()
        if not client:
            return jsonify({"success": False, "error": "Service unavailable"}), 503

        user_response = client.auth.get_user(access_token)

        if user_response.user:
            session["user"] = {
                "id": user_response.user.id,
                "email": user_response.user.email,
                "access_token": access_token,
                "refresh_token": refresh_token,
            }
            session.permanent = True
            flash("Successfully logged in with Google!", "success")
            return jsonify({"success": True, "redirect": url_for("dashboard")})
        else:
            return jsonify({"success": False, "error": "Invalid token"}), 401

    except Exception as e:
        logger.exception("Token exchange error: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/auth/verify-email", methods=["GET", "POST"])
@limiter.limit("10 per minute")
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

            if response.user and response.session:
                # Clear pending verification
                session.pop("pending_verification", None)

                # Set user session
                session["user"] = {
                    "id": response.user.id,
                    "email": response.user.email,
                    "access_token": response.session.access_token,
                    "refresh_token": response.session.refresh_token,
                }
                session.permanent = True
                flash("Email verified successfully! Welcome!", "success")
                return redirect(url_for("dashboard"))
            else:
                flash("Invalid or expired verification code.", "error")
                return render_template("verify_email.html", email=pending["email"])

        except Exception as e:
            logger.warning("Verification error: %s", e)
            flash("Invalid or expired verification code. Please try again.", "error")
            return render_template("verify_email.html", email=pending["email"])

    return render_template("verify_email.html", email=pending["email"])


@app.route("/auth/resend-code", methods=["POST"])
@limiter.limit("3 per minute")
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
        logger.warning("Resend error: %s", e)
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
        "date": datetime.now(timezone.utc).date().isoformat(),
    }
    session.permanent = False  # Guest sessions expire when browser closes

    flash(
        f"Welcome, Guest! Today's topic is: {daily_topic}. You can attempt up to 3 quizzes today.",
        "info",
    )
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
        try:
            stats = get_user_statistics(
                user["id"], access_token=user.get("access_token")
            )
        except Exception as e:
            # Check if JWT expired
            if "JWT expired" in str(e) or "PGRST303" in str(e):
                logger.info("Access token expired, attempting refresh")
                refreshed_session = refresh_user_token(user)
                if refreshed_session:
                    session["user"] = refreshed_session
                    user = refreshed_session
                    # Retry with new token
                    try:
                        stats = get_user_statistics(
                            user["id"], access_token=user.get("access_token")
                        )
                    except Exception as retry_e:
                        logger.exception(
                            "Error fetching stats after token refresh: %s", retry_e
                        )
                        stats = None
                else:
                    # Token refresh failed, clear session and redirect to login
                    logger.warning("Token refresh failed, logging out user")
                    session.clear()
                    flash("Your session has expired. Please login again.", "info")
                    return redirect(url_for("auth"))
            else:
                logger.exception("Error fetching user statistics: %s", e)
                stats = None

    # For guests, limit to daily topic only
    guest_attempts = 0
    guest_attempts_remaining = 0
    if DEBUG_MODE:
        logger.debug("Guest session: %s", guest)
    if guest and not user:
        topics = [guest["daily_topic"]]
        guest_attempts = guest.get("attempts", 0)
        guest_attempts_remaining = max(0, 3 - guest_attempts)

    return render_template(
        "dashboard.html",
        topics=topics,
        stats=stats,
        is_guest=guest and guest["is_guest"] and not user,
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
    # Defensive parsing of numeric parameters
    try:
        num_questions = int(request.form.get("num_questions", 10))
    except (TypeError, ValueError):
        num_questions = 10
    time_limit_raw = request.form.get("time_limit", None)

    # Validate topic exists
    if not topic:
        flash("Please select a topic.", "error")
        return redirect(url_for("dashboard"))

    if time_limit_raw:
        try:
            time_limit = int(time_limit_raw)
        except (TypeError, ValueError):
            time_limit = None
    else:
        time_limit = None

    # Validate topic for guests
    if guest and not user:
        today_iso = datetime.now(timezone.utc).date().isoformat()
        guest_date = guest.get("date")
        if guest_date != today_iso:
            guest["date"] = today_iso
            guest["attempts"] = 0

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
        "start_time": datetime.now(timezone.utc).isoformat(),
        "current_question": 0,
        "answers": {},
    }

    if guest and not user:
        guest["attempts"] = guest.get("attempts", 0) + 1
        session["guest"] = guest

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

    # Calculate elapsed time using UTC
    start_time = datetime.fromisoformat(quiz_state["start_time"])
    current_time = datetime.now(timezone.utc)
    elapsed_seconds = int((current_time - start_time).total_seconds())

    # Check if time limit exceeded
    if quiz_state["time_limit"] and elapsed_seconds >= quiz_state["time_limit"] * 60:
        flash("Time limit exceeded. Quiz auto-submitted.", "warning")
        return redirect(url_for("submit_quiz", quiz_id=quiz_id))

    quiz_data = dict(quiz_state)
    quiz_data["questions"] = questions
    quiz_data["answers"] = {
        int(key): value for key, value in quiz_data.get("answers", {}).items()
    }

    if DEBUG_MODE:
        logger.debug("Quiz %s loaded with %d questions", quiz_id, len(questions))

    return render_template(
        "quiz.html",
        quiz_id=quiz_id,
        quiz_data=quiz_data,
        elapsed_seconds=elapsed_seconds,
        server_time=current_time.isoformat(),
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

    # Calculate time taken using UTC
    start_time = datetime.fromisoformat(quiz_state["start_time"])
    time_taken = int((datetime.now(timezone.utc) - start_time).total_seconds())

    # Save results for authenticated users
    results = None
    if user:
        # Convert time limit from minutes (UI/session) to seconds for persistence
        time_limit_minutes = quiz_state.get("time_limit")
        time_limit_seconds = (
            int(time_limit_minutes) * 60
            if isinstance(time_limit_minutes, int)
            else None
        )

        try:
            results = save_quiz_results(
                user_id=user["id"],
                topic=quiz_state["topic"],
                questions=questions,
                answers=quiz_state["answers"],
                time_taken=time_taken,
                time_limit=time_limit_seconds,
                access_token=user.get("access_token"),
            )
        except Exception as e:
            # Check if JWT expired
            if "JWT expired" in str(e) or "PGRST303" in str(e):
                logger.info(
                    "Access token expired during quiz submission, attempting refresh"
                )
                refreshed_session = refresh_user_token(user)
                if refreshed_session:
                    session["user"] = refreshed_session
                    user = refreshed_session
                    # Retry with new token
                    try:
                        results = save_quiz_results(
                            user_id=user["id"],
                            topic=quiz_state["topic"],
                            questions=questions,
                            answers=quiz_state["answers"],
                            time_taken=time_taken,
                            time_limit=time_limit_seconds,
                            access_token=user.get("access_token"),
                        )
                    except Exception as retry_e:
                        logger.exception(
                            "Error saving quiz results after token refresh: %s", retry_e
                        )
                        flash("Failed to save quiz results. Please try again.", "error")
                        return redirect(url_for("dashboard"))
                else:
                    # Token refresh failed, clear session and redirect to login
                    logger.warning("Token refresh failed during quiz submission")
                    session.clear()
                    flash("Your session has expired. Please login again.", "info")
                    return redirect(url_for("auth"))
            else:
                logger.exception("Error saving quiz results: %s", e)
                flash("Failed to save quiz results. Please try again.", "error")
                return redirect(url_for("dashboard"))

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
                # Transform quiz_details into quiz_data format for the template
                quiz_data = None
                if quiz_details.get("answers"):
                    # Build questions array and answers dict from user_answers
                    # get_quiz_details now returns complete question data with all options
                    questions_list = []
                    answers_dict = {}
                    seen_question_ids = set()

                    for answer in quiz_details["answers"]:
                        question_data = answer.get("questions")
                        question_id = answer.get("question_id")

                        # Add complete question data (only once per question)
                        if question_data and question_id not in seen_question_ids:
                            questions_list.append(question_data)
                            seen_question_ids.add(question_id)

                        # Add selected answer to answers dict (can be None for unanswered)
                        if question_id:
                            answers_dict[question_id] = answer.get("selected_option_id")

                    if questions_list:
                        quiz_data = {
                            "questions": questions_list,
                            "answers": answers_dict,
                        }

                return render_template(
                    "results.html",
                    results=quiz_details,
                    quiz_data=quiz_data,
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
    from datetime import datetime

    from utils.database import get_quiz_history

    user = session.get("user")

    if not user:
        flash("Please login to view your quiz history.", "error")
        return redirect(url_for("auth"))

    # Get quiz history
    history_data = get_quiz_history(user["id"], limit=50)

    # Convert completed_at strings to datetime objects
    for quiz in history_data:
        if quiz.get("completed_at") and isinstance(quiz["completed_at"], str):
            try:
                # Parse ISO format datetime string
                quiz["completed_at"] = datetime.fromisoformat(
                    quiz["completed_at"].replace("Z", "+00:00")
                )
            except (ValueError, AttributeError):
                quiz["completed_at"] = None

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

    # Transform quiz_details into quiz_data format for the template
    quiz_data = None
    if quiz_details.get("answers"):
        # Build questions array and answers dict from user_answers
        # get_quiz_details now returns complete question data with all options
        questions_list = []
        answers_dict = {}
        seen_question_ids = set()

        for answer in quiz_details["answers"]:
            question_data = answer.get("questions")
            question_id = answer.get("question_id")

            # Add complete question data (only once per question)
            if question_data and question_id not in seen_question_ids:
                questions_list.append(question_data)
                seen_question_ids.add(question_id)

            # Add selected answer to answers dict (can be None for unanswered)
            if question_id:
                answers_dict[question_id] = answer.get("selected_option_id")

        if questions_list:
            quiz_data = {"questions": questions_list, "answers": answers_dict}

    return render_template(
        "results.html",
        results=quiz_details,
        quiz_data=quiz_data,
        is_history=True,
        time_formatted=format_time(quiz_details.get("time_taken", 0)),
    )


# ============================================================================
# API ENDPOINTS
# ============================================================================


@app.route("/api/topics")
@limiter.limit("100 per minute")
def api_topics():
    """Get all available topics"""
    from utils.database import get_all_topics

    try:
        topics = get_all_topics()
        return jsonify({"success": True, "topics": topics})
    except Exception as e:
        logger.exception("Error fetching topics: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/questions")
@limiter.limit("100 per minute")
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
        logger.exception("Error fetching questions: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/quiz/submit", methods=["POST"])
@limiter.limit("30 per minute")
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

        # Calculate time taken using UTC
        start_time = datetime.fromisoformat(quiz_data["start_time"])
        time_taken = int((datetime.now(timezone.utc) - start_time).total_seconds())

        questions = get_questions_by_ids(quiz_data.get("question_ids", []))

        if not questions:
            return (
                jsonify({"success": False, "error": "Unable to load questions."}),
                500,
            )

        # Save results (convert time limit from minutes to seconds)
        time_limit_minutes = quiz_data.get("time_limit")
        time_limit_seconds = (
            int(time_limit_minutes) * 60
            if isinstance(time_limit_minutes, int)
            else None
        )

        try:
            results = save_quiz_results(
                user_id=user["id"],
                topic=quiz_data["topic"],
                questions=questions,
                answers=answers,
                time_taken=time_taken,
                time_limit=time_limit_seconds,
                access_token=user.get("access_token"),
            )
        except Exception as save_error:
            # Check if JWT expired
            if "JWT expired" in str(save_error) or "PGRST303" in str(save_error):
                logger.info(
                    "Access token expired during API quiz submission, attempting refresh"
                )
                refreshed_session = refresh_user_token(user)
                if refreshed_session:
                    session["user"] = refreshed_session
                    # Retry with new token
                    try:
                        results = save_quiz_results(
                            user_id=refreshed_session["id"],
                            topic=quiz_data["topic"],
                            questions=questions,
                            answers=answers,
                            time_taken=time_taken,
                            time_limit=time_limit_seconds,
                            access_token=refreshed_session.get("access_token"),
                        )
                    except Exception as retry_e:
                        logger.exception(
                            "Error saving quiz results after token refresh: %s", retry_e
                        )
                        return (
                            jsonify(
                                {"success": False, "error": "Failed to save results"}
                            ),
                            500,
                        )
                else:
                    # Token refresh failed
                    logger.warning("Token refresh failed during API quiz submission")
                    session.clear()
                    return (
                        jsonify(
                            {
                                "success": False,
                                "error": "Session expired",
                                "redirect": "/auth",
                            }
                        ),
                        401,
                    )
            else:
                raise  # Re-raise non-JWT errors to be caught by outer exception handler

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
        logger.exception("Error submitting quiz: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/stats")
@limiter.limit("60 per minute")
def api_stats():
    """Get user statistics"""
    user = session.get("user")

    if not user:
        return jsonify({"success": False, "error": "Authentication required"}), 401

    try:
        stats = get_user_statistics(user["id"], access_token=user.get("access_token"))
        return jsonify({"success": True, "stats": stats})
    except Exception as e:
        # Check if JWT expired
        if "JWT expired" in str(e) or "PGRST303" in str(e):
            logger.info("Access token expired, attempting refresh")
            refreshed_session = refresh_user_token(user)
            if refreshed_session:
                session["user"] = refreshed_session
                # Retry with new token
                try:
                    stats = get_user_statistics(
                        refreshed_session["id"],
                        access_token=refreshed_session.get("access_token"),
                    )
                    return jsonify({"success": True, "stats": stats})
                except Exception as retry_e:
                    logger.exception(
                        "Error fetching stats after token refresh: %s", retry_e
                    )
                    return (
                        jsonify(
                            {"success": False, "error": "Failed to fetch statistics"}
                        ),
                        500,
                    )
            else:
                # Token refresh failed
                logger.warning("Token refresh failed")
                session.clear()
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": "Session expired",
                            "redirect": "/auth",
                        }
                    ),
                    401,
                )
        else:
            logger.exception("Error fetching stats: %s", e)
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


@app.errorhandler(413)
def request_too_large(error):
    """Handle 413 Request Entity Too Large errors"""
    return (
        jsonify(
            {"success": False, "error": "Request too large. Maximum size is 16MB."}
        ),
        413,
    )


@app.route("/health")
def health_check():
    """Health check endpoint for monitoring"""
    try:
        # Optionally check database connection
        client = get_active_supabase_client()
        db_status = "connected" if client is not None else "disconnected"
    except Exception:
        db_status = "error"

    return (
        jsonify(
            {
                "status": "healthy",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "database": db_status,
            }
        ),
        200,
    )


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    # Safer default is non-debug
    debug_mode = os.getenv("DEBUG", "False") == "True"
    if not debug_mode:
        app.config["SESSION_COOKIE_SECURE"] = True
    # In production, run behind a WSGI server like gunicorn
    app.run(debug=debug_mode, host="0.0.0.0", port=5000)
