from flask import (
    Blueprint,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from utils.supabase_utils import is_valid_credentails_for_signup

# Create a blueprint for auth routes
auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/signup", methods=["GET", "POST"])
def signup():
    """
    Route for user signup.
    """
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        error = is_valid_credentails_for_signup(email, password, confirm_password)

        if error:
            flash(error, "danger")
            return redirect(url_for("auth.signup"))

        try:
            # Access the supabase client from the app context
            supabase = g.supabase_client
            response = supabase.auth.sign_up({"email": email, "password": password})

            print("Signup response user:", response.user)
            print("Signup response session:", response.session)

            if response.user:
                flash("Signup successful!", "success")
        except Exception as e:
            print("Error during signup:", e)
            flash("Signup failed. Please try again.", "danger")
            return redirect(url_for("auth.signup"))

        return redirect(url_for("base.index"))

    return render_template("signup.html")


@auth_bp.route("/signin", methods=["GET", "POST"])
def signin():
    """
    Route for user sign-in. Stores session tokens on success.
    """
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        if not email or not password:
            flash("Email and password are required.", "warning")
            return redirect(url_for("auth.signin"))
        try:
            # Access the supabase client from the app context
            supabase = g.supabase_client
            response = supabase.auth.sign_in_with_password(
                {"email": email, "password": password}
            )

            print("Signin response user:", response.user)
            print("Signin response session:", response.session)

            if response.user and response.session:
                # Store tokens in Flask session
                session["supabase_access_token"] = response.session.access_token
                session["supabase_refresh_token"] = response.session.refresh_token
                session.permanent = True
                flash("Signin successful!", "success")
                return redirect(url_for("base.index"))
            else:
                flash("Signin failed. Please check your credentials.", "danger")
                return redirect(url_for("auth.signin"))

        except Exception as e:
            print("Error during signin:", e)
            # TODO: Check for specific Supabase errors if possible, e.g., invalid credentials
            flash("An error occurred during signin. Please try again.", "danger")
            return redirect(url_for("auth.signin"))

    return render_template("signin.html")


@auth_bp.route("/logout")
def logout():
    """
    Route for user logout. Clears Supabase and Flask sessions.
    """
    access_token = session.get("supabase_access_token")
    if access_token:  # Only sign out if we have a token
        try:
            # Access the supabase client from the app context
            supabase = g.supabase_client
            # It's good practice to sign out the specific session if possible
            # supabase.auth.sign_out(access_token) # Check Supabase docs for exact method if needed
            supabase.auth.sign_out()  # General sign out
        except Exception as e:
            print(f"Error during Supabase sign out: {e}")
            # Continue with clearing local session anyway

    # Clear Flask session
    session.pop("supabase_access_token", None)
    session.pop("supabase_refresh_token", None)
    session.clear()  # Ensure everything is cleared
    g.user = None  # Clear g.user as well

    flash("You have been logged out successfully.", "success")
    return redirect(url_for("auth.signin"))


@auth_bp.route("/signin/google")
def signin_google():
    """
    Route to initiate Google OAuth sign-in.
    """
    try:
        # Access the supabase client from the app context
        supabase = g.supabase_client
        # Construct an absolute URL for the callback
        redirect_url = url_for("auth.auth_callback_google", _external=True)
        sign_in_url = supabase.auth.sign_in_with_oauth(
            {"provider": "google", "options": {"redirect_to": redirect_url}}
        )

        # Redirect the user to the Google sign-in page
        return redirect(sign_in_url.url)
    except Exception as e:
        print("Error during Google sign-in:", e)
        flash("Failed to initiate Google sign-in.", "danger")
        return redirect(url_for("auth.signin"))


@auth_bp.route("/auth/callback/google")
def auth_callback_google():
    """
    Callback route for Google OAuth sign-in. Stores session tokens on success.
    """
    try:
        code = request.args.get("code")
        if not code:
            flash(
                "Authentication failed: No code received. Please try again.", "danger"
            )
            return redirect(url_for("auth.signin"))

        # Access the supabase client from the app context
        supabase = g.supabase_client
        # Exchange the authorization code for a session
        session_response = supabase.auth.exchange_code_for_session({"auth_code": code})

        # Check if the session exchange was successful
        if session_response and session_response.user and session_response.session:
            # Store tokens in Flask session
            session["supabase_access_token"] = session_response.session.access_token
            session["supabase_refresh_token"] = session_response.session.refresh_token
            session.permanent = True  # Make the session persistent
            flash("Sign-in successful!", "success")
            # Session is set by Supabase client, redirect to the main page
            return redirect(url_for("base.index"))
        else:
            print(
                "Error during Google auth callback - code exchange failed:",
                session_response,
            )
            flash(
                "Authentication failed during code exchange. Please try again.",
                "danger",
            )
            return redirect(url_for("auth.signin"))

    except Exception as e:
        # Catch potential exceptions during the code exchange
        print("Error during Google auth callback:", e)
        flash(f"Authentication failed: {e}. Please try again.", "danger")
        return redirect(url_for("auth.signin"))
