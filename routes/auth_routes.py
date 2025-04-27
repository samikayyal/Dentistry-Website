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

from routes.base_routes import login_required
from utils.supabase_utils import get_user_from_session, is_valid_credentails_for_signup
from utils.utils import format_datetime

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

    return render_template("user_management/signup.html")


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

    return render_template("user_management/signin.html")


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


@auth_bp.route("/profile")
@login_required
def profile():
    """
    Route to display the user's profile information.
    """
    # Access the user from g object
    user = g.user
    print(user)
    print(type(user.created_at))
    user_created_at = (
        format_datetime(str(user.created_at), method="month year") if user else None
    )
    return render_template(
        "user_management/profile.html", user=user, user_created_at=user_created_at
    )


@auth_bp.route("/profile/change_email", methods=["POST"])
@login_required
def change_email():
    """
    Route to change the user's email address.
    """
    new_email = request.form.get("new_email")
    supabase = g.supabase_client
    # Basic validation
    if not new_email:
        flash("New email is required.", "danger")
        return redirect(url_for("auth.profile"))
    try:
        response = supabase.auth.update_user({"email": new_email})
        if hasattr(response, "user") and response.user:
            flash(
                "Email updated successfully. Please check your new email for a confirmation link.",
                "success",
            )
        else:
            flash("Failed to update email. Please try again.", "danger")
    except Exception as e:
        flash(f"Failed to update email: {e}", "danger")
    return redirect(url_for("auth.profile"))


@auth_bp.route("/profile/change_password", methods=["POST"])
@login_required
def change_password():
    """
    Route to change the user's password.
    """
    current_password = request.form.get("current_password")
    new_password = request.form.get("new_password")
    confirm_new_password = request.form.get("confirm_new_password")
    supabase = g.supabase_client
    # Basic validation
    if not current_password or not new_password or not confirm_new_password:
        flash("All fields are required.", "danger")
        return redirect(url_for("auth.profile"))
    if new_password != confirm_new_password:
        flash("New passwords do not match.", "danger")
        return redirect(url_for("auth.profile"))
    if len(new_password) < 8:
        flash("New password must be at least 8 characters.", "danger")
        return redirect(url_for("auth.profile"))
    try:
        # Re-authenticate user
        user = supabase.auth.sign_in_with_password(
            {"email": g.user.email, "password": current_password}
        )
        if not user or not user.user:
            flash("Current password is incorrect.", "danger")
            return redirect(url_for("auth.profile"))
        # Update password
        response = supabase.auth.update_user({"password": new_password})
        if hasattr(response, "user") and response.user:
            flash("Password updated successfully.", "success")
        else:
            flash("Failed to update password. Please try again.", "danger")
    except Exception as e:
        flash(f"Failed to update password: {e}", "danger")
    return redirect(url_for("auth.profile"))


@auth_bp.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email")
        if not email:
            flash("Email is required.", "danger")
            return redirect(url_for("auth.forgot_password"))
        try:
            # Access the supabase client from the app context
            redirect_url = url_for("auth.reset_password", _external=True)
            supabase = g.supabase_client
            supabase.auth.reset_password_for_email(
                email,
                options={
                    "redirect_to": redirect_url,
                },
            )

            flash(
                "Password reset email sent successfully. Please check your inbox.",
                "success",
            )

        except Exception as e:
            print("Error during password reset:", e)
            flash("An error occurred. Please try again.", "danger")
            return redirect(url_for("auth.forgot_password"))

        return redirect(url_for("auth.signin"))

    return render_template("user_management/forgot_password.html")


@auth_bp.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        new_password = request.form.get("new_password")
        confirm_new_password = request.form.get("confirm_password")
        access_token = request.form.get("access_token")
        refresh_token = request.form.get("refresh_token")

        # Validation
        if not new_password or not confirm_new_password:
            flash("All fields are required.", "danger")
            return redirect(url_for("auth.reset_password"))
        if len(new_password) < 8:
            flash("New password must be at least 8 characters.", "danger")
            return redirect(url_for("auth.reset_password"))
        if new_password != confirm_new_password:
            flash("New passwords do not match.", "danger")
            return redirect(url_for("auth.reset_password"))
        if not access_token or not refresh_token:
            flash(
                "Missing recovery token. Please try the reset link again or request a new one.",
                "danger",
            )
            return redirect(url_for("auth.forgot_password"))

        try:
            supabase = g.supabase_client
            # Set the session with the provided access and refresh tokens
            res = supabase.auth.set_session(access_token, refresh_token)

            if not res.user:
                flash(
                    "Invalid or expired recovery token. Please request a new one.",
                    "danger",
                )
                return redirect(url_for("auth.forgot_password"))

            # Now we can update the password
            response = supabase.auth.update_user({"password": new_password})
            if hasattr(response, "user") and response.user:
                flash("Password reset successfully. You can now sign in.", "success")
                return redirect(url_for("auth.signin"))
            else:
                flash("Failed to reset password. Please try again.", "danger")

        except Exception as e:
            print("Error during password reset:", e)
            flash("An error occurred. Please try again.", "danger")

    # For GET requests, just render the template
    return render_template("user_management/reset_password.html")
