from datetime import timedelta

from dotenv import load_dotenv
from flask import Flask, g, session

from routes import auth_bp, base_bp, test_bp

# from utils.local_db_utils import get_table_names
from utils.supabase_utils import get_supabase_client, get_test_history

load_dotenv()

app = Flask(__name__)
app.secret_key = "your-secret-key"  # Replace with a secure secret key
app.permanent_session_lifetime = timedelta(days=30)

# Initialize Supabase client (global)
supabase_client = get_supabase_client()


@app.before_request
def load_user():
    """
    Load the user from the session and store in flask.g for each request.
    Attempts to restore session from Flask session cookie if available.
    Also makes the supabase client available in the g object.
    """
    # Make supabase client available to all routes
    g.supabase_client = supabase_client

    # Initialize user as None
    g.user = None
    access_token = session.get("supabase_access_token")
    refresh_token = session.get("supabase_refresh_token")

    if access_token and refresh_token:
        try:
            # Try setting the session first
            supabase_client.auth.set_session(access_token, refresh_token)
            user_response = supabase_client.auth.get_user()

            if user_response and user_response.user:
                g.user = user_response.user
                session.permanent = True
            else:
                # If get_user fails with current tokens, try refreshing
                print("Attempting to refresh Supabase session...")
                refresh_response = supabase_client.auth.refresh_session(refresh_token)
                if refresh_response and refresh_response.user:
                    print("Session refreshed successfully.")
                    g.user = refresh_response.user
                    # Update session cookies with new tokens
                    session["supabase_access_token"] = (
                        refresh_response.session.access_token
                    )
                    session["supabase_refresh_token"] = (
                        refresh_response.session.refresh_token
                    )
                    session.permanent = True
                else:
                    print("Failed to refresh session or no user found after refresh.")
                    # Clear invalid tokens from session
                    session.pop("supabase_access_token", None)
                    session.pop("supabase_refresh_token", None)

        except Exception as e:
            print(f"Error restoring Supabase session: {e}")
            # Clear potentially invalid tokens on error
            session.pop("supabase_access_token", None)
            session.pop("supabase_refresh_token", None)
    # else: No tokens in session, g.user remains None


# Register all blueprints
app.register_blueprint(auth_bp, url_prefix="")
app.register_blueprint(base_bp, url_prefix="")
app.register_blueprint(test_bp, url_prefix="")


if __name__ == "__main__":
    print("Registered routes:")
    print(app.url_map)
    app.run(debug=True, host="0.0.0.0", port=5000)
