from functools import wraps

from flask import Blueprint, flash, g, render_template

from utils.local_db_utils import get_topics

base_bp = Blueprint("base", __name__)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.user is None:
            # flash("Please sign in to access this page.", "warning")
            from flask import redirect, url_for

            return redirect(url_for("auth.signin"))
        return f(*args, **kwargs)

    return decorated_function


@base_bp.route("/")
@login_required
def index():
    """
    Home route that returns a welcome message and lists all topics.
    """
    topics = get_topics()
    if "General" in topics:
        # make it first in the list
        topics.remove("General")
        topics.insert(0, "General")
    if not topics:
        flash("No topics available.", "warning")
    return render_template("index.html", user=g.user, topics=topics)
