import flask

app = flask.Flask(__name__)


@app.route("/")
def main_page():
    """Render the main page.

    This page asks whether to log in via department credentials or via RIT SSO.
    """
    return "Hello, world!"


@app.route("/login-dept")
def department_login():
    """Ask for department credentials, then redirect to the reset page.
    """
    return flask.redirect(flask.url_for("reset_page"))


@app.route("/login-sso")
def sso_login():
    """Bounce the user through SAML authentication, then redirect to the reset
    page.
    """
    return flask.redirect(flask.url_for("reset_page"))


@app.route("/reset", methods=["GET"])
def reset_page():
    """Render the password reset page.

    This page displays the username and asks for the password twice.
    """
    return "Password reset page."


@app.route("/reset", methods=["POST"])
def do_reset():
    """Handle the password reset.
    """
    return flask.redirect(flask.url_for("success"))


@app.route("/success")
def success_page():
    """Confirm to the user that their password reset succeeded.
    """
    return "Password was reset!"


@app.route("/error")
def error_page():
    """Display a useful error message to the user.
    """
    return "Error page."
