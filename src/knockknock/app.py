import flask
import knockknock.hibp

app = flask.Flask(__name__)


@app.route("/")
def main_page():
    """Render the main page.

    This page asks whether to log in via department credentials or via RIT SSO.
    """
    return flask.render_template("choose_login.html.j2")


@app.route("/login-dept")
def department_login():
    """Ask for department credentials, then redirect to the reset page."""
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
    return flask.render_template("reset.html.j2")


@app.route("/reset", methods=["POST"])
def do_reset():
    """Handle the password reset request."""
    request = flask.request
    if "password" not in request.form:
        return flask.render_template(
            "reset.html.j2", error="missing request parameter: password"
        )
    if "confirmPassword" not in request.form:
        return flask.render_template(
            "reset.html.j2", error="missing request parameter: confirmPassword"
        )
    password = request.form["password"]
    confirm = request.form["confirmPassword"]
    if password != confirm:
        return flask.render_template(
            "reset.html.j2",
            error="The passwords you entered didn’t match. Please try again.",
        )
    # TODO: check password against character class rules
    breach_count = knockknock.hibp.check_password(password)
    if breach_count > 0:
        return flask.render_template(
            "reset.html.j2",
            error="The password you entered has been found in {} prior data breaches.  Please choose a new one.".format(
                breach_count
            ),
        )

    return flask.redirect(flask.url_for("success_page"))


@app.route("/success")
def success_page():
    """Confirm to the user that their password reset succeeded."""
    return "Password was reset!"


@app.route("/error")
def error_page():
    """Display a useful error message to the user."""
    return "Error page."
