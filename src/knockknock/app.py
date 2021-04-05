import flask
import knockknock.hibp
import knockknock.auth
import knockknock.config

app = flask.Flask(__name__)
app.register_blueprint(knockknock.auth.bp)
# app.config.update(
#     SESSION_COOKIE_SECURE=True,
#     SESSION_COOKIE_SAMESITE="Strict",
# )


def get_active_config():
    return knockknock.config.Config()


@app.route("/")
def main_page():
    """Render the main page.

    This page asks whether to log in via department credentials or via RIT SSO.
    """
    return flask.render_template("choose_login.html.j2")


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
    errors = []
    if "password" not in request.form:
        errors.append("missing request parameter: password")
    if "confirmPassword" not in request.form:
        errors.append("missing request parameter: confirmPassword")
    # The two errors above this point are fatal and prevent other checks from
    # succeeding.
    if len(errors) > 0:
        return flask.render_template("reset.html.j2", errors=errors)

    password = request.form["password"]
    confirm = request.form["confirmPassword"]
    if password != confirm:
        errors.append("The passwords you entered didn’t match.")
    if len(password) < 10:
        errors.append("Your password must be at least 10 characters long.")
    # TODO: check password against character class rules, pending discussion
    # about NIST guidelines
    breach_count = knockknock.hibp.check_password(password)
    if breach_count > 0:
        errors.append(
            "The password you chose has been found {} time{} in prior data breaches. (If you’re using that password on other websites, you should change it on all of them.)".format(
                breach_count, "s" if breach_count > 1 else ""
            )
        )
    if len(errors) > 0:
        return flask.render_template("reset.html.j2", errors=errors)
    else:
        # TODO: use LDAP to change password
        return flask.redirect(flask.url_for("success_page"))


@app.route("/success")
def success_page():
    """Confirm to the user that their password reset succeeded."""
    return "Password was reset!"


@app.route("/error")
def error_page():
    """Display a useful error message to the user."""
    return "Error page."


if app.debug:
    print("WARNING: Running in development mode with insecure session key")
    app.secret_key = "THIS_IS_INSECURE"
