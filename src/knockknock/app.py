import flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import knockknock.hibp
import knockknock.auth
import knockknock.config
from knockknock.ldap import LDAPClient
from ldap3.core.exceptions import LDAPException
import logging

logger = logging.getLogger(__name__)

app = flask.Flask(__name__)
limiter = Limiter(app, key_func=get_remote_address, default_limits=["10 per second"])
# Only allow one request per user per second on the authentication endpoints.
limiter.limit("1 per second")(knockknock.auth.bp)
app.register_blueprint(knockknock.auth.bp)
# app.config.update(
#     SESSION_COOKIE_SECURE=True,
#     SESSION_COOKIE_SAMESITE="Strict",
# )
config = knockknock.config.Config("../../etc/config.ini")


def get_active_config():
    return config


@app.route("/")
def main_page():
    """Render the main page.

    This page asks whether to log in via department credentials or via RIT SSO.
    """
    return flask.render_template("choose_login.html.j2")


@app.route("/reset", methods=["GET"])
@limiter.limit("1 per second")
@knockknock.auth.login_required
def reset_page():
    """Render the password reset page.

    This page displays the username and asks for the password twice.
    """
    return flask.render_template("reset.html.j2")


@app.route("/reset", methods=["POST"])
@limiter.limit("1 per second")
@knockknock.auth.login_required
def do_reset():
    """Handle the password reset request."""
    request = flask.request
    errors = []
    if "password" not in request.form:
        logger.info("no password provided")
        errors.append("missing request parameter: password")
    if "confirmPassword" not in request.form:
        logger.info("no password confirmation provided")
        errors.append("missing request parameter: confirmPassword")
    # The two errors above this point are fatal and prevent other checks from
    # succeeding.
    if len(errors) > 0:
        return flask.render_template("reset.html.j2", errors=errors)

    password = request.form["password"]
    confirm = request.form["confirmPassword"]
    if password != confirm:
        logger.info("password and confirmPassword didn't match")
        errors.append("The passwords you entered didn’t match.")
    if len(password) < 10:
        logger.info("password too short")
        errors.append("Your password must be at least 10 characters long.")
    # TODO: check password against character class rules, pending discussion
    # about NIST guidelines
    breach_count = knockknock.hibp.check_password(password)
    if breach_count > 0:
        logger.info("password found in prior breaches")
        errors.append(
            "The password you chose has been found {} time{} in prior data breaches. (If you’re using that password on other websites, you should change it on all of them.)".format(
                breach_count, "s" if breach_count > 1 else ""
            )
        )
    if len(errors) > 0:
        return flask.render_template("reset.html.j2", errors=errors)
    else:
        c = LDAPClient(get_active_config())
        try:
            c.reset_password(flask.session["username"], password)
            del flask.session["username"]
            del flask.session["method"]
            del flask.session["date"]
            return flask.redirect(flask.url_for("success_page"))
        except LDAPException as e:
            logger.exception(e)
            errors.append(e)
            return flask.render_template("error.html.j2", message=e)


@app.route("/success")
def success_page():
    """Confirm to the user that their password reset succeeded."""
    return flask.render_template("success.html.j2")


if app.debug:
    print("WARNING: Running in development mode with insecure session key")
    app.secret_key = "THIS_IS_INSECURE"
    logging.basicConfig(level=logging.DEBUG)
