import functools
import flask
from enum import Enum
import datetime
import knockknock.app
from knockknock.ldap import LDAPClient
import ldap3.core.exceptions

bp = flask.Blueprint("auth", __name__, url_prefix="/auth")

# Authentication notes:
# Werkzeug puts an authorization object into flask.request that I can use to
# check for HTTP Basic credentials.
# The OneLogin SAML library hook can easily be used to set something in the
# session.
# I can define a decorator function that checks the session object for which
# kind of auth the user is logged in using, and then verifies that they have it.
# Flask cryptographically signs the session cookie, so the user can't tamper
# with it.


class LoginMethod(Enum):
    SSO = 1
    DEPT = 2


def login_required(view):
    @functools.wrap(view)
    def wrapped_view(**kwargs):
        """Check if the user has logged in.
        If they have not, bounce them back to the main page so they can log in.
        """
        flask.g.username = flask.session.get("username")
        flask.g.signin_method = flask.session.get("method")
        flask.g.signin_date = flask.session.get("date")
        if (
            flask.g.username is None
            or flask.g.signin_method is None
            or flask.g.signin_date is None
        ):
            return flask.redirect(flask.url_for("auth.choose_login"))
        # I have arbitrarily decided that 30 minutes is an acceptable limit for
        # session lengths.  It's long enough to not irritate people, even people
        # with motor difficulties, but short enough that session cookie thefts
        # shouldn't be too great a risk.
        # It may be worth figuring out how to attach a unique ID to each session
        # and invalidate that ID after a reset occurs, so that someone can't
        # steal a session cookie and use it to reset a password again.
        if (datetime.datetime.now() - flask.g.signin_date) > datetime.timedelta(
            minutes=30
        ):
            return flask.redirect(flask.url_for("auth.choose_login"))
        return view(**kwargs)

    return wrapped_view


def make_401():
    resp = flask.make_response("Credentials required.", 401)
    resp.headers["WWW-Authenticate"] = "Basic realm=KnockKnock Authorization"
    return resp


@bp.route("/dept")
def department_login():
    """Ask for department credentials, then redirect to the reset page."""
    auth = flask.request.authorization
    if auth is None or auth.username is None or auth.password is None:
        return make_401()
    # TODO: implement that function in knockknock.app
    c = LDAPClient(knockknock.app.get_active_config())
    try:
        password_match = c.check_password(auth.username, auth.password)
    except ldap3.core.exceptions.LDAPException as e:
        return flask.render_template("error.html.j2", message=e)
    if password_match:
        flask.session["username"] = auth.username
        flask.session["method"] = LoginMethod.SSO
        flask.session["date"] = datetime.datetime.now()
        return flask.redirect(flask.url_for("reset"))
    else:
        guess_count = flask.session.get("ldap_password_guesses", 0)
        if guess_count < 3:
            flask.session["ldap_password_guesses"] = guess_count + 1
            return make_401()
        else:
            # If you don't do this, people get stuck until they clear their
            # cookies.
            flask.session["ldap_password_guesses"] = 0
            return "403 Unauthorized", 403


@bp.route("/sso")
def sso_login():
    """Bounce the user through SAML authentication, then redirect to the reset
    page.
    """
    # TODO: hook up OneLogin's SAML toolkit here, probably with several
    # additional endpoints.
    return flask.redirect(flask.url_for("reset"))
