import functools
import flask
from enum import Enum
import datetime

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


@bp.route("/dept")
def department_login():
    """Ask for department credentials, then redirect to the reset page."""
    # TODO: set session variables username, method, date
    # TODO: return 403
    # TODO: figure out how to keep track of password attempt count and return
    # 401 after 3 failures
    return flask.redirect(flask.url_for("reset"))


@bp.route("/sso")
def sso_login():
    """Bounce the user through SAML authentication, then redirect to the reset
    page.
    """
    # TODO: hook up OneLogin's SAML toolkit here, probably with several
    # additional endpoints.
    return flask.redirect(flask.url_for("reset"))
