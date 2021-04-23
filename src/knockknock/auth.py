import functools
import flask
from enum import Enum
import datetime
import knockknock.app
from knockknock.ldap import LDAPClient
import ldap3.core.exceptions
import logging
from urllib.parse import urlparse
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils

logger = logging.getLogger(__name__)

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


class LoginMethod(int, Enum):
    SSO = 1
    DEPT = 2


def login_required(view):
    @functools.wraps(view)
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
            logger.info("no session cookie, bouncing to main page for login")
            return flask.redirect(flask.url_for("main_page"))
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
            logger.info("session cookie expired, bouncing to main page for login")
            return flask.redirect(flask.url_for("main_page"))
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
        logger.debug("no authorization header present; sending 401")
        return make_401()
    c = LDAPClient(knockknock.app.get_active_config())
    try:
        password_match = c.check_password(auth.username, auth.password)
    except ldap3.core.exceptions.LDAPException as e:
        logger.exception(
            "Encountered exception while checking LDAP password for user "
            "{username}:".format(username=auth.username)
        )
        logger.exception(e)
        return flask.render_template("error.html.j2", message=e)
    if password_match:
        flask.session["username"] = auth.username
        flask.session["method"] = LoginMethod.DEPT
        flask.session["date"] = datetime.datetime.now()
        logger.info(
            "accepted login for {username} using LDAP credentials".format(
                username=auth.username
            )
        )
        return flask.redirect(flask.url_for("do_reset"))
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


#############################
# SAML endpoints below here #
#############################


def init_saml_auth(req):
    config = knockknock.app.get_active_config()
    auth = OneLogin_Saml2_Auth(req, custom_base_path=config.saml_config_dir)
    return auth


def prepare_flask_request(req):
    url_data = urlparse(req.url)
    return {
        "https": "on" if req.scheme == "https" else "off",
        "http_host": req.host,
        "server_port": url_data.port,
        "script_name": req.path,
        "get_data": req.args.copy(),
        "post_data": req.form.copy(),
    }


@bp.route("/saml/sso")
def saml_sso():
    """Redirect clients to the IdP for authentication.
    SAMLv2 allows SSO flows to begin at the SP (as opposed to SAMLv1, which
    required all SSO flows to begin at the IdP).  All this does is bounce the
    client to the IdP for authentication and tell the IdP where the client
    should come back to when they're done.
    """
    req = prepare_flask_request(flask.request)
    auth = init_saml_auth(req)
    return_to = "{}reset".format(flask.request.host_url)
    return flask.redirect(auth.login(return_to=return_to))


@bp.route("/saml/slo")
def saml_slo():
    """Redirect users to the IdP for logout."""
    req = prepare_flask_request(flask.request)
    auth = init_saml_auth(req)
    name_id = flask.session["samlNameId"] if "samlNameId" in flask.session else None
    session_index = (
        flask.session["samlSessionIndex"]
        if "samlSessionIndex" in flask.session
        else None
    )
    return flask.redirect(auth.logout(name_id=name_id, session_index=session_index))


@bp.route("/saml/acs")
def saml_acs():
    """Consume attributes returned by the IdP and forward the user to the reset
    page.
    """
    req = prepare_flask_request(flask.request)
    auth = init_saml_auth(req)
    auth.process_response()
    errors = auth.get_errors()
    if len(errors) == 0:
        if not auth.is_authenticated():
            return flask.render_template(
                "error.html.j2",
                message="RIT's Single-Sign On service says that you're not authenticated!",
            )
        flask.session["saml_userdata"] = auth.get_attributes()
        flask.session["saml_nameId"] = auth.get_nameid()
        flask.session["saml_sessionIndex"] = auth.get_session_index()
        flask.session["method"] = LoginMethod.SSO
        flask.session["date"] = datetime.datetime.now()
        flask.session["username"] = flask.session["samlUserdata"].get(
            "urn:oid:0.9.2342.19200300.100.1.1"
        )[0]
        logger.info(
            "accepted login for {username} using SSO credentials".format(
                username=auth.username
            )
        )
        # TODO: is this necessary?
        #         if not is_user(flask.session["username"]):
        #             return flask.render_template("error.html.j2", message="You're not an authorized user of this application.")
        self_url = OneLogin_Saml2_Utils.get_self_url(req)
        if (
            "RelayState" in flask.request.form
            and self_url != flask.request.form["RelayState"]
        ):
            return flask.redirect(auth.redirect_to(flask.request.form["RelayState"]))
        else:
            return flask.render_template(
                "error.html.j2",
                message="There was an error while handling the SAML response: "
                + str(auth.get_last_error_reason()),
            )


@bp.route("/saml/sls")
def saml_sls():
    """I haven't figured out what SLS is yet, I think it happens after SLO."""
    req = prepare_flask_request(flask.request)
    auth = init_saml_auth(req)
    url = auth.process_slo(delete_session_cb=lambda: flask.session.clear())
    errors = auth.get_errors()
    if len(errors) == 0:
        if url is not None:
            return flask.redirect(url)
        # TODO: this should probably handle errors.
    return flask.redirect(flask.url_for("main_page"))
