import ldap3
import ssl
from knockknock.config import Config
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class LDAPUserMissing(ldap3.core.exceptions.LDAPException):
    pass


class LDAPUserNotUnique(ldap3.core.exceptions.LDAPException):
    pass


class LDAPClient:
    """A client for accessing an LDAP server."""

    def __init__(self, config: Config):
        self.config = config
        if self.config.no_certificate_checks:
            self.tls = ldap3.Tls(validate=ssl.CERT_NONE)
        else:
            self.tls = ldap3.Tls()
        self.server = ldap3.Server(self.config.ldap_url, tls=self.tls)
        logger.debug("initialized client for {url}".format(url=self.config.ldap_url))

    def find_dn_using_connection(self, username: str, connection: ldap3.Connection) -> Optional[str]:
        """Find the distinguished name for a particular user in LDAP.
        This function will raise an LDAPUserNotUnique exception if multiple
        records are returned for a single username, because there is not a
        secure way to disambiguate.  This function requires you to already have
        a connection to LDAP.  If you don't, use find_dn(user), which will open
        one for you.

        :param username: The username of the user to find the DN for.
        :param connection: The connection to the LDAP server to use for finding
        the DN.
        :return: The user's distinguished name, or None if the user is not in LDAP.
        """
        search_filter = self.config.ldap_filter.format(uid=username)
        logger.debug(
            "searching for distinguished name for {username} using "
            'filter "{filter}"'.format(username=username, filter=search_filter)
        )
        connection.search(
            self.config.ldap_base,
            "({filter})".format(filter=search_filter),
            ldap3.SUBTREE,
        )
        if connection.response and len(connection.response) == 1:
            logger.debug("found dn: {dn}".format(dn=connection.response[0]["dn"]))
            return connection.response[0]["dn"]
        elif connection.response is None or len(connection.response) == 0:
            logger.info(
                "could not find dn for {username}, response was None or "
                "contained 0 records".format(username=username)
            )
            return None
        else:
            raise LDAPUserNotUnique(
                "found {number} results for the username {username} in LDAP; "
                "unable to determine whose password to reset".format(
                    username=username, number=len(connection.response)
                )
            )

    def find_dn(self, username: str) -> Optional[str]:
        """Find the distinguished name for a particular user in LDAP.
        This function will raise a NonUniqueUser exception if multiple records
        are returned for a single username, because there is not a secure way to
        disambiguate.  This function will open a connection using the configured
        credentials in LDAP.  If you don't want that, use
        find_dn_using_connection(user, connection).

        :param username: The username of the user to find the DN for.
        :return: The user's distinguished name, or None if the user is not in LDAP.
        """
        with ldap3.Connection(
                self.server,
                user=self.config.ldap_username,
                password=self.config.ldap_password,
        ) as connection:
            connection.bind()
            return self.find_dn_using_connection(username, connection)

    def check_password(self, username: str, password: str) -> bool:
        logger.debug("checking password for {username}".format(username=username))
        dn = self.find_dn(username)
        with ldap3.Connection(
            self.server,
            dn,
            password,
        ) as connection:
            logger.debug(str(connection))
            # Bind returns true if the password is valid and false if it
            # isn't.  It throws an exception when there's a connection
            # problem.  This is not documented, but I fooled around with it
            # in a test shell for a while to figure it out.
            return connection.bind()

    def reset_password(self, username: str, password: str):
        logger.debug("changing password for {username}".format(username=username))
        with ldap3.Connection(
            self.server,
            user=self.config.ldap_username,
            password=self.config.ldap_password,
        ) as connection:
            logger.debug(str(connection))
            connection.bind()
            user_dn = self.find_dn_using_connection(username, connection)
            if user_dn is None:
                raise LDAPUserMissing("{username} is not a registered user")
            return connection.extend.microsoft.modify_password(user_dn, password)
