import ldap3
import ssl
from knockknock.config import Config
from typing import Optional


class LDAPClient:
    """A client for accessing an LDAP server."""

    def __init__(self, config: Config):
        self.config = config
        # Hacks for freezoid, because it's Server 2008R2.  The replacement is
        # taking a while to be ready.
        if self.config.use_extremely_weak_ciphers and self.config.no_certificate_checks:
            self.tls = ldap3.Tls(validate=ssl.CERT_NONE, ciphers="DEFAULT@SECLEVEL=1")
        elif self.config.use_extremely_weak_ciphers:
            self.tls = ldap3.Tls(ciphers="DEFAULT@SECLEVEL=1")
        elif self.config.no_certificate_checks:
            self.tls = ldap3.Tls(validate=ssl.CERT_NONE)
        else:
            self.tls = ldap3.Tls()
        self.server = ldap3.Server(self.config.ldap_url, tls=self.tls)

    def find_dn(self, username: str) -> Optional[str]:
        with ldap3.Connection(
            self.server,
            user=self.config.ldap_username,
            password=self.config.ldap_password,
        ) as connection:
            search_filter = self.config.ldap_filter.format(uid=username)
            connection.search(
                self.config.ldap_base,
                "({filter})".format(filter=search_filter),
                ldap3.SUBTREE,
            )
            if connection.response and len(connection.response) > 0:
                return connection.response[0]["dn"]
            else:
                return None

    def check_password(self, username: str, password: str) -> bool:
        with ldap3.Connection(
            self.server,
            user=username,
            password=password,
        ) as connection:
            # Bind returns true if the password is valid and false if it
            # isn't.  It throws an exception when there's a connection
            # problem.  This is not documented, but I fooled around with it
            # in a test shell for a while to figure it out.
            return connection.bind()

    def reset_password(self, username: str, password: str):
        pass
