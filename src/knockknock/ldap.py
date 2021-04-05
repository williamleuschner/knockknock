import ldap3
import ssl
from knockknock.config import Config


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
        self.server = ldap3.Server(self.config.url, tls=self.tls)

    def check_password(self, username: str, password: str) -> bool:
        with ldap3.Connection(
            self.server, user=self.config.username, password=self.config.password
        ) as connection:
            # Bind returns true if the password is valid and false if it
            # isn't.  It throws an exception when there's a connection
            # problem.  This is not documented, but I fooled around with it
            # in a test shell for a while to figure it out.
            return connection.bind()

    def reset_password(self, username: str, password: str):
        pass
