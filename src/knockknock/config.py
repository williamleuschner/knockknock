import configparser


class ConfigError(Exception):
    pass


class Config:
    """A configuration for KnockKnock."""

    SECTION_LDAP = "LDAP"
    SECTION_SITE = "Site"
    OPTION_URL = "url"
    OPTION_USERNAME = "username"
    OPTION_PASSWORD = "password"
    OPTION_BASE = "base"
    OPTION_FILTER = "filter"
    OPTION_SHORT_DEPT = "short_department_name"
    OPTION_LONG_DEPT = "long_department_name"
    OPTION_SHORT_ORG = "short_organization_name"
    OPTION_LONG_ORG = "long_organization_name"

    @staticmethod
    def validate(parser):
        """Validate that all of the required keys are present in a config."""
        errors = []
        # Verify sections are present.
        sections = [Config.SECTION_LDAP, Config.SECTION_SITE]
        for section in sections:
            if not parser.has_section(section):
                errors.append("missing required section: {}".format(section))
        if len(errors) > 0:
            raise ConfigError(errors)
        # Verify options are present in LDAP section.
        ldap_options = [
            Config.OPTION_URL,
            Config.OPTION_USERNAME,
            Config.OPTION_PASSWORD,
            Config.OPTION_BASE,
            Config.OPTION_FILTER,
        ]
        site_options = [
            Config.OPTION_SHORT_DEPT,
            Config.OPTION_LONG_DEPT,
            Config.OPTION_SHORT_ORG,
            Config.OPTION_LONG_ORG,
        ]
        for option in ldap_options:
            if not parser.has_option(Config.SECTION_LDAP, option):
                errors.append(
                    "missing required option in {} section: {}".format(
                        Config.SECTION_LDAP, option
                    )
                )
        for option in site_options:
            if not parser.has_option(Config.SECTION_SITE, option):
                errors.append(
                    "missing required option in {} section: {}".format(
                        Config.SECTION_SITE, option
                    )
                )

    def __init__(self, path):
        """Read a configuration file at path and create a Config from it."""
        with open(path, "r") as config_file:
            parser = configparser.ConfigParser()
            parser.read_file(config_file)
            Config.validate(parser)
            self.ldap_url = parser[Config.SECTION_LDAP][Config.OPTION_URL]
            self.ldap_username = parser[Config.SECTION_LDAP][Config.OPTION_USERNAME]
            self.ldap_password = parser[Config.SECTION_LDAP][Config.OPTION_PASSWORD]
            self.ldap_base = parser[Config.SECTION_LDAP][Config.OPTION_BASE]
            self.ldap_filter = parser[Config.SECTION_LDAP][Config.OPTION_FILTER]
            self.site_short_dept_name = parser[Config.SECTION_SITE][
                Config.OPTION_SHORT_DEPT
            ]
            self.site_long_dept_name = parser[Config.SECTION_SITE][
                Config.OPTION_LONG_DEPT
            ]
            self.site_short_org_name = parser[Config.SECTION_SITE][
                Config.OPTION_SHORT_ORG
            ]
            self.site_long_org_name = parser[Config.SECTION_SITE][
                Config.OPTION_LONG_ORG
            ]
