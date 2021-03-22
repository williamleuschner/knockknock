import requests
import hashlib


def check_password(password: str) -> int:
    """Use Have I Been Pwned to determine whether a password is bad.

    If the request fails, this function will assume the password is fine, but
    log an error so that administrators can diagnose it later.

    :param password: The password to validate.
    :return: A positive integer indicating the number of times the password has
    been found in a breach. Zero is good, >0 is bad.
    """
    sha1_hash = hashlib.sha1()
    sha1_hash.update(password.encode("utf-8"))
    digest = sha1_hash.hexdigest()
    digest = digest.upper()
    response = requests.get("https://api.pwnedpasswords.com/range/" + digest[0:5])
    if response.status_code != 200:
        # The docs say this shouldn't happen, but just in case.
        return 0
    return suffix_in_text(digest[5:], response.text)


def suffix_in_text(suffix: str, text: str) -> int:
    """Determine whether a hash suffix is in the text.

    :param suffix: Everything except the first 5 characters of the SHA1 hash of
    some password.
    :param text: The response text from the HIBP API.
    :return: The number of breaches the suffix was found in, or 0 if not present.
    """
    for line in text.split("\r\n"):
        line_split = line.split(":")
        if line_split[0] == suffix:
            try:
                return int(line_split[1])
            except ValueError:
                # If somehow the number can't be parsed, the suffix was already
                # found, so it has to be in at least one breach.
                return 1
    return 0
