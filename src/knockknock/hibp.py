import requests
import hashlib


def check_password(password: str) -> bool:
    """Use Have I Been Pwned to determine whether a password is bad.

    If the request fails, this function will assume the password is fine, but
    log an error so that administrators can diagnose it later.

    :param password: The password to validate.
    :return: True if the password has been found in a prior breach, false
    otherwise.
    """
    sha1_hash = hashlib.sha1()
    sha1_hash.update(password.encode("utf-8"))
    digest = sha1_hash.hexdigest()
    digest = digest.upper()
    response = requests.get("https://api.pwnedpasswords.com/range/" + digest[0:5])
    if response.status_code != 200:
        # The docs say this shouldn't happen, but just in case.
        return False
    return suffix_in_text(digest[5:], response.text)


def suffix_in_text(suffix: str, text: str) -> bool:
    """Determine whether a hash suffix is in the text.

    :param suffix: Everything except the first 5 characters of the SHA1 hash of
    some password.
    :param text: The response text from the HIBP API.
    :return: True if the suffix is in the response, False if it is not.
    """
    for line in text.split("\r\n"):
        if line.startswith(suffix):
            return True
    return False
