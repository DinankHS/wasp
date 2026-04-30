# core/utils.py
"""
Shared utility functions used across all modules.
"""

from urllib.parse import urlparse, urljoin
import re


def get_logger(name):
    from core.logger import get_logger as _get_logger
    return _get_logger(name)

log = get_logger(__name__)


def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


def is_same_domain(base_url: str, target_url: str) -> bool:
    base_domain   = urlparse(base_url).netloc
    target_domain = urlparse(target_url).netloc
    return base_domain == target_domain


def build_absolute_url(base: str, href: str) -> str:
    return urljoin(base, href)


def extract_domain(url: str) -> str:
    return urlparse(url).netloc


def is_valid_url(url: str) -> bool:
    try:
        result = urlparse(url)
        return result.scheme in ("http", "https") and bool(result.netloc)
    except ValueError:
        return False


def sanitize_filename(name: str) -> str:
    return re.sub(r"[^\w\-_.]", "_", name)


def build_cookie_jar(cookies: dict, url: str = "http://localhost"):
    """
    Build a RequestsCookieJar with explicit domain set.
    Fixes the issue where requests ignores cookies for non-standard ports.
    """
    from requests.cookies import RequestsCookieJar

    parsed = urlparse(url)
    host   = parsed.hostname or "localhost"

    jar = RequestsCookieJar()
    for name, value in cookies.items():
        jar.set(name, value, domain=host, path="/")
    return jar


def dvwa_login(
    base_url: str,
    username: str = "admin",
    password: str = "password"
) -> dict | None:
    """Auto-login for DVWA. Returns session cookies or None on failure."""
    import requests
    from bs4 import BeautifulSoup

    session = requests.Session()
    try:
        login_url = f"{base_url}/login.php"
        r = session.get(login_url, timeout=10)

        soup        = BeautifulSoup(r.text, "lxml")
        token_input = soup.find("input", {"name": "user_token"})
        token       = token_input["value"] if token_input else ""

        session.post(login_url, data={
            "username":   username,
            "password":   password,
            "Login":      "Login",
            "user_token": token,
        }, timeout=10)

        session.post(f"{base_url}/security.php", data={
            "security":      "low",
            "seclev_submit": "Submit",
            "user_token":    token,
        }, timeout=10)

        return {c.name: c.value for c in session.cookies}

    except Exception as e:
        log.error(f"DVWA login error: {e}")
        return None


def bwapp_login(
    base_url: str,
    username: str = "bee",
    password: str = "bug"
) -> dict | None:
    """Auto-login for bWAPP. Returns cookies dict or None on failure."""
    session = bwapp_get_session(base_url, username, password)
    if session is None:
        return None
    try:
        test = session.get(f"{base_url}/portal.php", timeout=10)
        if "welcome" in test.text.lower() or "bee" in test.text.lower():
            cookies = {c.name: c.value for c in session.cookies}
            cookies["security_level"] = "0"
            return cookies
        return None
    except Exception:
        return None


def bwapp_get_session(
    base_url: str,
    username: str = "bee",
    password: str = "bug"
):
    """
    Login to bWAPP and return the authenticated requests.Session directly.
    Returns None if bWAPP is unreachable.
    """
    import requests
    session = requests.Session()
    try:
        session.get(f"{base_url}/login.php", timeout=10)
        session.post(
            f"{base_url}/login.php",
            data={
                "login":          username,
                "password":       password,
                "security_level": "0",
                "form":           "submit",
            },
            timeout=10,
            allow_redirects=True,
        )
        log.info(f"bWAPP session created. Cookies: {[c.name for c in session.cookies]}")
        return session

    except Exception as e:
        log.error(f"bWAPP connection failed: {e}")
        log.error("Is bWAPP running? Start it with:")
        log.error("  docker run --rm -d -p 8080:80 --name bwapp raesene/bwapp")
        return None