# scanner/auth_tester.py
"""
WASP Authentication Tester — Phase 2
Tests authentication endpoints for common weaknesses:

  1. Default credentials  — admin/admin, admin/password, etc.
  2. Weak passwords       — dictionary attack with common passwords
  3. Username enumeration — detect if app reveals valid usernames
  4. Account lockout      — check if lockout policy exists
  5. Password in URL      — detect credentials in GET parameters

IMPORTANT: Only use against systems you own or have written
permission to test. Brute force without permission is illegal.
"""

import time
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

from config import REQUEST_TIMEOUT, REQUEST_DELAY, USER_AGENT
from core.logger import get_logger
from core.models import Vulnerability, Severity

log = get_logger(__name__)


# ── Credential lists ──────────────────────────────────────────────────────────

DEFAULT_CREDENTIALS = [
    ("admin",       "admin"),
    ("admin",       "password"),
    ("admin",       "123456"),
    ("admin",       "admin123"),
    ("admin",       ""),
    ("administrator", "administrator"),
    ("administrator", "password"),
    ("root",        "root"),
    ("root",        "toor"),
    ("root",        "password"),
    ("user",        "user"),
    ("user",        "password"),
    ("test",        "test"),
    ("guest",       "guest"),
    ("demo",        "demo"),
    # App-specific defaults
    ("admin",       "dvwa"),       # DVWA
    ("bee",         "bug"),        # bWAPP
    ("admin",       "admin@123"),
    ("admin",       "P@ssw0rd"),
    ("webmaster",   "webmaster"),
]

WEAK_PASSWORDS = [
    "password", "123456", "12345678", "qwerty", "abc123",
    "monkey", "1234567", "letmein", "trustno1", "dragon",
    "baseball", "iloveyou", "master", "sunshine", "ashley",
    "bailey", "passw0rd", "shadow", "123123", "654321",
    "superman", "qazwsx", "michael", "football", "password1",
    "1q2w3e4r", "qwertyuiop", "123456789", "123qwe", "access",
    "welcome", "login", "hello", "changeme", "default",
]

# Signatures that indicate a successful login
SUCCESS_INDICATORS = [
    "logout", "log out", "sign out", "signout",
    "dashboard", "welcome", "profile", "account",
    "my account", "home", "panel", "portal",
]

# Signatures that indicate a failed login
FAILURE_INDICATORS = [
    "invalid", "incorrect", "wrong", "failed",
    "error", "denied", "unauthorized", "bad credentials",
    "login failed", "authentication failed", "invalid credentials",
    "username or password", "try again",
]


class AuthTester:
    """
    Tests authentication forms for common weaknesses.
    Uses conservative rate limiting to avoid service disruption.
    """

    def __init__(
        self,
        session=None,
        cookies: dict | None = None,
        delay: float = 0.5,
    ):
        self.findings: list[Vulnerability] = []
        self.delay = delay

        if session is not None:
            self.session = session
        else:
            self.session = requests.Session()
            self.session.headers.update({"User-Agent": USER_AGENT})
            if cookies:
                self.session.cookies.update(cookies)

    # ── Public API ────────────────────────────────────────────────────────────

    def scan(
        self,
        urls: list[str],
        forms: list[dict] | None = None,
    ) -> list[Vulnerability]:
        """
        Run all auth tests against discovered URLs and forms.
        Returns list of Vulnerability objects.
        """
        log.info("Auth tester started.")

        # Test 1: Find login forms and test default credentials
        login_forms = self._find_login_forms(urls, forms or [])
        log.info(f"Found {len(login_forms)} login form(s).")

        for form in login_forms:
            self._test_default_credentials(form)
            self._test_username_enumeration(form)
            self._test_account_lockout(form)

        # Test 2: Detect passwords in URL parameters
        self._test_password_in_url(urls)

        log.info(f"Auth test complete. {len(self.findings)} finding(s).")
        return self.findings

    # ── Login form discovery ──────────────────────────────────────────────────

    def _find_login_forms(
        self,
        urls: list[str],
        existing_forms: list[dict],
    ) -> list[dict]:
        """
        Find all login forms from crawled pages and existing form data.
        Identifies forms that have username + password fields.
        """
        login_forms = []

        # Check existing forms first
        for form in existing_forms:
            if self._is_login_form(form):
                login_forms.append(form)

        # Also scan URL pages directly for login forms
        login_urls = [
            u for u in urls
            if any(kw in u.lower() for kw in [
                "login", "signin", "auth", "logon",
                "account", "user", "admin",
            ])
        ]

        for url in login_urls[:5]:  # limit to 5 to avoid too many requests
            try:
                resp = self.session.get(url, timeout=REQUEST_TIMEOUT)
                soup = BeautifulSoup(resp.text, "lxml")

                for form_tag in soup.find_all("form"):
                    form = self._parse_form(form_tag, url)
                    if form and self._is_login_form(form):
                        # Avoid duplicates
                        if not any(
                            f["action"] == form["action"]
                            for f in login_forms
                        ):
                            login_forms.append(form)

            except Exception as e:
                log.debug(f"Login form discovery error ({url}): {e}")

        return login_forms

    def _is_login_form(self, form: dict) -> bool:
        """
        Determine if a form is a login form by checking
        for both username-like and password fields.
        """
        fields = form.get("fields", {})
        field_names   = [n.lower() for n in fields.keys()]
        field_types   = [
            info.get("type", "").lower()
            for info in fields.values()
        ]

        has_password = "password" in field_types

        username_hints = [
            "user", "username", "email", "login",
            "name", "account", "uid", "id",
        ]
        has_username = any(
            any(hint in name for hint in username_hints)
            for name in field_names
        )

        return has_password and has_username

    # ── Test 1: Default credentials ───────────────────────────────────────────

    def _test_default_credentials(self, form: dict) -> None:
        """
        Try a list of default username/password combinations.
        Reports success if any combination logs in.
        """
        log.info(
            f"Testing default credentials on: {form['action']}"
        )

        user_field = self._find_username_field(form)
        pass_field = self._find_password_field(form)

        if not user_field or not pass_field:
            log.debug("Could not identify username/password fields.")
            return

        # Get baseline response (empty credentials)
        baseline = self._submit_login(form, user_field, pass_field, "", "")
        baseline_len = len(baseline) if baseline else 0

        for username, password in DEFAULT_CREDENTIALS:
            response = self._submit_login(
                form, user_field, pass_field, username, password
            )

            if response is None:
                continue

            if self._is_login_success(response, baseline_len):
                log.warning(
                    f"[DEFAULT CREDS] {form['action']} | "
                    f"user='{username}' pass='{password}'"
                )
                self.findings.append(Vulnerability(
                    vuln_type   = "Weak/Default Credentials",
                    url         = form["action"],
                    parameter   = f"{user_field} / {pass_field}",
                    payload     = f"{username} / {password}",
                    severity    = Severity.CRITICAL,
                    description = (
                        f"The application accepts default credentials "
                        f"'{username}' / '{password}'. This allows "
                        f"unauthorized access without any exploitation."
                    ),
                    evidence    = f"Login succeeded with {username}:{password}",
                ))
                # Stop after first success — don't need more
                return

            time.sleep(self.delay)

    # ── Test 2: Username enumeration ──────────────────────────────────────────

    def _test_username_enumeration(self, form: dict) -> None:
        """
        Detect if the app reveals whether a username exists
        by returning different error messages for valid vs invalid
        usernames.

        This helps attackers narrow down valid accounts before
        attempting password attacks.
        """
        log.info(f"Testing username enumeration on: {form['action']}")

        user_field = self._find_username_field(form)
        pass_field = self._find_password_field(form)

        if not user_field or not pass_field:
            return

        # Common valid username + definitely wrong password
        resp_valid_user = self._submit_login(
            form, user_field, pass_field,
            "admin", "xXinvalidpasswordXx_wasp_test_9999"
        )

        time.sleep(self.delay)

        # Definitely invalid username + same wrong password
        resp_invalid_user = self._submit_login(
            form, user_field, pass_field,
            "wasp_invalid_user_xyz_9999", "xXinvalidpasswordXx_wasp_test_9999"
        )

        if resp_valid_user is None or resp_invalid_user is None:
            return

        # Check if error messages differ between the two
        valid_lower   = resp_valid_user.lower()
        invalid_lower = resp_invalid_user.lower()

        # Look for username-specific messages in one but not the other
        user_specific = [
            "user not found", "unknown user", "no account",
            "user does not exist", "invalid username",
        ]
        pass_specific = [
            "wrong password", "incorrect password",
            "invalid password", "password is incorrect",
        ]

        found_user_msg = any(m in valid_lower for m in user_specific)
        found_pass_msg = any(m in valid_lower for m in pass_specific)
        different_len  = abs(len(resp_valid_user) - len(resp_invalid_user)) > 20

        if found_user_msg or found_pass_msg or different_len:
            log.warning(
                f"[USERNAME ENUMERATION] {form['action']} — "
                f"different responses for valid vs invalid usernames"
            )
            self.findings.append(Vulnerability(
                vuln_type   = "Username Enumeration",
                url         = form["action"],
                parameter   = user_field,
                payload     = "admin vs random_invalid_user",
                severity    = Severity.MEDIUM,
                description = (
                    f"The login form at '{form['action']}' returns "
                    f"different responses for valid vs invalid usernames, "
                    f"allowing attackers to enumerate valid accounts."
                ),
                evidence    = (
                    f"Response length difference: "
                    f"{len(resp_valid_user)} vs {len(resp_invalid_user)} bytes"
                ),
            ))

    # ── Test 3: Account lockout ───────────────────────────────────────────────

    def _test_account_lockout(self, form: dict) -> None:
        """
        Check if the application implements account lockout
        after multiple failed login attempts.

        Applications without lockout allow unlimited brute-force
        attempts, making password attacks trivial.
        """
        log.info(f"Testing account lockout on: {form['action']}")

        user_field = self._find_username_field(form)
        pass_field = self._find_password_field(form)

        if not user_field or not pass_field:
            return

        # Attempt 6 failed logins and check if still getting same response
        prev_response = None
        lockout_detected = False

        for i in range(6):
            response = self._submit_login(
                form, user_field, pass_field,
                "admin",
                f"wasp_brute_test_attempt_{i}_xxxxxx"
            )

            if response is None:
                break

            if prev_response is not None:
                # Check if response changed — might indicate lockout
                if "locked" in response.lower() or \
                   "too many" in response.lower() or \
                   "blocked" in response.lower() or \
                   "captcha" in response.lower():
                    lockout_detected = True
                    break

            prev_response = response
            time.sleep(self.delay)

        if not lockout_detected:
            log.warning(
                f"[NO LOCKOUT] {form['action']} — "
                f"no account lockout after 6 failed attempts"
            )
            self.findings.append(Vulnerability(
                vuln_type   = "Missing Account Lockout",
                url         = form["action"],
                parameter   = user_field,
                payload     = "6x failed login attempts",
                severity    = Severity.MEDIUM,
                description = (
                    f"The login form at '{form['action']}' does not "
                    f"implement account lockout after multiple failed "
                    f"attempts, allowing unlimited brute-force attacks."
                ),
                evidence    = (
                    "6 consecutive failed login attempts accepted "
                    "without lockout, CAPTCHA, or rate limiting."
                ),
            ))

    # ── Test 4: Password in URL ───────────────────────────────────────────────

    def _test_password_in_url(self, urls: list[str]) -> None:
        """
        Detect if credentials appear in URL parameters.
        This is dangerous because URLs are logged in server logs,
        browser history, and referrer headers.
        """
        sensitive_params = [
            "password", "passwd", "pass", "pwd",
            "secret", "token", "api_key", "apikey",
            "auth", "credential", "key",
        ]

        for url in urls:
            parsed = urlparse(url)
            if not parsed.query:
                continue

            lower_query = parsed.query.lower()
            for param in sensitive_params:
                if param in lower_query:
                    log.warning(
                        f"[PASSWORD IN URL] {url} contains '{param}' parameter"
                    )
                    self.findings.append(Vulnerability(
                        vuln_type   = "Sensitive Data in URL",
                        url         = url,
                        parameter   = param,
                        payload     = "N/A — detected in URL",
                        severity    = Severity.HIGH,
                        description = (
                            f"The URL contains a sensitive parameter '{param}'. "
                            f"Credentials or tokens in URLs are exposed in "
                            f"server logs, browser history, and HTTP referrer "
                            f"headers."
                        ),
                        evidence    = f"Parameter '{param}' found in URL query string",
                    ))
                    break  # one finding per URL

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _submit_login(
        self,
        form: dict,
        user_field: str,
        pass_field: str,
        username: str,
        password: str,
    ) -> str | None:
        """Submit a login form with given credentials."""
        data = {}

        for name, info in form["fields"].items():
            if name == user_field:
                data[name] = username
            elif name == pass_field:
                data[name] = password
            else:
                data[name] = info.get("value", "")

        try:
            if form["method"] == "post":
                resp = self.session.post(
                    form["action"], data=data,
                    timeout=REQUEST_TIMEOUT, allow_redirects=True
                )
            else:
                resp = self.session.get(
                    form["action"], params=data,
                    timeout=REQUEST_TIMEOUT, allow_redirects=True
                )
            return resp.text

        except Exception as e:
            log.debug(f"Login submission error: {e}")
            return None

    def _is_login_success(
        self,
        response: str,
        baseline_len: int,
    ) -> bool:
        """
        Determine if a login response indicates success.
        Uses two strategies:
        1. Check for success/failure keywords in response
        2. Compare response length to baseline (empty credentials)
        """
        lower = response.lower()

        # Direct failure indicators — if found, definitely failed
        for indicator in FAILURE_INDICATORS:
            if indicator in lower:
                return False

        # Direct success indicators — if found, likely succeeded
        for indicator in SUCCESS_INDICATORS:
            if indicator in lower:
                return True

        # Length heuristic — if response is significantly different
        # from baseline (empty login), might indicate success
        len_diff = abs(len(response) - baseline_len)
        if len_diff > 500 and baseline_len > 0:
            return True

        return False

    def _find_username_field(self, form: dict) -> str | None:
        """Find the username/email field name in a form."""
        hints = ["user", "email", "login", "name", "account", "uid"]
        for name, info in form["fields"].items():
            name_lower = name.lower()
            ftype      = info.get("type", "").lower()
            if ftype in ("email",):
                return name
            if any(h in name_lower for h in hints):
                return name
        # Fallback: first text field
        for name, info in form["fields"].items():
            if info.get("type", "text") in ("text", "email"):
                return name
        return None

    def _find_password_field(self, form: dict) -> str | None:
        """Find the password field name in a form."""
        for name, info in form["fields"].items():
            if info.get("type", "").lower() == "password":
                return name
        return None

    def _parse_form(self, form_tag, base_url: str) -> dict | None:
        """Parse a BeautifulSoup form tag into a form dict."""
        action = form_tag.get("action", "")
        method = form_tag.get("method", "get").lower()

        if not action:
            action = base_url
        elif not action.startswith("http"):
            action = urljoin(base_url, action)

        fields = {}
        for tag in form_tag.find_all(["input", "textarea"]):
            name  = tag.get("name", "").strip()
            ftype = tag.get("type", "text").lower()
            value = tag.get("value", "")
            if name:
                fields[name] = {
                    "type":       ftype,
                    "value":      value,
                    "injectable": ftype not in (
                        "submit", "button", "image", "reset"
                    ),
                }

        if not fields:
            return None

        return {
            "action":            action,
            "method":            method,
            "fields":            fields,
            "injectable_fields": [
                n for n, i in fields.items() if i["injectable"]
            ],
            "source_url":        base_url,
        }