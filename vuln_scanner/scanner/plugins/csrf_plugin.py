# scanner/plugins/csrf_plugin.py
"""
WASP CSRF Detection Plugin
Detects Cross-Site Request Forgery vulnerabilities by checking
if forms are missing CSRF tokens or have weak token implementations.

CSRF allows attackers to trick authenticated users into performing
unintended actions on a web application.

Detection checks:
  1. Missing CSRF token      — form has no token field at all
  2. Predictable token       — token is too short or looks guessable
  3. Token not required      — form submits successfully without token
  4. GET-based state change  — dangerous action uses GET instead of POST
  5. Missing SameSite cookie — session cookie lacks SameSite attribute
"""

import re
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup

from core.models import Severity
from core.logger import get_logger
from scanner.plugins.base_plugin import BasePlugin

log = get_logger(__name__)

# Common CSRF token field names used by frameworks
CSRF_TOKEN_NAMES = [
    "csrf", "csrf_token", "csrftoken", "_csrf", "_token",
    "token", "authenticity_token", "user_token", "nonce",
    "xsrf", "xsrf_token", "_xsrf", "anti_csrf", "request_token",
    "form_token", "formtoken", "verify_token", "security_token",
    "hidden_token", "__requestverificationtoken",
]

# Actions that should never use GET (state-changing operations)
DANGEROUS_GET_PATTERNS = [
    "delete", "remove", "update", "edit", "change",
    "reset", "transfer", "purchase", "confirm", "approve",
    "logout", "disable", "enable", "create", "add",
]


class CSRFPlugin(BasePlugin):

    name        = "CSRF Scanner"
    version     = "1.0"
    description = "Detects Cross-Site Request Forgery vulnerabilities"
    author      = "WASP"

    def scan(
        self,
        urls: list[str],
        forms: list[dict] | None = None,
    ) -> list:
        """
        Run all CSRF checks against discovered URLs and forms.
        """
        self.log.info(
            f"CSRF scan started. {len(urls)} URL(s), "
            f"{len(forms or [])} form(s)."
        )

        # Check 1: Analyze all forms for missing/weak CSRF tokens
        all_forms = self._discover_forms(urls)
        if forms:
            all_forms.extend(forms)

        for form in all_forms:
            self._check_missing_token(form)
            self._check_token_strength(form)
            self._check_token_not_validated(form)
            self._check_dangerous_get(form)

        # Check 2: Check cookies for SameSite attribute
        for url in urls[:3]:  # check first 3 URLs only
            self._check_samesite_cookie(url)

        self.log.info(
            f"CSRF scan complete. {len(self.findings)} finding(s)."
        )
        return self.findings

    # ── Form discovery ────────────────────────────────────────────────────────

    def _discover_forms(self, urls: list[str]) -> list[dict]:
        """Fetch pages and extract all forms."""
        all_forms = []
        for url in urls:
            html = self.fetch(url)
            if not html:
                continue
            forms = self._parse_forms(html, url)
            all_forms.extend(forms)
        return all_forms

    def _parse_forms(self, html: str, base_url: str) -> list[dict]:
        """Parse all forms from HTML into structured dicts."""
        forms = []
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception:
            return forms

        for form_tag in soup.find_all("form"):
            action = form_tag.get("action", base_url)
            if not action.startswith("http"):
                action = urljoin(base_url, action)

            method = form_tag.get("method", "get").lower()
            fields = {}

            for tag in form_tag.find_all(["input", "textarea", "select"]):
                name  = tag.get("name", "").strip()
                ftype = tag.get("type", "text").lower()
                value = tag.get("value", "")
                if name:
                    fields[name] = {
                        "type":  ftype,
                        "value": value,
                    }

            if fields:
                forms.append({
                    "action":     action,
                    "method":     method,
                    "fields":     fields,
                    "source_url": base_url,
                })

        return forms

    # ── Check 1: Missing CSRF token ───────────────────────────────────────────

    def _check_missing_token(self, form: dict) -> None:
        """
        Check if a POST form has no CSRF token at all.
        GET forms are excluded — they should not have CSRF tokens.
        Forms with only one field (like search) are skipped.
        """
        # Only POST forms need CSRF protection
        if form["method"] != "post":
            return

        # Skip trivial single-field forms (search boxes etc.)
        if len(form["fields"]) <= 1:
            return

        # Check if any field looks like a CSRF token
        field_names_lower = [n.lower() for n in form["fields"].keys()]
        has_token = any(
            token_name in name
            for name in field_names_lower
            for token_name in CSRF_TOKEN_NAMES
        )

        if not has_token:
            self.log.warning(
                f"[CSRF - MISSING TOKEN] {form['action']} — "
                f"POST form with no CSRF token field"
            )
            self.add_finding(
                vuln_type   = "CSRF — Missing Token",
                url         = form["action"],
                parameter   = "N/A",
                payload     = "POST without CSRF token",
                severity    = Severity.HIGH,
                description = (
                    f"The POST form at '{form['action']}' (from "
                    f"'{form['source_url']}') does not contain a CSRF "
                    f"token. Without a token, attackers can trick "
                    f"authenticated users into submitting this form "
                    f"from any website."
                ),
                evidence    = (
                    f"POST form fields: {list(form['fields'].keys())} — "
                    f"none match known CSRF token names"
                ),
            )

    # ── Check 2: Weak/predictable token ──────────────────────────────────────

    def _check_token_strength(self, form: dict) -> None:
        """
        Check if a CSRF token looks weak or predictable.
        Strong tokens should be: random, long (32+ chars), hex/base64.
        """
        for field_name, field_info in form["fields"].items():
            field_lower = field_name.lower()

            # Only check fields that look like CSRF tokens
            is_token_field = any(
                t in field_lower for t in CSRF_TOKEN_NAMES
            )
            if not is_token_field:
                continue

            token_value = field_info.get("value", "")
            if not token_value:
                continue

            issues = []

            # Too short — strong tokens are 32+ characters
            if len(token_value) < 16:
                issues.append(f"token too short ({len(token_value)} chars, need 32+)")

            # Looks numeric/sequential — not random enough
            if token_value.isdigit():
                issues.append("token is purely numeric (not cryptographically random)")

            # Looks like a timestamp
            if re.match(r"^\d{10,13}$", token_value):
                issues.append("token appears to be a timestamp (predictable)")

            # All same characters
            if len(set(token_value)) < 4:
                issues.append("token has very low entropy (too few unique characters)")

            if issues:
                self.log.warning(
                    f"[CSRF - WEAK TOKEN] {form['action']} | "
                    f"field='{field_name}' — {', '.join(issues)}"
                )
                self.add_finding(
                    vuln_type   = "CSRF — Weak Token",
                    url         = form["action"],
                    parameter   = field_name,
                    payload     = token_value[:20] + "...",
                    severity    = Severity.MEDIUM,
                    description = (
                        f"The CSRF token in field '{field_name}' at "
                        f"'{form['action']}' appears weak: {', '.join(issues)}. "
                        f"Weak tokens can be guessed or predicted by attackers."
                    ),
                    evidence    = f"Token value: '{token_value[:30]}' — {issues[0]}",
                )

    # ── Check 3: Token not validated server-side ──────────────────────────────

    def _check_token_not_validated(self, form: dict) -> None:
        """
        Submit the form with a fake/wrong CSRF token and check if
        the server accepts it. If it does, CSRF is not validated.
        Only tests forms that HAVE a token field — checks server-side validation.
        """
        if form["method"] != "post":
            return

        # Find CSRF token field
        token_field = None
        for field_name in form["fields"]:
            if any(t in field_name.lower() for t in CSRF_TOKEN_NAMES):
                token_field = field_name
                break

        if not token_field:
            return  # Already caught by missing token check

        # Build form data with fake token
        data = {}
        for name, info in form["fields"].items():
            if name == token_field:
                data[name] = "WASP_FAKE_CSRF_TOKEN_12345_INVALID"
            else:
                data[name] = info.get("value", "test")

        try:
            if self.session is None:
                import requests as req
                self.session = req.Session()

            resp = self.session.post(
                form["action"],
                data=data,
                timeout=10,
                allow_redirects=True,
            )

            # Check if the server rejected the fake token
            resp_lower = resp.text.lower()
            rejection_signs = [
                "invalid token", "csrf", "forbidden", "403",
                "security", "token mismatch", "invalid request",
            ]
            rejected = any(sign in resp_lower for sign in rejection_signs)

            # If server didn't reject fake token — CSRF not validated
            if not rejected and resp.status_code not in (403, 419, 422):
                self.log.warning(
                    f"[CSRF - NOT VALIDATED] {form['action']} — "
                    f"fake token accepted by server"
                )
                self.add_finding(
                    vuln_type   = "CSRF — Token Not Validated",
                    url         = form["action"],
                    parameter   = token_field,
                    payload     = "WASP_FAKE_CSRF_TOKEN_12345_INVALID",
                    severity    = Severity.HIGH,
                    description = (
                        f"The form at '{form['action']}' has a CSRF token "
                        f"field ('{token_field}') but the server accepted a "
                        f"completely fake token value. The token exists in "
                        f"the HTML but is not validated server-side."
                    ),
                    evidence    = (
                        f"Server returned HTTP {resp.status_code} "
                        f"with fake token — no rejection detected"
                    ),
                )

        except Exception as e:
            self.log.debug(f"Token validation check error: {e}")

    # ── Check 4: Dangerous GET-based state change ─────────────────────────────

    def _check_dangerous_get(self, form: dict) -> None:
        """
        Check if a form uses GET for state-changing operations.
        GET requests are bookmarkable, loggable, and CSRF-vulnerable.
        Actions like delete/update/transfer should always use POST.
        """
        if form["method"] != "get":
            return

        action_lower = form["action"].lower()
        matched = [
            pattern for pattern in DANGEROUS_GET_PATTERNS
            if pattern in action_lower
        ]

        if matched:
            self.log.warning(
                f"[CSRF - DANGEROUS GET] {form['action']} — "
                f"state-changing action via GET: {matched}"
            )
            self.add_finding(
                vuln_type   = "CSRF — Dangerous GET Request",
                url         = form["action"],
                parameter   = "method",
                payload     = "GET form submission",
                severity    = Severity.MEDIUM,
                description = (
                    f"The form at '{form['action']}' uses GET method for "
                    f"what appears to be a state-changing operation "
                    f"({', '.join(matched)}). GET requests are logged in "
                    f"server logs, browser history, and referrer headers, "
                    f"and are trivially exploitable for CSRF attacks."
                ),
                evidence    = (
                    f"GET form action contains: {matched}"
                ),
            )

    # ── Check 5: SameSite cookie attribute ────────────────────────────────────

    def _check_samesite_cookie(self, url: str) -> None:
        """
        Check if session cookies have the SameSite attribute.
        Without SameSite=Strict or Lax, cookies are sent on
        cross-site requests, enabling CSRF attacks.
        """
        try:
            if self.session is None:
                import requests as req
                self.session = req.Session()

            resp = self.session.get(url, timeout=10, allow_redirects=True)

            # Parse Set-Cookie headers
            set_cookie_headers = resp.headers.getlist("Set-Cookie") \
                if hasattr(resp.headers, "getlist") \
                else [resp.headers.get("Set-Cookie", "")]

            for cookie_header in set_cookie_headers:
                if not cookie_header:
                    continue

                cookie_lower = cookie_header.lower()

                # Check if this looks like a session cookie
                is_session = any(
                    name in cookie_lower
                    for name in ["phpsessid", "session", "auth", "token"]
                )

                if is_session and "samesite" not in cookie_lower:
                    self.log.warning(
                        f"[CSRF - NO SAMESITE] {url} — "
                        f"session cookie missing SameSite attribute"
                    )
                    self.add_finding(
                        vuln_type   = "CSRF — Missing SameSite Cookie",
                        url         = url,
                        parameter   = "Set-Cookie header",
                        payload     = "N/A — cookie attribute check",
                        severity    = Severity.MEDIUM,
                        description = (
                            f"A session cookie at '{url}' is missing the "
                            f"SameSite attribute. Without SameSite=Strict or "
                            f"SameSite=Lax, the cookie is sent with "
                            f"cross-site requests, enabling CSRF attacks even "
                            f"if CSRF tokens are implemented."
                        ),
                        evidence    = (
                            f"Cookie header: {cookie_header[:80]} — "
                            f"no SameSite directive found"
                        ),
                    )
                    break  # One finding per URL

        except Exception as e:
            self.log.debug(f"SameSite check error ({url}): {e}")