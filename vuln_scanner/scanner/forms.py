# scanner/forms.py
"""
WASP Form Crawler — Phase 2
Discovers and extracts all HTML forms from crawled pages.
Handles GET and POST forms, hidden fields, CSRF tokens,
and multi-step forms.

This feeds the SQLi and XSS scanners with POST targets
that the Phase 1 URL-only crawler would have missed entirely.
"""

import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup

from config import REQUEST_TIMEOUT, USER_AGENT
from core.logger import get_logger

log = get_logger(__name__)


class FormCrawler:
    """
    Extracts all HTML forms from a list of URLs.
    Returns structured form data ready for injection testing.

    Each returned form dict has:
        action            — URL the form submits to
        method            — "get" or "post"
        fields            — dict of {name: {type, value, injectable}}
        injectable_fields — list of field names safe to inject into
        source_url        — page where this form was found
    """

    def __init__(
        self,
        session=None,
        cookies: dict | None = None,
    ):
        if session is not None:
            self.session = session
        else:
            self.session = requests.Session()
            self.session.headers.update({"User-Agent": USER_AGENT})
            if cookies:
                self.session.cookies.update(cookies)

    # ── Public API ────────────────────────────────────────────────────────────

    def extract_forms(self, urls: list[str]) -> list[dict]:
        """
        Extract all forms from a list of URLs.
        Returns a deduplicated flat list of form dicts ready for injection.

        Deduplication key: (action, method, frozenset of injectable field names)
        This prevents the same form appearing on 40 pages (e.g. a site-wide
        search bar) from being scanned 40 times.
        """
        all_forms  = []
        seen_forms: set[tuple] = set()

        for url in urls:
            forms = self._extract_from_url(url)
            for form in forms:
                # Build a dedup key from the form's identity
                key = (
                    form["action"],
                    form["method"],
                    frozenset(form["injectable_fields"]),
                )
                if key not in seen_forms:
                    seen_forms.add(key)
                    all_forms.append(form)
                else:
                    log.debug(
                        f"Skipping duplicate form: {form['action']} "
                        f"fields={form['injectable_fields']}"
                    )

        log.info(
            f"Form crawl complete. {len(all_forms)} form(s) found "
            f"across {len(urls)} URL(s)."
        )
        return all_forms

    def submit_form(
        self,
        form: dict,
        payload: str,
        target_field: str | None = None,
    ) -> str | None:
        """
        Submit a form with a payload injected into injectable fields.

        Args:
            form         — form dict from extract_forms()
            payload      — the injection payload to test
            target_field — if set, only inject into this field;
                           if None, inject into all injectable fields

        Returns response text or None on error.
        """
        data = {}
        for name, info in form["fields"].items():
            if info["injectable"]:
                if target_field is None or name == target_field:
                    data[name] = payload
                else:
                    data[name] = info["value"] or "test"
            else:
                data[name] = info["value"]

        try:
            if form["method"] == "post":
                response = self.session.post(
                    form["action"],
                    data=data,
                    timeout=REQUEST_TIMEOUT,
                    allow_redirects=True,
                )
            else:
                response = self.session.get(
                    form["action"],
                    params=data,
                    timeout=REQUEST_TIMEOUT,
                    allow_redirects=True,
                )

            # Detect login redirect — only flag genuine login page redirects
            if self._is_login_redirect(response, form["action"]):
                log.debug("Form submission redirected to login — session expired?")
                return None

            return response.text

        except requests.exceptions.Timeout:
            log.debug(f"Timeout submitting form to {form['action']}")
            return None
        except requests.exceptions.RequestException as e:
            log.debug(f"Form submission error ({form['action']}): {e}")
            return None

    # ── Private helpers ───────────────────────────────────────────────────────

    def _is_login_redirect(self, response, original_action: str) -> bool:
        """
        Returns True only if the response is a genuine login page redirect.
        Avoids false-positives on pages that mention 'login' in content.
        """
        final_url   = response.url.lower()
        action_url  = original_action.lower()

        login_markers = ["login.php", "/login?", "/login/"]
        for marker in login_markers:
            if marker in final_url and marker not in action_url:
                return True

        body = response.text[:2000].lower()
        if (
            'name="user_token"' in body
            or 'action="login.php"' in body
        ):
            return True

        return False

    def _extract_from_url(self, url: str) -> list[dict]:
        """Fetch a single page and extract all its forms."""
        try:
            response = self.session.get(
                url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
            )

            content_type = response.headers.get("Content-Type", "")
            if "text/html" not in content_type:
                return []

            if response.status_code != 200:
                return []

            return self._parse_forms(response.text, url)

        except requests.exceptions.RequestException as e:
            log.debug(f"Form extraction error for {url}: {e}")
            return []

    def _parse_forms(self, html: str, base_url: str) -> list[dict]:
        """Parse all <form> tags from HTML and return structured dicts."""
        forms = []
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception as e:
            log.warning(f"HTML parse error on {base_url}: {e}")
            return forms

        for form_tag in soup.find_all("form"):
            form = self._parse_single_form(form_tag, base_url)
            if form:
                forms.append(form)

        return forms

    def _parse_single_form(self, form_tag, base_url: str) -> dict | None:
        """
        Parse a single <form> element into a structured dict.

        Handles:
        - Relative and absolute action URLs
        - All input types including hidden and CSRF tokens
        - Textarea and select elements
        - Missing action attribute (defaults to current page)
        """
        # ── Action URL ────────────────────────────────────────────────────────
        action = form_tag.get("action", "")
        method = form_tag.get("method", "get").lower().strip()

        if not action:
            action = base_url
        elif not action.startswith("http"):
            action = urljoin(base_url, action)

        if method not in ("get", "post"):
            method = "get"

        # ── Field extraction ──────────────────────────────────────────────────
        fields = {}

        for tag in form_tag.find_all(["input", "textarea", "select"]):
            name  = tag.get("name", "").strip()
            ftype = tag.get("type", "text").lower().strip()
            value = tag.get("value", "")

            if not name:
                continue

            is_injectable = ftype not in (
                "submit", "button", "image",
                "reset", "file", "checkbox",
                "radio", "hidden",
            )

            # Special case: hidden fields with user-data names are injectable
            if ftype == "hidden":
                user_data_hints = [
                    "id", "user", "name", "search",
                    "query", "q", "term", "input",
                ]
                if any(h in name.lower() for h in user_data_hints):
                    is_injectable = True

            fields[name] = {
                "type":       ftype,
                "value":      value,
                "injectable": is_injectable,
            }

        if not fields:
            return None

        injectable_fields = [
            name for name, info in fields.items()
            if info["injectable"]
        ]

        if not injectable_fields:
            return None

        return {
            "action":            action,
            "method":            method,
            "fields":            fields,
            "injectable_fields": injectable_fields,
            "source_url":        base_url,
        }