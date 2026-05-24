"""
WASP XSS Scanner — Phase 2 (Multithreaded)
Detects Reflected XSS via URL params, forms, and headers.
Uses ThreadPoolExecutor to scan multiple URLs simultaneously.
"""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests
from bs4 import BeautifulSoup

from config import REQUEST_TIMEOUT, REQUEST_DELAY, USER_AGENT
from core.logger import get_logger
from core.models import Vulnerability, Severity
from core.utils import build_cookie_jar

log = get_logger(__name__)

XSS_PAYLOADS = [
    '<script>alert("WASP-XSS")</script>',
    '<script>alert(1)</script>',
    '"><script>alert("WASP-XSS")</script>',
    "'><script>alert('WASP-XSS')</script>",
    '<img src=x onerror=alert("WASP-XSS")>',
    '<svg onload=alert("WASP-XSS")>',
    '"><img src=x onerror=alert(1)>',
    '<body onload=alert("WASP-XSS")>',
    'javascript:alert("WASP-XSS")',
    '"><svg/onload=alert(1)>',
]

XSS_REFLECTION_SIGNATURES = [
    '<script>alert(',
    'onerror=alert(',
    'onload=alert(',
    'WASP-XSS',
    'javascript:alert(',
    '<svg/onload=',
    'onerror=alert(1)',
]

INJECTABLE_HEADERS = {
    "Referer":         "http://WASP-XSS-TEST.com/<script>alert(1)</script>",
    "User-Agent":      "WASP-Scanner/<script>alert(1)</script>",
    "X-Forwarded-For": "<script>alert(1)</script>",
}

MAX_WORKERS = 10


class XSSScanner:
    """
    Multithreaded XSS scanner.
    Scans multiple URLs simultaneously using ThreadPoolExecutor.
    Thread-safe finding collection via threading.Lock.
    """

    def __init__(
        self,
        cookies: dict | None = None,
        target_url: str = "http://localhost",
        session=None,
        max_workers: int = MAX_WORKERS,
    ):
        self.cookies     = cookies or {}
        self.findings:   list[Vulnerability] = []
        self.max_workers = max_workers
        self._lock       = __import__("threading").Lock()

        if session is not None:
            self.session = session
            log.debug("XSS scanner using provided authenticated session.")
        else:
            self.session = requests.Session()
            self.session.headers.update({"User-Agent": USER_AGENT})
            if self.cookies:
                self.session.cookies = build_cookie_jar(
                    self.cookies, url=target_url
                )
                log.debug(f"XSS scanner cookies set: {list(self.cookies.keys())}")

    # ── Public API ────────────────────────────────────────────────────────────

    def scan(self, urls: list[str]) -> list[Vulnerability]:
        """
        Scan all URLs for XSS using a thread pool.
        Each URL is scanned independently in its own thread.
        """
        log.info(
            f"XSS scan started (multithreaded, {self.max_workers} workers). "
            f"{len(urls)} URL(s) to probe."
        )

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._scan_url, url): url
                for url in urls
            }
            for future in as_completed(futures):
                url = futures[future]
                try:
                    future.result()
                except Exception as e:
                    log.warning(f"XSS scan error for {url}: {e}")

        log.info(
            f"XSS scan complete. {len(self.findings)} "
            f"vulnerability/vulnerabilities found."
        )
        return self.findings

    def scan_forms_with_mutation(
        self,
        forms: list[dict],
    ) -> list[Vulnerability]:
        """
        Scan forms for XSS using mutated payloads (multithreaded).
        """
        if not forms:
            return []

        log.info(
            f"XSS form mutation scan ({self.max_workers} workers). "
            f"{len(forms)} form(s)."
        )

        from scanner.forms import FormCrawler
        from scanner.mutator import PayloadMutator
        mutator      = PayloadMutator()
        form_crawler = FormCrawler(session=self.session)

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(
                    self._scan_form_mutated, form, form_crawler, mutator
                ): form
                for form in forms
                if form.get("injectable_fields")
            }
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    log.warning(f"Form XSS error: {e}")

        return self.findings

    # ── Per-URL scanning ──────────────────────────────────────────────────────

    def _scan_url(self, url: str) -> None:
        """Scan a single URL — runs in its own thread."""
        log.info(f"[Thread] Scanning: {url}")

        if "?" in url:
            self._test_url_params(url)

        html = self._fetch(url)
        if html:
            forms = self._extract_forms(html, url)
            for form in forms:
                self._test_form(form, url)

        self._test_headers(url)

    def _scan_form_mutated(
        self,
        form: dict,
        form_crawler,
        mutator,
    ) -> None:
        """Scan a single form with mutation — runs in its own thread."""
        for field in form["injectable_fields"]:
            for base_payload in XSS_PAYLOADS[:4]:
                for payload in mutator.mutate_xss(base_payload)[:8]:
                    response = form_crawler.submit_form(
                        form, payload, target_field=field
                    )
                    if response is None:
                        continue
                    reflected = self._find_reflection(response, payload)
                    if reflected:
                        log.warning(
                            f"[FORM XSS MUTATION] {form['action']} | "
                            f"field='{field}'"
                        )
                        self._add_finding(Vulnerability(
                            vuln_type   = "Reflected XSS (Form - Mutated)",
                            url         = form["action"],
                            parameter   = field,
                            payload     = payload,
                            severity    = Severity.HIGH,
                            description = (
                                f"Form field '{field}' reflects mutated XSS "
                                f"payload unescaped, bypassing basic filters."
                            ),
                            evidence    = reflected,
                        ))
                        return

    # ── Detection techniques ──────────────────────────────────────────────────

    def _test_url_params(self, url: str) -> None:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        for param_name in params:
            for payload in XSS_PAYLOADS:
                test_params = dict(params)
                test_params[param_name] = [payload]
                test_url = urlunparse(
                    parsed._replace(
                        query=urlencode(test_params, doseq=True)
                    )
                )
                response_text = self._fetch(test_url)
                if response_text is None:
                    continue

                reflected = self._find_reflection(response_text, payload)
                if reflected:
                    log.warning(
                        f"[XSS - URL PARAM] {url} | param='{param_name}'"
                    )
                    self._add_finding(Vulnerability(
                        vuln_type   = "Reflected XSS (URL Parameter)",
                        url         = url,
                        parameter   = param_name,
                        payload     = payload,
                        severity    = Severity.HIGH,
                        description = (
                            f"Parameter '{param_name}' reflects user input "
                            f"unescaped, allowing script injection via URL."
                        ),
                        evidence    = reflected,
                    ))
                    break

    def _test_form(self, form: dict, base_url: str) -> None:
        action = form["action"]
        method = form["method"]
        inputs = form["inputs"]

        for payload in XSS_PAYLOADS:
            data            = {}
            injected_fields = []

            for inp in inputs:
                name  = inp.get("name")
                itype = inp.get("type", "text").lower()
                value = inp.get("value", "")
                if not name:
                    continue
                if itype in ("hidden","submit","button","image","reset"):
                    data[name] = value
                elif itype == "checkbox":
                    data[name] = "on"
                else:
                    data[name] = payload
                    injected_fields.append(name)

            if not data:
                continue

            response_text = self._submit_form(action, method, data)
            if response_text is None:
                continue

            reflected = self._find_reflection(response_text, payload)
            if reflected:
                param = ", ".join(injected_fields) if injected_fields else "unknown"
                log.warning(
                    f"[XSS - FORM] {base_url} | "
                    f"action='{action}' fields='{param}'"
                )
                self._add_finding(Vulnerability(
                    vuln_type   = "Reflected XSS (Form Input)",
                    url         = action,
                    parameter   = param,
                    payload     = payload,
                    severity    = Severity.HIGH,
                    description = (
                        f"Form at '{action}' reflects field(s) "
                        f"'{param}' unescaped."
                    ),
                    evidence    = reflected,
                ))
                return

    def _test_headers(self, url: str) -> None:
        for header_name, payload in INJECTABLE_HEADERS.items():
            try:
                response  = self.session.get(
                    url, timeout=REQUEST_TIMEOUT,
                    headers={header_name: payload},
                    allow_redirects=True,
                )
                reflected = self._find_reflection(response.text, payload)
                if reflected:
                    log.warning(
                        f"[XSS - HEADER] {url} | header='{header_name}'"
                    )
                    self._add_finding(Vulnerability(
                        vuln_type   = "Reflected XSS (HTTP Header)",
                        url         = url,
                        parameter   = header_name,
                        payload     = payload,
                        severity    = Severity.MEDIUM,
                        description = (
                            f"Header '{header_name}' reflected unescaped."
                        ),
                        evidence    = reflected,
                    ))
            except Exception as e:
                log.debug(f"Header test error ({header_name}): {e}")

    # ── Thread-safe finding add ───────────────────────────────────────────────

    def _add_finding(self, vuln: Vulnerability) -> None:
        """Thread-safe method to add a finding."""
        with self._lock:
            self.findings.append(vuln)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _extract_forms(self, html: str, base_url: str) -> list[dict]:
        forms = []
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception:
            return forms

        for form_tag in soup.find_all("form"):
            action = form_tag.get("action", base_url)
            if not action.startswith("http"):
                from urllib.parse import urljoin
                action = urljoin(base_url, action)

            method = form_tag.get("method", "get").lower()
            inputs = []
            for tag in form_tag.find_all(["input","textarea","select"]):
                inputs.append({
                    "name":  tag.get("name", ""),
                    "type":  tag.get("type", "text"),
                    "value": tag.get("value", ""),
                })

            if inputs:
                forms.append({
                    "action": action,
                    "method": method,
                    "inputs": inputs,
                })

        return forms

    def _submit_form(
        self, action: str, method: str, data: dict
    ) -> str | None:
        try:
            if method == "post":
                r = self.session.post(
                    action, data=data,
                    timeout=REQUEST_TIMEOUT, allow_redirects=True
                )
            else:
                r = self.session.get(
                    action, params=data,
                    timeout=REQUEST_TIMEOUT, allow_redirects=True
                )
            return r.text
        except Exception as e:
            log.debug(f"Form submit error: {e}")
            return None

    def _fetch(self, url: str) -> str | None:
        try:
            r = self.session.get(
                url, timeout=REQUEST_TIMEOUT, allow_redirects=True
            )
            if "login" in r.url and "login" not in url:
                return None
            return r.text
        except Exception as e:
            log.debug(f"Fetch error ({url}): {e}")
            return None

    def _find_reflection(
        self, response_text: str, payload: str
    ) -> str | None:
        if payload in response_text:
            return f"Full payload reflected: {payload[:80]}"

        lower_response = response_text.lower()
        lower_payload  = payload.lower()

        dangerous_parts = [
            "<script>", "onerror=", "onload=", "onclick=",
            "javascript:", "<svg", "<img", "alert(", "WASP-XSS",
        ]

        for part in dangerous_parts:
            if part.lower() in lower_payload and part.lower() in lower_response:
                return f"Dangerous tag/attribute reflected: {part}"

        for sig in XSS_REFLECTION_SIGNATURES:
            if sig.lower() in lower_response:
                return f"XSS signature detected: {sig}"

        return None