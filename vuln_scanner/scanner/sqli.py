# scanner/sqli.py
"""
WASP SQL Injection Scanner — Phase 2 (Multithreaded)
Three detection techniques: error-based, boolean-based, time-based.
Uses ThreadPoolExecutor to scan multiple URLs simultaneously.
"""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests

from config import REQUEST_TIMEOUT, REQUEST_DELAY, USER_AGENT, SQLI_TIMEOUT_THRESHOLD
from core.logger import get_logger
from core.models import Vulnerability, Severity
from core.utils import build_cookie_jar

log = get_logger(__name__)

ERROR_PAYLOADS = [
    "'",
    "''",
    "`",
    '"',
    "\\",
    "' --",
    "' #",
    "' /*",
    "') --",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
]

BOOLEAN_PAYLOADS = [
    ("1' AND '1'='1", "1' AND '1'='2"),
    ("1 AND 1=1",     "1 AND 1=2"),
    ("1' AND 1=1--",  "1' AND 1=2--"),
    ("admin'--",      "admin' AND '1'='2"),
]

TIME_PAYLOADS = [
    "1; SELECT SLEEP(5)--",
    "1' AND SLEEP(5)--",
    "1; WAITFOR DELAY '0:0:5'--",
    "1'; WAITFOR DELAY '0:0:5'--",
    "1; SELECT pg_sleep(5)--",
]

DB_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch_array()",
    "mysql_num_rows()",
    "mysql_fetch_assoc()",
    "mysql_fetch_row()",
    "mysql_query()",
    "com.mysql.jdbc",
    "supplied argument is not a valid mysql",
    "mysql server version",
    "error: you have an error",
    "check the manual that corresponds",
    "right syntax to use near",
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "sqlserver",
    "unclosed quotation mark",
    "ora-01756",
    "ora-00933",
    "oracle error",
    "postgresql",
    "pg_query()",
    "pg::syntaxerror",
    "sql syntax",
    "syntax error",
    "sql error",
    "database error",
    "db error",
    "invalid query",
    "quoted string not properly terminated",
    "error in your sql",
]

LOGIN_INDICATORS = [
    "login.php",
    "/login",
    "login_user",
    "user_token",
]

MAX_WORKERS = 10


class SQLiScanner:
    """
    Multithreaded SQL Injection scanner.
    Scans multiple URLs simultaneously using ThreadPoolExecutor.
    Each URL is tested independently in its own thread.
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
            if self.cookies:
                self.session.cookies.update(self.cookies)
            log.debug("SQLi scanner using provided authenticated session.")
        else:
            self.session = requests.Session()
            self.session.headers.update({"User-Agent": USER_AGENT})
            if self.cookies:
                # update() skips domain validation — works for localhost
                self.session.cookies.update(self.cookies)
                log.debug(f"SQLi scanner cookies set: {list(self.cookies.keys())}")

    # ── Public API ────────────────────────────────────────────────────────────

    def scan(self, urls: list[str]) -> list[Vulnerability]:
        injectable_urls = [u for u in urls if "?" in u]
        if not injectable_urls:
            log.warning("No URLs with query parameters. SQLi scan skipped.")
            return []

        log.info(
            f"SQLi scan started (multithreaded, {self.max_workers} workers). "
            f"{len(injectable_urls)} injectable URL(s)."
        )

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._scan_url, url): url
                for url in injectable_urls
            }
            for future in as_completed(futures):
                url = futures[future]
                try:
                    future.result()
                except Exception as e:
                    log.warning(f"Error scanning {url}: {e}")

        log.info(
            f"SQLi scan complete. {len(self.findings)} "
            f"vulnerability/vulnerabilities found."
        )
        return self.findings

    def scan_forms(self, forms: list[dict]) -> list[Vulnerability]:
        if not forms:
            return []

        log.info(
            f"SQLi form scan started ({self.max_workers} workers). "
            f"{len(forms)} form(s)."
        )

        from scanner.forms import FormCrawler
        from scanner.mutator import PayloadMutator
        mutator      = PayloadMutator()
        form_crawler = FormCrawler(session=self.session)

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._scan_form, form, form_crawler, mutator): form
                for form in forms
                if form.get("injectable_fields")
            }
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    log.warning(f"Form scan error: {e}")

        return self.findings

    # ── Per-URL scanning ──────────────────────────────────────────────────────

    def _scan_url(self, url: str) -> None:
        log.info(f"[Thread] Scanning: {url}")

        baseline = self._fetch(url)
        if baseline is None:
            log.warning(
                f"[SQLi] Base URL unreachable or redirected to login: {url} "
                f"| cookies: {list(self.session.cookies.keys())}"
            )
            return

        params = self._extract_params(url)
        for param_name in params:
            self._test_error_based(url, param_name, baseline)
            self._test_boolean_based(url, param_name, baseline)
            self._test_time_based(url, param_name)

    def _scan_form(self, form: dict, form_crawler, mutator) -> None:
        log.info(f"[Thread] Form scan: {form['action']}")
        for field in form["injectable_fields"]:
            for base_payload in ERROR_PAYLOADS[:5]:
                for payload in mutator.mutate_sqli(base_payload)[:5]:
                    response = form_crawler.submit_form(
                        form, payload, target_field=field
                    )
                    if response is None:
                        continue
                    matched = self._find_db_error(response)
                    if matched:
                        log.warning(
                            f"[FORM SQLi] {form['action']} | "
                            f"field='{field}' | payload='{payload}'"
                        )
                        self._add_finding(Vulnerability(
                            vuln_type   = "SQL Injection (Form - Error-based)",
                            url         = form["action"],
                            parameter   = field,
                            payload     = payload,
                            severity    = Severity.HIGH,
                            description = (
                                f"Form field '{field}' at '{form['action']}' "
                                f"is vulnerable to SQL injection. "
                                f"DB error '{matched}' found in response."
                            ),
                            evidence    = matched,
                        ))
                        return

    # ── Detection techniques ──────────────────────────────────────────────────

    def _test_error_based(
        self, url: str, param: str, baseline: str | None = None
    ) -> None:
        for payload in ERROR_PAYLOADS:
            injected_url  = self._inject_payload(url, param, payload)
            response_text = self._fetch(injected_url)
            if response_text is None:
                continue
            matched_error = self._find_db_error(response_text)
            if matched_error:
                log.warning(
                    f"[ERROR-BASED SQLi] {url} | param='{param}' | "
                    f"payload='{payload}' | matched='{matched_error}'"
                )
                self._add_finding(Vulnerability(
                    vuln_type   = "SQL Injection (Error-based)",
                    url         = url,
                    parameter   = param,
                    payload     = payload,
                    severity    = Severity.HIGH,
                    description = (
                        f"The parameter '{param}' is vulnerable to "
                        f"error-based SQL injection. DB error "
                        f"'{matched_error}' was reflected in the response."
                    ),
                    evidence    = matched_error,
                ))
                return

    def _test_boolean_based(
        self, url: str, param: str, baseline: str | None = None
    ) -> None:
        base_len = len(baseline) if baseline else None

        for true_payload, false_payload in BOOLEAN_PAYLOADS:
            true_url   = self._inject_payload(url, param, true_payload)
            false_url  = self._inject_payload(url, param, false_payload)
            true_resp  = self._fetch(true_url)
            false_resp = self._fetch(false_url)

            if true_resp is None or false_resp is None:
                continue

            if base_len is None:
                b = self._fetch(url)
                base_len = len(b) if b else 0

            true_len  = len(true_resp)
            false_len = len(false_resp)

            if abs(true_len - base_len) < 50 and abs(false_len - base_len) > 100:
                log.warning(f"[BOOLEAN-BASED SQLi] {url} | param='{param}'")
                self._add_finding(Vulnerability(
                    vuln_type   = "SQL Injection (Boolean-based)",
                    url         = url,
                    parameter   = param,
                    payload     = f"TRUE: {true_payload} | FALSE: {false_payload}",
                    severity    = Severity.HIGH,
                    description = (
                        f"Parameter '{param}' shows different response lengths "
                        f"for TRUE ({true_len}b) vs FALSE ({false_len}b)."
                    ),
                    evidence    = (
                        f"Baseline:{base_len}b | True:{true_len}b | False:{false_len}b"
                    ),
                ))
                return

    def _test_time_based(self, url: str, param: str) -> None:
        for payload in TIME_PAYLOADS:
            injected_url  = self._inject_payload(url, param, payload)
            start         = time.time()
            response_text = self._fetch(injected_url, timeout=15)
            elapsed       = time.time() - start
            if response_text is None:
                continue
            if elapsed >= SQLI_TIMEOUT_THRESHOLD:
                log.warning(
                    f"[TIME-BASED SQLi] {url} | param='{param}' | "
                    f"delay={elapsed:.2f}s"
                )
                self._add_finding(Vulnerability(
                    vuln_type   = "SQL Injection (Time-based)",
                    url         = url,
                    parameter   = param,
                    payload     = payload,
                    severity    = Severity.HIGH,
                    description = (
                        f"Parameter '{param}' caused {elapsed:.1f}s delay "
                        f"with SLEEP payload."
                    ),
                    evidence    = f"Response time: {elapsed:.2f}s",
                ))
                return

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _find_db_error(self, response_text: str) -> str | None:
        """Check response text for known database error signatures."""
        lower_text = response_text.lower()
        for sig in DB_ERROR_SIGNATURES:
            if sig.lower() in lower_text:
                return sig
        return None

    def _add_finding(self, vuln: Vulnerability) -> None:
        """Thread-safe deduplicating finding append."""
        with self._lock:
            for existing in self.findings:
                if (existing.url == vuln.url
                        and existing.parameter == vuln.parameter
                        and existing.vuln_type == vuln.vuln_type):
                    return
            self.findings.append(vuln)

    def _extract_params(self, url: str) -> list[str]:
        parsed = urlparse(url)
        return list(parse_qs(parsed.query).keys())

    def _inject_payload(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        new_params = {
            k: [payload] if k == param else v
            for k, v in params.items()
        }
        return urlunparse(parsed._replace(query=urlencode(new_params, doseq=True)))

    def _fetch(self, url: str, timeout: int = REQUEST_TIMEOUT) -> str | None:
        try:
            response = self.session.get(
                url, timeout=timeout, allow_redirects=True
            )
            if self._is_login_redirect(response):
                log.debug(
                    f"Session redirected to login for: {url} "
                    f"(final url: {response.url})"
                )
                return None
            return response.text
        except Exception as e:
            log.debug(f"Request error: {url} — {e}")
            return None

    def _is_login_redirect(self, response) -> bool:
        """
        Returns True if the response looks like a redirect to the login page.
        NOTE: Does NOT check for 'username'/'password' in URL to avoid
        false-positives on pages that contain login forms alongside content.
        """
        final_url = response.url.lower()
        for indicator in LOGIN_INDICATORS:
            if indicator in final_url:
                return True
        # Body check — only flag if it looks exclusively like a login page
        body = response.text[:2000].lower()
        if (
            'name="user_token"' in body
            or 'action="login.php"' in body
        ):
            return True
        return False