# scanner/plugins/base_plugin.py
"""
WASP Base Plugin — Phase 2
All vulnerability scanner plugins must inherit from this class.

Required overrides:
    name        — short plugin name e.g. "LFI Scanner"
    version     — version string e.g. "1.0"
    description — one-line description
    scan()      — main scan method

Optional overrides:
    setup()     — called once before scanning starts
    teardown()  — called once after scanning finishes
"""

from core.models import Vulnerability, ScanResult
from core.logger import get_logger


class BasePlugin:
    """
    Abstract base class for all WASP scanner plugins.
    Every plugin must implement at minimum: name, version,
    description, and scan().
    """

    # ── Plugin metadata (override in subclass) ────────────────────────────────
    name:        str = "Unnamed Plugin"
    version:     str = "1.0"
    description: str = "No description provided."
    author:      str = "Unknown"

    def __init__(self):
        self.log      = get_logger(f"plugin.{self.name}")
        self.findings: list[Vulnerability] = []
        self.session  = None   # set by WASP before calling scan()
        self.cookies: dict | None = None

    # ── Lifecycle hooks ───────────────────────────────────────────────────────

    def setup(self) -> None:
        """
        Optional: called once before scan() runs.
        Use for any initialization or warm-up logic.
        """
        pass

    def teardown(self) -> None:
        """
        Optional: called once after scan() finishes.
        Use for cleanup or closing connections.
        """
        pass

    # ── Main scan method (MUST override) ──────────────────────────────────────

    def scan(
        self,
        urls: list[str],
        forms: list[dict] | None = None,
    ) -> list[Vulnerability]:
        """
        Run the plugin against the provided URLs and forms.

        Args:
            urls  — list of discovered URLs from the crawler
            forms — list of form dicts from FormCrawler (may be None)

        Returns:
            list of Vulnerability objects found by this plugin.
            Return an empty list if nothing found.
        """
        raise NotImplementedError(
            f"Plugin '{self.name}' must implement scan()"
        )

    # ── Helpers available to all plugins ─────────────────────────────────────

    def fetch(self, url: str, timeout: int = 10) -> str | None:
        """
        Fetch a URL using the authenticated session.
        Returns response text or None on error.
        """
        if self.session is None:
            import requests
            self.session = requests.Session()

        try:
            resp = self.session.get(
                url, timeout=timeout, allow_redirects=True
            )
            if "login" in resp.url and "login" not in url:
                self.log.debug(f"Redirected to login: {url}")
                return None
            return resp.text
        except Exception as e:
            self.log.debug(f"Fetch error ({url}): {e}")
            return None

    def post(
        self,
        url: str,
        data: dict,
        timeout: int = 10,
    ) -> str | None:
        """
        POST data to a URL using the authenticated session.
        Returns response text or None on error.
        """
        if self.session is None:
            import requests
            self.session = requests.Session()

        try:
            resp = self.session.post(
                url, data=data,
                timeout=timeout, allow_redirects=True
            )
            return resp.text
        except Exception as e:
            self.log.debug(f"POST error ({url}): {e}")
            return None

    def add_finding(
        self,
        vuln_type:   str,
        url:         str,
        parameter:   str,
        payload:     str,
        severity,
        description: str,
        evidence:    str = "",
    ) -> Vulnerability:
        """
        Helper to create and record a Vulnerability finding.
        Returns the created Vulnerability object.
        """
        from core.models import Vulnerability
        vuln = Vulnerability(
            vuln_type   = vuln_type,
            url         = url,
            parameter   = parameter,
            payload     = payload,
            severity    = severity,
            description = description,
            evidence    = evidence,
        )
        self.findings.append(vuln)
        self.log.warning(
            f"[{self.name}] Found: {vuln_type} at {url} "
            f"param='{parameter}'"
        )
        return vuln