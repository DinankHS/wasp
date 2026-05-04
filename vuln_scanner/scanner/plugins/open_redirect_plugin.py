# scanner/plugins/open_redirect_plugin.py
"""
WASP Open Redirect Plugin
Detects unvalidated redirect vulnerabilities by injecting
external URLs into redirect/return parameters.

Example vulnerable URL:
    http://site.com/redirect?url=http://evil.com
    Response: 302 Location: http://evil.com
"""

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.models import Severity
from scanner.plugins.base_plugin import BasePlugin


class OpenRedirectPlugin(BasePlugin):

    name        = "Open Redirect Scanner"
    version     = "1.0"
    description = "Detects unvalidated URL redirect vulnerabilities"
    author      = "WASP"

    # Parameters commonly used for redirects
    REDIRECT_PARAMS = [
        "url", "redirect", "return", "next", "goto",
        "dest", "destination", "target", "redir",
        "redirect_url", "return_url", "callback",
        "continue", "forward", "location", "link",
        "ref", "referrer", "out", "view", "go",
    ]

    # Canary domain — safe external URL for testing
    CANARY = "http://example.com/wasp-redirect-test"

    def scan(
        self,
        urls: list[str],
        forms: list[dict] | None = None,
    ) -> list:

        self.log.info(
            f"Open Redirect scan started. {len(urls)} URL(s)."
        )

        for url in urls:
            if "?" not in url:
                continue
            self._test_url(url)

        self.log.info(
            f"Open Redirect scan complete. {len(self.findings)} finding(s)."
        )
        return self.findings

    def _test_url(self, url: str) -> None:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        for param_name in params:
            # Only test parameters with redirect-like names
            if param_name.lower() not in self.REDIRECT_PARAMS:
                continue

            test_url = urlunparse(
                parsed._replace(
                    query=urlencode(
                        {**params, param_name: [self.CANARY]},
                        doseq=True
                    )
                )
            )

            try:
                # Don't follow redirects — we want to see the 302
                if self.session is None:
                    import requests as req
                    self.session = req.Session()

                resp = self.session.get(
                    test_url,
                    timeout=10,
                    allow_redirects=False,
                )

                # Check if redirect goes to our canary
                location = resp.headers.get("Location", "")
                if (
                    resp.status_code in (301, 302, 303, 307, 308)
                    and "example.com" in location
                ):
                    self.add_finding(
                        vuln_type   = "Open Redirect",
                        url         = url,
                        parameter   = param_name,
                        payload     = self.CANARY,
                        severity    = Severity.MEDIUM,
                        description = (
                            f"Parameter '{param_name}' allows unvalidated "
                            f"redirects to external URLs. Attackers can use "
                            f"this for phishing by crafting trusted-looking "
                            f"redirect links."
                        ),
                        evidence    = f"302 Location: {location}",
                    )
                    return

            except Exception as e:
                self.log.debug(f"Redirect test error ({url}): {e}")