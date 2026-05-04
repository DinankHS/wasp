# scanner/plugins/my_plugin.py
from core.models import Severity
from scanner.plugins.base_plugin import BasePlugin

class MyPlugin(BasePlugin):
    name        = "My Custom Scanner"
    version     = "1.0"
    description = "Detects something interesting"

    def scan(self, urls, forms=None):
        for url in urls:
            response = self.fetch(url)
            if response and "something_bad" in response:
                self.add_finding(
                    vuln_type   = "My Vulnerability",
                    url         = url,
                    parameter   = "N/A",
                    payload     = "N/A",
                    severity    = Severity.MEDIUM,
                    description = "Found something bad.",
                    evidence    = "something_bad in response",
                )
        return self.findings