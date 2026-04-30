# core/models.py
"""
Data models for scan results.
All scanner modules produce Vulnerability objects, which are
collected into a ScanResult and handed to the reporter.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    """CVSS-inspired severity levels."""
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


@dataclass
class Vulnerability:
    """A single confirmed or suspected vulnerability finding."""
    vuln_type:   str              # e.g. "SQL Injection", "Reflected XSS"
    url:         str              # the URL where it was found
    parameter:   str              # which param/field triggered it
    payload:     str              # the payload that worked
    severity:    Severity
    description: str              # human-readable finding summary
    evidence:    str = ""         # snippet from the response confirming the hit
    remediation: str = ""         # Phase 2: AI-generated fix (empty in Phase 1)


@dataclass
class PortResult:
    """Result from a single port probe."""
    port:    int
    state:   str      # "open" | "closed" | "filtered"
    service: str = "" # e.g. "http", "ssh" (Phase 2: banner grab)


@dataclass
class ScanResult:
    """Top-level container for everything a scan produces."""
    target:          str
    start_time:      str = field(
        default_factory=lambda: datetime.now().isoformat()
    )
    end_time:        str = ""
    urls_crawled:    list[str]          = field(default_factory=list)
    vulnerabilities: list[Vulnerability]= field(default_factory=list)
    open_ports:      list[PortResult]   = field(default_factory=list)
    errors:          list[str]          = field(default_factory=list)

    def add_vuln(self, vuln: Vulnerability) -> None:
        self.vulnerabilities.append(vuln)

    def add_port(self, port: PortResult) -> None:
        self.open_ports.append(port)

    def finalize(self) -> None:
        """Call when the scan is complete."""
        self.end_time = datetime.now().isoformat()

    def summary(self) -> str:
        return (
            f"Target: {self.target}\n"
            f"URLs crawled: {len(self.urls_crawled)}\n"
            f"Vulnerabilities found: {len(self.vulnerabilities)}\n"
            f"Open ports: {len(self.open_ports)}\n"
        )