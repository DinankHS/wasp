# scanner/port_scanner.py
"""
WASP Port Scanner — Phase 1
Performs TCP connect scan on top ports.
Detects open ports and identifies common services.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from config import TOP_PORTS
from core.logger import get_logger
from core.models import PortResult

log = get_logger(__name__)

# Common port-to-service mapping
PORT_SERVICES = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}


class PortScanner:
    """
    TCP connect port scanner using threading for speed.
    """

    def __init__(self, host: str, ports: list[int] = TOP_PORTS, timeout: float = 1.0):
        self.host    = host
        self.ports   = ports
        self.timeout = timeout
        self.results: list[PortResult] = []

    def scan(self) -> list[PortResult]:
        """Scan all ports using a thread pool. Returns list of PortResult."""
        log.info(f"Port scan started on {self.host} — {len(self.ports)} ports")

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {
                executor.submit(self._scan_port, port): port
                for port in self.ports
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.results.append(result)

        # Sort by port number
        self.results.sort(key=lambda r: r.port)
        log.info(f"Port scan complete. {len(self.results)} open port(s) found.")
        return self.results

    def _scan_port(self, port: int) -> PortResult | None:
        """
        Attempt TCP connection to a single port.
        Returns PortResult if open, None if closed/filtered.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.host, port))
            sock.close()

            if result == 0:
                service = PORT_SERVICES.get(port, "unknown")
                log.info(f"Open port found: {port} ({service})")
                return PortResult(port=port, state="open", service=service)

        except socket.error as e:
            log.debug(f"Socket error on port {port}: {e}")

        return None