# config.py
"""
Central configuration for the vulnerability scanner.
All tuneable values live here — never hardcode these in scanner modules.
"""

import os

# ── Request settings ──────────────────────────────────────────────────────────
REQUEST_TIMEOUT = 10          # seconds before a request is abandoned
REQUEST_DELAY   = 0.5         # polite delay between requests (be a good citizen)
MAX_RETRIES     = 2           # retry count on transient network errors
USER_AGENT      = (
    "VulnScanner/1.0 (Educational Use Only; "
    "github.com/yourname/vuln_scanner)"
)

# ── Crawler settings ──────────────────────────────────────────────────────────
MAX_CRAWL_DEPTH = 3           # how deep to follow links from the root URL
MAX_URLS        = 100         # safety cap: stop after this many URLs

# ── Scanner settings ──────────────────────────────────────────────────────────
SQLI_TIMEOUT_THRESHOLD = 5    # extra seconds that suggest a time-based SQLi hit
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143,
    443, 445, 3306, 3389, 5432, 8080, 8443
]

# ── Output settings ───────────────────────────────────────────────────────────
OUTPUT_DIR = r"C:\wasp_reports"
LOG_DIR    = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
LOG_LEVEL  = "INFO"

# ── Safety / scope guard ─────────────────────────────────────────────────────
# The scanner will REFUSE to scan anything outside this scope.
# Populated at runtime from the CLI argument.
ALLOWED_SCOPE: list[str] = []