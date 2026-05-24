# reporter/csv_reporter.py
"""
WASP CSV Reporter
Serializes ScanResult to a CSV file — Excel-compatible findings export.
"""

import csv
import os
from datetime import datetime

from config import OUTPUT_DIR
from core.logger import get_logger
from core.models import ScanResult
from core.utils import sanitize_filename

log = get_logger(__name__)


def generate(result: ScanResult) -> str:
    """
    Generate a CSV report from a ScanResult.
    Returns the path to the generated file.
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = sanitize_filename(
        result.target.replace("http://", "").replace("https://", "")
    )
    filename = f"wasp_{safe_name}_{timestamp}.csv"
    filepath = os.path.join(OUTPUT_DIR, filename)

    headers = [
        "#", "Severity", "Type", "URL",
        "Parameter", "Payload", "Evidence", "Remediation"
    ]

    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        for i, v in enumerate(result.vulnerabilities, 1):
            writer.writerow([
                i,
                v.severity.value,
                v.vuln_type,
                v.url,
                v.parameter,
                v.payload,
                v.evidence,
                v.remediation,
            ])

    log.info(f"CSV report saved: {filepath}")
    return filepath