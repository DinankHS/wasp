# reporter/json_reporter.py
"""
WASP JSON Reporter — Phase 1
Serializes ScanResult to a JSON file.
"""

import json
import os
from datetime import datetime

from config import OUTPUT_DIR
from core.logger import get_logger
from core.models import ScanResult
from core.utils import sanitize_filename

log = get_logger(__name__)


def generate(result: ScanResult) -> str:
    """
    Generate a JSON report from a ScanResult.
    Returns the path to the generated file.
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Build filename from target and timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = sanitize_filename(result.target.replace("http://", "").replace("https://", ""))
    filename  = f"wasp_{safe_name}_{timestamp}.json"
    filepath  = os.path.join(OUTPUT_DIR, filename)

    # Build report dict
    report = {
        "wasp_version": "1.0",
        "target":       result.target,
        "start_time":   result.start_time,
        "end_time":     result.end_time,
        "summary": {
            "urls_crawled":       len(result.urls_crawled),
            "vulnerabilities":    len(result.vulnerabilities),
            "open_ports":         len(result.open_ports),
            "errors":             len(result.errors),
        },
        "urls_crawled": result.urls_crawled,
        "vulnerabilities": [
            {
                "type":        v.vuln_type,
                "url":         v.url,
                "parameter":   v.parameter,
                "payload":     v.payload,
                "severity":    v.severity.value,
                "description": v.description,
                "evidence":    v.evidence,
                "remediation": v.remediation,
            }
            for v in result.vulnerabilities
        ],
        "open_ports": [
            {
                "port":    p.port,
                "state":   p.state,
                "service": p.service,
            }
            for p in result.open_ports
        ],
        "errors": result.errors,
    }

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    log.info(f"JSON report saved: {filepath}")
    return filepath