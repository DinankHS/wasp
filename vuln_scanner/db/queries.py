# db/queries.py
"""
WASP database query functions.

Every public function accepts plain Python types (str, dict, dataclasses)
so callers never need to import psycopg2 directly.

Import pattern:
    from db.queries import (
        create_scan, finish_scan, save_results,
        get_scan, list_scans, delete_scan,
    )
"""

import os
import logging
from datetime import datetime, timezone
from psycopg2.extras import RealDictCursor

from .connection import get_conn

log = logging.getLogger("wasp.db.queries")


# ─────────────────────────────────────────────────────────────────────────────
# SCANS
# ─────────────────────────────────────────────────────────────────────────────

def create_scan(scan_id: str, config: dict) -> None:
    """
    Insert a new scan row when a scan starts.

    Args:
        scan_id: The unique scan identifier (e.g. "20240101_120000_123456")
        config:  The config dict from dashboard/app.py or main.py
    """
    sql = """
        INSERT INTO scans (
            id, target, status, depth, app_type,
            skip_ports, use_ai, output_format, cookie_supplied, started_at
        ) VALUES (
            %(id)s, %(target)s, 'running', %(depth)s, %(app_type)s,
            %(skip_ports)s, %(use_ai)s, %(output_format)s, %(cookie_supplied)s, NOW()
        )
        ON CONFLICT (id) DO NOTHING;
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, {
                "id":              scan_id,
                "target":          config.get("target", ""),
                "depth":           int(config.get("depth", 2)),
                "app_type":        config.get("app_type", "none"),
                "skip_ports":      bool(config.get("skip_ports", False)),
                "use_ai":          bool(config.get("use_ai", False)),
                "output_format":   config.get("output", "all"),
                "cookie_supplied": bool(config.get("cookie", "")),
            })
    log.debug("Scan created: %s", scan_id)


def finish_scan(
    scan_id: str,
    status: str,
    scan_result,          # core.models.ScanResult
    error_message: str = "",
) -> None:
    """
    Update the scan row when the scan finishes (complete / error / stopped).

    Args:
        scan_id:       Scan identifier
        status:        "complete" | "error" | "stopped"
        scan_result:   ScanResult object (may be None on error)
        error_message: Populated only when status == "error"
    """
    urls_crawled = len(scan_result.urls_crawled)    if scan_result else 0
    vuln_count   = len(scan_result.vulnerabilities) if scan_result else 0
    port_count   = len(scan_result.open_ports)      if scan_result else 0
    error_count  = len(scan_result.errors)          if scan_result else 0

    sql = """
        UPDATE scans SET
            status        = %(status)s,
            finished_at   = NOW(),
            urls_crawled  = %(urls_crawled)s,
            vuln_count    = %(vuln_count)s,
            port_count    = %(port_count)s,
            error_count   = %(error_count)s,
            error_message = %(error_message)s
        WHERE id = %(id)s;
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, {
                "id":            scan_id,
                "status":        status,
                "urls_crawled":  urls_crawled,
                "vuln_count":    vuln_count,
                "port_count":    port_count,
                "error_count":   error_count,
                "error_message": error_message,
            })
    log.debug("Scan finished: %s → %s", scan_id, status)


def get_scan(scan_id: str) -> dict | None:
    """Return a single scan row as a dict, or None if not found."""
    sql = "SELECT * FROM scans WHERE id = %s;"
    with get_conn() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, (scan_id,))
            row = cur.fetchone()
            return dict(row) if row else None


def list_scans(
    limit: int = 50,
    offset: int = 0,
    status: str | None = None,
    target_filter: str | None = None,
) -> list[dict]:
    """
    Return a list of scans ordered by started_at DESC.

    Args:
        limit:         Max rows to return
        offset:        Pagination offset
        status:        Filter by status ("complete", "error", etc.)
        target_filter: Case-insensitive substring match on target URL
    """
    conditions = []
    params: dict = {"limit": limit, "offset": offset}

    if status:
        conditions.append("status = %(status)s")
        params["status"] = status

    if target_filter:
        conditions.append("target ILIKE %(target_filter)s")
        params["target_filter"] = f"%{target_filter}%"

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    sql = f"""
        SELECT
            id, target, status, started_at, finished_at,
            urls_crawled, vuln_count, port_count, use_ai, app_type
        FROM scans
        {where}
        ORDER BY started_at DESC
        LIMIT %(limit)s OFFSET %(offset)s;
    """
    with get_conn() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, params)
            return [dict(r) for r in cur.fetchall()]


def delete_scan(scan_id: str) -> bool:
    """
    Hard-delete a scan and all related rows (CASCADE).
    Returns True if a row was deleted, False if scan_id not found.
    """
    sql = "DELETE FROM scans WHERE id = %s RETURNING id;"
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (scan_id,))
            return cur.fetchone() is not None


# ─────────────────────────────────────────────────────────────────────────────
# VULNERABILITIES
# ─────────────────────────────────────────────────────────────────────────────

def save_vulnerabilities(scan_id: str, vulnerabilities: list) -> None:
    """
    Bulk-insert all Vulnerability objects for a scan.

    Args:
        scan_id:         Scan identifier
        vulnerabilities: List of core.models.Vulnerability
    """
    if not vulnerabilities:
        return

    sql = """
        INSERT INTO vulnerabilities
            (scan_id, vuln_type, url, parameter, payload, severity,
             description, evidence, remediation)
        VALUES
            (%(scan_id)s, %(vuln_type)s, %(url)s, %(parameter)s, %(payload)s,
             %(severity)s, %(description)s, %(evidence)s, %(remediation)s);
    """
    rows = [
        {
            "scan_id":     scan_id,
            "vuln_type":   v.vuln_type,
            "url":         v.url,
            "parameter":   v.parameter  or "",
            "payload":     v.payload    or "",
            "severity":    v.severity.value if hasattr(v.severity, "value") else str(v.severity),
            "description": v.description or "",
            "evidence":    v.evidence    or "",
            "remediation": v.remediation or "",
        }
        for v in vulnerabilities
    ]
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.executemany(sql, rows)
    log.debug("Saved %d vulnerabilities for scan %s", len(rows), scan_id)


def get_vulnerabilities(
    scan_id: str,
    severity: str | None = None,
) -> list[dict]:
    """
    Return all vulnerabilities for a scan.

    Args:
        scan_id:  Scan identifier
        severity: Optional filter (CRITICAL | HIGH | MEDIUM | LOW | INFO)
    """
    params: dict = {"scan_id": scan_id}
    extra = ""
    if severity:
        extra = "AND severity = %(severity)s"
        params["severity"] = severity.upper()

    sql = f"""
        SELECT *
        FROM   vulnerabilities
        WHERE  scan_id = %(scan_id)s {extra}
        ORDER  BY
            CASE severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH'     THEN 2
                WHEN 'MEDIUM'   THEN 3
                WHEN 'LOW'      THEN 4
                ELSE 5
            END,
            found_at;
    """
    with get_conn() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, params)
            return [dict(r) for r in cur.fetchall()]


def vuln_severity_counts(scan_id: str) -> dict[str, int]:
    """Return {severity: count} for a given scan — useful for charts."""
    sql = """
        SELECT severity, COUNT(*) AS cnt
        FROM   vulnerabilities
        WHERE  scan_id = %s
        GROUP  BY severity;
    """
    with get_conn() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, (scan_id,))
            return {r["severity"]: r["cnt"] for r in cur.fetchall()}


# ─────────────────────────────────────────────────────────────────────────────
# PORTS
# ─────────────────────────────────────────────────────────────────────────────

def save_ports(scan_id: str, ports: list) -> None:
    """
    Bulk-insert open port results.

    Args:
        scan_id: Scan identifier
        ports:   List of core.models.PortResult
    """
    if not ports:
        return

    sql = """
        INSERT INTO ports (scan_id, port, state, service)
        VALUES (%(scan_id)s, %(port)s, %(state)s, %(service)s);
    """
    rows = [
        {
            "scan_id": scan_id,
            "port":    p.port,
            "state":   p.state   or "open",
            "service": p.service or "",
        }
        for p in ports
    ]
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.executemany(sql, rows)
    log.debug("Saved %d ports for scan %s", len(rows), scan_id)


def get_ports(scan_id: str) -> list[dict]:
    """Return all port results for a scan."""
    sql = "SELECT * FROM ports WHERE scan_id = %s ORDER BY port;"
    with get_conn() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, (scan_id,))
            return [dict(r) for r in cur.fetchall()]


# ─────────────────────────────────────────────────────────────────────────────
# URLS
# ─────────────────────────────────────────────────────────────────────────────

def save_urls(scan_id: str, urls: list[str]) -> None:
    """Bulk-insert crawled URLs."""
    if not urls:
        return

    sql = "INSERT INTO urls (scan_id, url) VALUES (%(scan_id)s, %(url)s);"
    rows = [{"scan_id": scan_id, "url": u} for u in urls]
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.executemany(sql, rows)
    log.debug("Saved %d URLs for scan %s", len(rows), scan_id)


def get_urls(scan_id: str) -> list[str]:
    """Return all crawled URLs for a scan."""
    sql = "SELECT url FROM urls WHERE scan_id = %s ORDER BY id;"
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (scan_id,))
            return [r[0] for r in cur.fetchall()]


# ─────────────────────────────────────────────────────────────────────────────
# REPORTS
# ─────────────────────────────────────────────────────────────────────────────

def save_reports(scan_id: str, reports: dict[str, str]) -> None:
    """
    Save report file metadata.

    Args:
        scan_id: Scan identifier
        reports: Dict of {report_type: absolute_filepath}
                 e.g. {"json": "/path/to/scan.json", "pdf": "/path/to/scan.pdf"}
    """
    if not reports:
        return

    sql = """
        INSERT INTO reports (scan_id, report_type, filename, filepath, file_size)
        VALUES (%(scan_id)s, %(report_type)s, %(filename)s, %(filepath)s, %(file_size)s)
        ON CONFLICT DO NOTHING;
    """
    rows = []
    for rtype, fpath in reports.items():
        try:
            size = os.path.getsize(fpath) if os.path.exists(fpath) else 0
        except OSError:
            size = 0
        rows.append({
            "scan_id":     scan_id,
            "report_type": rtype,
            "filename":    os.path.basename(fpath),
            "filepath":    fpath,
            "file_size":   size,
        })

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.executemany(sql, rows)
    log.debug("Saved %d report records for scan %s", len(rows), scan_id)


def get_reports(scan_id: str) -> list[dict]:
    """Return all report metadata for a scan."""
    sql = "SELECT * FROM reports WHERE scan_id = %s ORDER BY created_at;"
    with get_conn() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, (scan_id,))
            return [dict(r) for r in cur.fetchall()]


# ─────────────────────────────────────────────────────────────────────────────
# CONVENIENCE — save everything at once
# ─────────────────────────────────────────────────────────────────────────────

def save_results(
    scan_id: str,
    scan_result,           # core.models.ScanResult
    reports: dict[str, str],
    status: str = "complete",
    error_message: str = "",
) -> None:
    """
    One-shot function to persist a completed scan:
      1. finish_scan()         — update scans row
      2. save_vulnerabilities()
      3. save_ports()
      4. save_urls()
      5. save_reports()

    This is what dashboard/app.py and main.py should call
    at the end of a successful (or failed) scan.

    Args:
        scan_id:       Scan identifier
        scan_result:   Completed ScanResult object
        reports:       Dict {type: filepath} from the reporter
        status:        "complete" | "error" | "stopped"
        error_message: Only populated when status == "error"
    """
    finish_scan(scan_id, status, scan_result, error_message)

    if scan_result:
        save_vulnerabilities(scan_id, scan_result.vulnerabilities)
        save_ports(scan_id,          scan_result.open_ports)
        save_urls(scan_id,           scan_result.urls_crawled)

    save_reports(scan_id, reports)
    log.info("All results saved for scan %s (status=%s)", scan_id, status)


# ─────────────────────────────────────────────────────────────────────────────
# STATS — dashboard overview cards
# ─────────────────────────────────────────────────────────────────────────────

def global_stats() -> dict:
    """
    Return aggregate stats for the dashboard overview.

    Returns:
        {
            "total_scans":   int,
            "total_vulns":   int,
            "critical_vulns":int,
            "targets_scanned":int,
        }
    """
    sql = """
        SELECT
            COUNT(DISTINCT s.id)            AS total_scans,
            COALESCE(SUM(s.vuln_count), 0)  AS total_vulns,
            COUNT(DISTINCT s.target)        AS targets_scanned,
            COALESCE(
                (SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'CRITICAL'), 0
            )                               AS critical_vulns
        FROM scans s
        WHERE s.status = 'complete';
    """
    with get_conn() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql)
            row = cur.fetchone()
            return dict(row) if row else {}