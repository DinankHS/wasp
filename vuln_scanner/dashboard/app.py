"""
WASP Web Dashboard — Phase 2
Flask-based web interface for running and viewing scans.
"""

import os
import sys
import json
import threading
import queue
import time
from datetime import datetime

from flask import (
    Flask, render_template, request,
    jsonify, Response, send_file,
)

# Add parent directory to path so we can import WASP modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import OUTPUT_DIR
from core.logger import get_logger
from core.models import ScanResult
from core.utils import normalize_url, is_valid_url
from config import OUTPUT_DIR
os.makedirs(OUTPUT_DIR, exist_ok=True)

log = get_logger(__name__)

app = Flask(__name__)
app.secret_key = os.urandom(24)

scans: dict[str, dict] = {}

# ── Database setup ────────────────────────────────────────────────────────────
try:
    from db import init_pool, run_migrations
    from db.queries import (
        create_scan, save_results, list_scans as db_list_scans,
        get_scan, get_vulnerabilities, get_ports, get_reports,
        global_stats,
    )
    init_pool()
    run_migrations()
    DB_ENABLED = True
    log.info("Database connected and migrations applied.")
except Exception as _db_err:
    DB_ENABLED = False
    log.warning("Database unavailable — running without persistence: %s", _db_err)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan/start", methods=["POST"])
def start_scan():
    data   = request.get_json()
    target = data.get("target", "").strip()

    if not target:
        return jsonify({"error": "Target URL is required"}), 400

    target = normalize_url(target)
    if not is_valid_url(target):
        return jsonify({"error": "Invalid target URL"}), 400

    scan_id = datetime.now().strftime("%Y%m%d_%H%M%S_%f")

    config = {
        "target":     target,
        "depth":      int(data.get("depth", 2)),
        "skip_ports": data.get("skip_ports", True),
        "app_type":   data.get("app_type", "none"),
        "cookie":     data.get("cookie", ""),
        "use_ai":     data.get("use_ai", False),
        "output":     data.get("output", "both"),
    }

    progress_queue = queue.Queue()
    scans[scan_id] = {
        "id":             scan_id,
        "status":         "running",
        "config":         config,
        "progress_queue": progress_queue,
        "result":         None,
        "reports":        {},
        "started_at":     datetime.now().isoformat(),
        "error":          None,
    }

    thread = threading.Thread(
        target=_run_scan_thread,
        args=(scan_id, config, progress_queue),
        daemon=True,
    )
    thread.start()

    # Persist scan record immediately so it appears in history right away
    if DB_ENABLED:
        try:
            create_scan(scan_id, config)
        except Exception as _e:
            log.warning("DB create_scan failed: %s", _e)

    log.info(f"Scan {scan_id} started for target: {target}")
    return jsonify({"scan_id": scan_id, "status": "started"})


@app.route("/api/scan/<scan_id>/progress")
def scan_progress(scan_id: str):
    if scan_id not in scans:
        return jsonify({"error": "Scan not found"}), 404

    def event_stream():
        scan = scans[scan_id]
        pq   = scan["progress_queue"]
        while True:
            try:
                msg = pq.get(timeout=1.0)
                yield f"data: {json.dumps(msg)}\n\n"
                if msg.get("type") in ("complete", "error"):
                    break
            except queue.Empty:
                if scan["status"] in ("complete", "error"):
                    break
                yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"

    return Response(
        event_stream(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":               "no-cache",
            "X-Accel-Buffering":           "no",
            "Access-Control-Allow-Origin": "*",
        },
    )


@app.route("/api/scan/<scan_id>/result")
def scan_result(scan_id: str):
    if scan_id not in scans:
        return jsonify({"error": "Scan not found"}), 404

    scan = scans[scan_id]
    if scan["status"] == "running":
        return jsonify({"status": "running"})

    result = scan.get("result")
    if result is None:
        return jsonify({
            "status": "error",
            "error":  scan.get("error", "Unknown error"),
        })

    return jsonify(_serialize_result(result, scan))


@app.route("/api/scans")
def list_scans():
    scan_list = []
    for scan_id, scan in scans.items():
        result = scan.get("result")
        scan_list.append({
            "id":         scan_id,
            "target":     scan["config"]["target"],
            "status":     scan["status"],
            "started_at": scan["started_at"],
            "vuln_count": len(result.vulnerabilities) if result else 0,
            "url_count":  len(result.urls_crawled)    if result else 0,
        })
    return jsonify(sorted(
        scan_list, key=lambda x: x["started_at"], reverse=True
    ))


@app.route("/api/scan/<scan_id>/download/<report_type>")
def download_report(scan_id: str, report_type: str):
    if scan_id not in scans:
        return jsonify({"error": "Scan not found"}), 404

    scan    = scans[scan_id]
    reports = scan.get("reports", {})

    if report_type not in reports:
        return jsonify({"error": f"Report '{report_type}' not available"}), 404

    filepath = reports[report_type]

    # Ensure absolute path
    if not os.path.isabs(filepath):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        filepath  = os.path.join(base_dir, filepath)

    if not os.path.exists(filepath):
        log.error(f"Report file not found: {filepath}")
        return jsonify({"error": f"File not found: {filepath}"}), 404

    mime_types = {
        "json": "application/json",
        "txt":  "text/plain",
        "pdf":  "application/pdf",
    }

    return send_file(
        filepath,
        as_attachment=True,
        mimetype=mime_types.get(report_type, "application/octet-stream"),
        download_name=os.path.basename(filepath),
    )


@app.route("/api/scan/<scan_id>/stop", methods=["POST"])
def stop_scan(scan_id: str):
    if scan_id not in scans:
        return jsonify({"error": "Scan not found"}), 404
    scans[scan_id]["status"] = "stopped"

    # Persist stopped state
    if DB_ENABLED:
        try:
            save_results(
                scan_id,
                scans[scan_id].get("result"),
                scans[scan_id].get("reports", {}),
                status="stopped",
            )
        except Exception as _e:
            log.warning("DB save stopped state failed: %s", _e)

    return jsonify({"status": "stopped"})


# ── DB history routes ─────────────────────────────────────────────────────────

@app.route("/api/db/scans")
def db_scans_route():
    """
    Persistent scan history from PostgreSQL.
    Query params: limit, offset, status, target
    """
    if not DB_ENABLED:
        return jsonify({"error": "Database not configured"}), 503

    limit         = int(request.args.get("limit",  50))
    offset        = int(request.args.get("offset",  0))
    status_filter = request.args.get("status", None)
    target_filter = request.args.get("target", None)

    rows = db_list_scans(
        limit=limit, offset=offset,
        status=status_filter, target_filter=target_filter,
    )
    for r in rows:
        for k in ("started_at", "finished_at"):
            if r.get(k) and hasattr(r[k], "isoformat"):
                r[k] = r[k].isoformat()
    return jsonify(rows)


@app.route("/api/db/scan/<scan_id>")
def db_get_scan_route(scan_id: str):
    """Full scan detail from DB including vulns, ports, and reports."""
    if not DB_ENABLED:
        return jsonify({"error": "Database not configured"}), 503

    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    for k in ("started_at", "finished_at"):
        if scan.get(k) and hasattr(scan[k], "isoformat"):
            scan[k] = scan[k].isoformat()

    scan["vulnerabilities"] = get_vulnerabilities(scan_id)
    scan["ports"]           = get_ports(scan_id)
    scan["reports"]         = get_reports(scan_id)

    for v in scan["vulnerabilities"]:
        if v.get("found_at") and hasattr(v["found_at"], "isoformat"):
            v["found_at"] = v["found_at"].isoformat()
    for r in scan["reports"]:
        if r.get("created_at") and hasattr(r["created_at"], "isoformat"):
            r["created_at"] = r["created_at"].isoformat()

    return jsonify(scan)


@app.route("/api/db/stats")
def db_stats_route():
    """Global aggregate stats for dashboard overview cards."""
    if not DB_ENABLED:
        return jsonify({"error": "Database not configured"}), 503
    return jsonify(global_stats())


# ── Scan runner ───────────────────────────────────────────────────────────────

def _run_scan_thread(
    scan_id: str,
    config: dict,
    pq: queue.Queue,
) -> None:
    from config import OUTPUT_DIR
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    def progress(stage: str, message: str, data: dict | None = None):
        pq.put({
            "type":    "progress",
            "stage":   stage,
            "message": message,
            "data":    data or {},
            "time":    datetime.now().isoformat(),
        })

    try:
        from scanner.crawler      import Crawler
        from scanner.sqli         import SQLiScanner
        from scanner.xss          import XSSScanner
        from scanner.forms        import FormCrawler
        from scanner.port_scanner import PortScanner
        from reporter             import json_reporter, txt_reporter

        target      = config["target"]
        scan_result = ScanResult(target=target)

        # ── Auth ──────────────────────────────────────────────────────────────
        cookies      = None
        auth_session = None
        app_type     = config.get("app_type", "none")

        progress("auth", f"Setting up authentication ({app_type})")

        if app_type == "bwapp":
            from core.utils import bwapp_get_session
            from urllib.parse import urlparse as _up
            parsed       = _up(target)
            base         = f"{parsed.scheme}://{parsed.netloc}"
            auth_session = bwapp_get_session(base)
            if auth_session:
                cookies = {c.name: c.value for c in auth_session.cookies}
                cookies["security_level"] = "0"
                progress("auth", "bWAPP login successful")
            else:
                progress("auth", "bWAPP login failed — scanning without auth")

        elif app_type == "dvwa":
            from core.utils import dvwa_login
            from urllib.parse import urlparse as _up
            parsed  = _up(target)
            base    = f"{parsed.scheme}://{parsed.netloc}"
            cookies = dvwa_login(base)
            if cookies:
                progress("auth", "DVWA login successful")
                # Verify session is valid by checking a known authenticated page
                try:
                    import requests as _req
                    _test = _req.Session()
                    _test.cookies.update(cookies)
                    _r = _test.get(f"{base}/index.php", timeout=5, allow_redirects=True)
                    if "login.php" in _r.url.lower() or 'action="login.php"' in _r.text[:500].lower():
                        progress("auth", "DVWA session invalid — re-logging in")
                        cookies = dvwa_login(base)
                        if cookies:
                            progress("auth", "DVWA re-login successful")
                        else:
                            progress("auth", "DVWA re-login failed — scanning without auth")
                except Exception:
                    pass
            else:
                progress("auth", "DVWA login failed — scanning without auth")

        elif config.get("cookie"):
            cookies = {}
            for part in config["cookie"].replace(";", ",").split(","):
                part = part.strip()
                if "=" in part:
                    k, v = part.split("=", 1)
                    cookies[k.strip()] = v.strip()
            progress("auth", f"Cookies loaded: {list(cookies.keys())}")

        # ── Crawl ─────────────────────────────────────────────────────────────
        progress("crawler", f"Starting crawler (depth={config['depth']})")
        crawler = Crawler(
            seed_url=target,
            max_depth=config["depth"],
            cookies=cookies,
            session=auth_session,
        )
        urls = crawler.crawl()
        scan_result.urls_crawled = urls
        progress("crawler", f"Crawler complete — {len(urls)} URL(s) found", {
            "urls": urls,
        })

        # ── Forms ─────────────────────────────────────────────────────────────
        progress("forms", "Extracting forms from discovered pages")
        form_crawler = FormCrawler(session=auth_session, cookies=cookies)
        forms        = form_crawler.extract_forms(urls)
        progress("forms", f"Found {len(forms)} form(s)")

        # ── SQLi ──────────────────────────────────────────────────────────────
        progress("sqli", "Running SQL injection scanner")
        sqli_scanner  = SQLiScanner(cookies=cookies, session=auth_session)
        sqli_findings = sqli_scanner.scan(urls)

        if forms:
            form_sqli = sqli_scanner.scan_forms(forms)
            sqli_findings.extend(form_sqli)

        sqli_findings = _deduplicate(sqli_findings)
        for v in sqli_findings:
            scan_result.add_vuln(v)

        progress("sqli", f"SQLi complete — {len(sqli_findings)} finding(s)", {
            "count": len(sqli_findings),
        })

        # ── XSS ───────────────────────────────────────────────────────────────
        progress("xss", "Running XSS scanner")
        xss_scanner  = XSSScanner(cookies=cookies, session=auth_session)
        xss_findings = xss_scanner.scan(urls)

        if forms:
            form_xss = xss_scanner.scan_forms_with_mutation(forms)
            xss_findings.extend(form_xss)

        xss_findings = _deduplicate(xss_findings)
        for v in xss_findings:
            scan_result.add_vuln(v)

        progress("xss", f"XSS complete — {len(xss_findings)} finding(s)", {
            "count": len(xss_findings),
        })

        # ── Port scan ─────────────────────────────────────────────────────────
        if not config.get("skip_ports"):
            progress("ports", "Running port scanner")
            import socket
            try:
                host = socket.gethostbyname(
                    target.replace("http://", "").replace("https://", "")
                    .split("/")[0].split(":")[0]
                )
                port_scanner = PortScanner(host=host)
                ports        = port_scanner.scan()
                for p in ports:
                    scan_result.add_port(p)
                progress("ports", f"Port scan complete — {len(ports)} open port(s)", {
                    "count": len(ports),
                })
            except Exception as e:
                progress("ports", f"Port scan error: {e}")

        # ── AI enrichment ─────────────────────────────────────────────────────
        ai_analyses       = {}
        executive_summary = ""

        if config.get("use_ai"):
            progress("ai", "Running AI analysis on findings")
            try:
                from ai.advisor import AIAdvisor
                advisor = AIAdvisor()
                if advisor.enabled:
                    for i, vuln in enumerate(scan_result.vulnerabilities):
                        analysis       = advisor.analyze_vulnerability(vuln)
                        ai_analyses[i] = analysis
                        vuln.remediation = analysis.get("remediation", "")
                    executive_summary = advisor.generate_executive_summary(scan_result)
                    progress("ai", "AI analysis complete")
                else:
                    progress("ai", "AI skipped — no API key in .env")
            except Exception as e:
                progress("ai", f"AI error: {e}")

        # ── Reports ───────────────────────────────────────────────────────────
        scan_result.finalize()
        reports = {}
        output  = config.get("output", "both")
        if output == "all":
            output = "both"
        progress("reports", "Generating reports")

        if output in ("json", "both"):
            try:
                path            = os.path.abspath(json_reporter.generate(scan_result))
                reports["json"] = path
                progress("reports", f"JSON saved: {os.path.basename(path)}")
            except Exception as e:
                log.warning(f"JSON report error: {e}")

        if output in ("txt", "both"):
            try:
                path           = os.path.abspath(txt_reporter.generate(scan_result))
                reports["txt"] = path
                progress("reports", f"TXT saved: {os.path.basename(path)}")
            except Exception as e:
                log.warning(f"TXT report error: {e}")

        try:
            from reporter import pdf_reporter
            path           = os.path.abspath(pdf_reporter.generate(
                scan_result, ai_analyses, executive_summary
            ))
            reports["pdf"] = path
            progress("reports", f"PDF saved: {os.path.basename(path)}")
        except Exception as e:
            log.warning(f"PDF report error: {e}")
        
        # after the existing json/txt/pdf blocks
        try:
            from reporter import csv_reporter
            path           = os.path.abspath(csv_reporter.generate(scan_result))
            reports["csv"] = path
            progress("reports", f"CSV saved: {os.path.basename(path)}")
        except Exception as e:
            log.warning(f"CSV report error: {e}")

        # ── Done ──────────────────────────────────────────────────────────────
        scans[scan_id]["result"]  = scan_result
        scans[scan_id]["reports"] = reports
        scans[scan_id]["status"]  = "complete"

        # Persist everything to DB
        if DB_ENABLED:
            try:
                save_results(scan_id, scan_result, reports, status="complete")
            except Exception as _db_e:
                log.warning("DB save_results failed: %s", _db_e)

        pq.put({
            "type":    "complete",
            "message": "Scan complete",
            "summary": {
                "urls":   len(scan_result.urls_crawled),
                "vulns":  len(scan_result.vulnerabilities),
                "ports":  len(scan_result.open_ports),
                "errors": len(scan_result.errors),
            },
            "time": datetime.now().isoformat(),
        })

    except Exception as e:
        log.error(f"Scan {scan_id} failed: {e}")
        scans[scan_id]["status"] = "error"
        scans[scan_id]["error"]  = str(e)

        # Persist error state
        if DB_ENABLED:
            try:
                save_results(
                    scan_id,
                    scans[scan_id].get("result"),
                    scans[scan_id].get("reports", {}),
                    status="error",
                    error_message=str(e),
                )
            except Exception as _db_e:
                log.warning("DB save error-state failed: %s", _db_e)

        pq.put({
            "type":    "error",
            "message": f"Scan failed: {e}",
            "time":    datetime.now().isoformat(),
        })


# ── Helpers ───────────────────────────────────────────────────────────────────

def _deduplicate(findings: list) -> list:
    seen   = set()
    unique = []
    for v in findings:
        # Normalize vuln_type — treat all XSS variants as same type
        base_type = v.vuln_type.replace(" (Form - Mutated)", "").replace(" (Form Input)", "").replace(" (URL Parameter)", "").replace(" (HTTP Header)", "")
        # Use only first field name if parameter contains multiple
        first_param = v.parameter.split(",")[0].strip()
        key = (v.url, base_type, first_param)
        if key not in seen:
            seen.add(key)
            unique.append(v)
    return unique


def _serialize_result(result: ScanResult, scan: dict) -> dict:
    return {
        "scan_id":    scan["id"],
        "status":     scan["status"],
        "target":     result.target,
        "start_time": result.start_time,
        "end_time":   result.end_time,
        "summary": {
            "urls_crawled":    len(result.urls_crawled),
            "vulnerabilities": len(result.vulnerabilities),
            "open_ports":      len(result.open_ports),
            "errors":          len(result.errors),
        },
        "vulnerabilities": [
            {
                "type":        v.vuln_type,
                "url":         v.url,
                "parameter":   v.parameter,
                "payload":     v.payload,
                "severity":    v.severity.value,
                "evidence":    v.evidence,
                "description": v.description,
                "remediation": v.remediation,
            }
            for v in result.vulnerabilities
        ],
        "open_ports": [
            {"port": p.port, "state": p.state, "service": p.service}
            for p in result.open_ports
        ],
        "urls_crawled": result.urls_crawled,
        "reports": {
            k: os.path.basename(v)
            for k, v in scan.get("reports", {}).items()
        },
    }


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print("""
╔══════════════════════════════════════════════════════╗
║     WASP Dashboard — http://localhost:5000            ║
║     Press Ctrl+C to stop                             ║
╚══════════════════════════════════════════════════════╝
    """)
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)