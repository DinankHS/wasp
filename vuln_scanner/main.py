# main.py
"""
WASP — Web Application Security Probe v2.0
Complete Phase 2 platform with all modules wired together.

Usage:
    # CLI mode
    python main.py --target http://localhost --auto-login --app dvwa
    python main.py --target "http://localhost:8080/sqli_1.php?title=%25&action=search" --auto-login --app bwapp --skip-ports
    python main.py --target http://testphp.vulnweb.com --depth 2 --skip-ports

    # Dashboard mode
    python main.py --dashboard
    # Then open http://localhost:5000
"""

import argparse
import sys
import os
import logging
import socket

from config import OUTPUT_DIR, TOP_PORTS
from core.logger import get_logger
from core.models import ScanResult
from core.utils import normalize_url, is_valid_url
from scanner.crawler      import Crawler
from scanner.sqli         import SQLiScanner
from scanner.xss          import XSSScanner
from scanner.port_scanner import PortScanner
from scanner.forms        import FormCrawler
from scanner.mutator      import PayloadMutator
from scanner.auth_tester  import AuthTester
from scanner.plugins      import load_plugins

log = get_logger("main")


# ── Argument parser ───────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="WASP v2.0 — Web Application Security Probe",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python main.py --target http://localhost --auto-login
    python main.py --target "http://localhost:8080/sqli_1.php?title=%25&action=search" --auto-login --app bwapp --skip-ports
    python main.py --target http://testphp.vulnweb.com --depth 2 --skip-ports
    python main.py --dashboard
        """
    )
    parser.add_argument("--target",      type=str, default=None, help="Target URL to scan")
    parser.add_argument("--output",      choices=["json","txt","pdf","all"], default="all", help="Report format (default: all)")
    parser.add_argument("--skip-ports",  action="store_true", help="Skip port scanning")
    parser.add_argument("--skip-auth",   action="store_true", help="Skip auth testing")
    parser.add_argument("--skip-plugins",action="store_true", help="Skip plugin modules")
    parser.add_argument("--depth",       type=int, default=2,  help="Crawler depth (default: 2)")
    parser.add_argument("--cookie",      type=str, default=None, help="Cookie string e.g. NAME=VALUE,NAME2=VALUE2")
    parser.add_argument("--cookie-file", type=str, default=None, help="Path to cookie file (one NAME=VALUE per line)")
    parser.add_argument("--auto-login",  action="store_true", help="Auto-login to DVWA or bWAPP")
    parser.add_argument("--app",         choices=["dvwa","bwapp"], default="dvwa", help="App type for auto-login")
    parser.add_argument("--use-ai",      action="store_true", help="Enable AI analysis (needs ANTHROPIC_API_KEY in .env)")
    parser.add_argument("--dashboard",   action="store_true", help="Launch web dashboard instead of CLI scan")
    parser.add_argument("--port",        type=int, default=5000, help="Dashboard port (default: 5000)")
    parser.add_argument("--verbose",     action="store_true", help="Enable DEBUG logging")
    return parser.parse_args()


# ── Helpers ───────────────────────────────────────────────────────────────────

def parse_cookie_string(cookie_str: str) -> dict:
    cookies   = {}
    separator = ";" if ";" in cookie_str else ","
    for part in cookie_str.split(separator):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies


def load_cookie_file(path: str) -> dict:
    cookies = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                cookies[k.strip()] = v.strip()
    return cookies


def deduplicate(findings: list) -> list:
    seen, unique = set(), []
    for v in findings:
        key = (v.url, v.parameter, v.vuln_type)
        if key not in seen:
            seen.add(key)
            unique.append(v)
    return unique


def banner() -> None:
    print("""
╔══════════════════════════════════════════════════════════════╗
║        WASP — Web Application Security Probe  v2.0          ║
║        For authorized testing only. Use responsibly.         ║
╚══════════════════════════════════════════════════════════════╝
    """)


def print_divider(char="─", width=60) -> None:
    print("  " + char * width)


def print_stage(num: int, total: int, name: str) -> None:
    print(f"\n[{num}/{total}] {name}")


# ── Stage runners ─────────────────────────────────────────────────────────────

def run_crawler(
    target: str,
    depth: int,
    scan_result: ScanResult,
    cookies: dict | None = None,
    session=None,
) -> list[str]:
    print_stage(1, 8, "CRAWLER")
    print(f"      Target  : {target}")
    print(f"      Depth   : {depth}")
    if cookies:
        print(f"      Cookies : {list(cookies.keys())}")
    print("      Status  : Running...\n")

    crawler = Crawler(
        seed_url=target, max_depth=depth,
        cookies=cookies, session=session,
    )
    urls = crawler.crawl()
    scan_result.urls_crawled = urls

    if urls:
        print(f"\n      Found {len(urls)} URL(s):")
        for url in urls:
            print(f"        [+] {url}")
    else:
        print("      No URLs found. Check if the target is reachable.")

    if crawler.errors:
        print(f"\n      Warnings ({len(crawler.errors)}):")
        for err in crawler.errors[:5]:
            print(f"        [!] {err}")
        scan_result.errors.extend(crawler.errors)

    return urls


def run_form_crawler(
    urls: list[str],
    session=None,
    cookies: dict | None = None,
) -> list[dict]:
    print_stage(2, 8, "FORM CRAWLER")
    print(f"      Targets : {len(urls)} URL(s)")
    print("      Status  : Running...\n")

    fc    = FormCrawler(session=session, cookies=cookies)
    forms = fc.extract_forms(urls)

    if forms:
        print(f"      Found {len(forms)} form(s):")
        for form in forms:
            print(
                f"        [+] [{form['method'].upper()}] {form['action']}"
                f"  fields={form['injectable_fields']}"
            )
    else:
        print("      No injectable forms found.")

    return forms


def run_sqli(
    urls: list[str],
    forms: list[dict],
    scan_result: ScanResult,
    cookies: dict | None = None,
    session=None,
) -> None:
    print_stage(3, 8, "SQL INJECTION SCANNER")

    injectable = [u for u in urls if "?" in u]
    if not injectable and not forms:
        print("      No injectable targets found. Skipping.")
        return

    print(f"      URL targets  : {len(injectable)}")
    print(f"      Form targets : {len(forms)}")
    print("      Status       : Running...\n")

    scanner  = SQLiScanner(cookies=cookies, session=session)
    findings = deduplicate(scanner.scan(urls))

    # Form-based SQLi with mutation
    if forms and hasattr(scanner, "scan_forms"):
        form_findings = deduplicate(scanner.scan_forms(forms))
        findings += [f for f in form_findings if f not in findings]

    for vuln in findings:
        scan_result.add_vuln(vuln)
        print(f"      [VULN] {vuln.vuln_type}")
        print(f"             URL       : {vuln.url}")
        print(f"             Parameter : {vuln.parameter}")
        print(f"             Payload   : {vuln.payload}")
        print(f"             Severity  : {vuln.severity.value}")
        print(f"             Evidence  : {vuln.evidence}")
        print()

    if not findings:
        print("      No SQL injection vulnerabilities found.")


def run_xss(
    urls: list[str],
    forms: list[dict],
    scan_result: ScanResult,
    cookies: dict | None = None,
    session=None,
) -> None:
    print_stage(4, 8, "XSS SCANNER")
    print(f"      URL targets  : {len(urls)}")
    print(f"      Form targets : {len(forms)}")
    print("      Status       : Running...\n")

    scanner  = XSSScanner(cookies=cookies, session=session)
    findings = deduplicate(scanner.scan(urls))

    # Form-based XSS with mutation
    if forms and hasattr(scanner, "scan_forms_with_mutation"):
        form_findings = deduplicate(scanner.scan_forms_with_mutation(forms))
        findings += [f for f in form_findings if f not in findings]

    for vuln in findings:
        scan_result.add_vuln(vuln)
        print(f"      [VULN] {vuln.vuln_type}")
        print(f"             URL       : {vuln.url}")
        print(f"             Parameter : {vuln.parameter}")
        print(f"             Payload   : {vuln.payload}")
        print(f"             Severity  : {vuln.severity.value}")
        print(f"             Evidence  : {vuln.evidence}")
        print()

    if not findings:
        print("      No XSS vulnerabilities found.")


def run_auth_tester(
    urls: list[str],
    forms: list[dict],
    scan_result: ScanResult,
    session=None,
    cookies: dict | None = None,
) -> None:
    print_stage(5, 8, "AUTHENTICATION TESTER")
    print(f"      Targets : {len(urls)} URL(s), {len(forms)} form(s)")
    print("      Status  : Running...\n")

    tester   = AuthTester(session=session, cookies=cookies)
    findings = deduplicate(tester.scan(urls, forms))

    for vuln in findings:
        scan_result.add_vuln(vuln)
        print(f"      [VULN] {vuln.vuln_type}")
        print(f"             URL       : {vuln.url}")
        print(f"             Payload   : {vuln.payload}")
        print(f"             Severity  : {vuln.severity.value}")
        print(f"             Evidence  : {vuln.evidence}")
        print()

    if not findings:
        print("      No authentication vulnerabilities found.")


def run_plugins(
    urls: list[str],
    forms: list[dict],
    scan_result: ScanResult,
    session=None,
) -> None:
    print_stage(6, 8, "PLUGIN SCANNER")

    plugins = load_plugins()
    if not plugins:
        print("      No plugins found in scanner/plugins/")
        return

    print(f"      Loaded {len(plugins)} plugin(s):")
    for p in plugins:
        print(f"        [+] {p.name} v{p.version} — {p.description}")
    print()

    for plugin in plugins:
        plugin.session = session
        plugin.cookies = session.cookies if session else {}
        plugin.setup()
        try:
            findings = deduplicate(plugin.scan(urls, forms))
            for vuln in findings:
                scan_result.add_vuln(vuln)
                print(f"      [{plugin.name}] {vuln.vuln_type}")
                print(f"             URL      : {vuln.url}")
                print(f"             Severity : {vuln.severity.value}")
                print(f"             Evidence : {vuln.evidence}")
                print()
        except Exception as e:
            log.warning(f"Plugin '{plugin.name}' error: {e}")
        finally:
            plugin.teardown()

    if not any(True for _ in scan_result.vulnerabilities):
        print("      No plugin findings.")


def run_port_scanner(
    target: str,
    scan_result: ScanResult,
) -> None:
    print_stage(7, 8, "PORT SCANNER")
    try:
        host = socket.gethostbyname(
            target.replace("http://", "").replace("https://", "")
            .split("/")[0].split(":")[0]
        )
    except socket.gaierror:
        host = "localhost"

    print(f"      Host    : {host}")
    print(f"      Ports   : {len(TOP_PORTS)} top ports")
    print("      Status  : Running...\n")

    scanner = PortScanner(host=host)
    ports   = scanner.scan()

    for p in ports:
        scan_result.add_port(p)
        print(f"      [OPEN] {p.port:<6} {p.service}")

    if not ports:
        print("      No open ports found.")


def run_ai_and_reports(
    scan_result: ScanResult,
    output: str,
    use_ai: bool,
) -> None:
    print_stage(8, 8, "AI ANALYSIS + REPORTS")

    ai_analyses       = {}
    executive_summary = ""

    # AI enrichment
    if use_ai:
        print("      AI Analysis  : Running...\n")
        try:
            from ai.advisor import AIAdvisor
            advisor = AIAdvisor()
            if advisor.enabled:
                for i, vuln in enumerate(scan_result.vulnerabilities):
                    print(f"        Analyzing {i+1}/{len(scan_result.vulnerabilities)}: {vuln.vuln_type}")
                    analysis       = advisor.analyze_vulnerability(vuln)
                    ai_analyses[i] = analysis
                    vuln.remediation = analysis.get("remediation", "")
                executive_summary = advisor.generate_executive_summary(scan_result)
                print("      AI Analysis  : Complete\n")
            else:
                print("      AI Analysis  : Skipped (no API key in .env)\n")
        except Exception as e:
            log.warning(f"AI analysis error: {e}")
            print(f"      AI Analysis  : Failed — {e}\n")
    else:
        print("      AI Analysis  : Skipped (use --use-ai to enable)\n")

    # Reports
    print("      Generating reports...\n")
    from reporter import json_reporter, txt_reporter

    if output in ("json", "all"):
        try:
            path = json_reporter.generate(scan_result)
            print(f"      JSON : {path}")
        except Exception as e:
            log.warning(f"JSON report error: {e}")

    if output in ("txt", "all"):
        try:
            path = txt_reporter.generate(scan_result)
            print(f"      TXT  : {path}")
        except Exception as e:
            log.warning(f"TXT report error: {e}")

    if output in ("pdf", "all"):
        try:
            from reporter import pdf_reporter
            path = pdf_reporter.generate(
                scan_result, ai_analyses, executive_summary
            )
            print(f"      PDF  : {path}")
        except Exception as e:
            log.warning(f"PDF report error: {e}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    banner()
    args = parse_args()

    # ── Dashboard mode ────────────────────────────────────────────────────────
    if args.dashboard:
        print(f"  Launching dashboard on http://localhost:{args.port}")
        print("  Press Ctrl+C to stop.\n")
        os.chdir(os.path.dirname(os.path.abspath(__file__)))
        from dashboard.app import app
        app.run(host="0.0.0.0", port=args.port, debug=False, threaded=True)
        return

    # ── CLI mode ──────────────────────────────────────────────────────────────
    if not args.target:
        print("  Error: --target is required in CLI mode.")
        print("  Use --dashboard to launch the web UI instead.")
        sys.exit(1)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    target = normalize_url(args.target)
    if not is_valid_url(target):
        log.error(f"Invalid target URL: {target}")
        sys.exit(1)

    # ── Cookie / session loading ──────────────────────────────────────────────
    cookies      = None
    auth_session = None

    if args.auto_login:
        from urllib.parse import urlparse as _up
        base = f"{_up(target).scheme}://{_up(target).netloc}"

        if args.app == "bwapp":
            from core.utils import bwapp_get_session
            log.info(f"Auto-logging into bWAPP at {base}...")
            auth_session = bwapp_get_session(base)
            if auth_session is None:
                log.error("bWAPP login failed. Is the container running?")
                log.error("  docker run --rm -d -p 8080:80 --name bwapp raesene/bwapp")
                sys.exit(1)
            cookies = {c.name: c.value for c in auth_session.cookies}
            cookies["security_level"] = "0"
        else:
            from core.utils import dvwa_login
            log.info(f"Auto-logging into DVWA at {base}...")
            cookies = dvwa_login(base)
            if not cookies:
                log.error("DVWA login failed. Is the container running?")
                log.error("  docker run --rm -d -p 80:80 --name dvwa vulnerables/web-dvwa")
                sys.exit(1)

        log.info(f"Auto-login successful: {list(cookies.keys())}")

    elif args.cookie_file:
        if os.path.exists(args.cookie_file):
            cookies = load_cookie_file(args.cookie_file)
            log.info(f"Cookies loaded from file: {list(cookies.keys())}")
        else:
            log.error(f"Cookie file not found: {args.cookie_file}")
            sys.exit(1)

    elif args.cookie:
        cookies = parse_cookie_string(args.cookie)
        log.info(f"Cookies loaded: {list(cookies.keys())}")

    # ── Print config ──────────────────────────────────────────────────────────
    print_divider()
    print(f"  Target   : {target}")
    print(f"  Depth    : {args.depth}")
    print(f"  Output   : {args.output}")
    print(f"  Cookies  : {list(cookies.keys()) if cookies else 'none'}")
    print(f"  AI       : {'enabled' if args.use_ai else 'disabled'}")
    print(f"  Ports    : {'skipped' if args.skip_ports else 'enabled'}")
    print(f"  Auth     : {'skipped' if args.skip_auth else 'enabled'}")
    print(f"  Plugins  : {'skipped' if args.skip_plugins else 'enabled'}")
    print_divider()

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    scan_result = ScanResult(target=target)

    # ── Pipeline ──────────────────────────────────────────────────────────────
    # Stage 1 — Crawler
    urls = run_crawler(
        target, args.depth, scan_result,
        cookies=cookies, session=auth_session,
    )

    # Stage 2 — Form crawler
    forms = run_form_crawler(
        urls, session=auth_session, cookies=cookies
    )

    # Stage 3 — SQLi scanner
    run_sqli(urls, forms, scan_result, cookies=cookies, session=auth_session)

    # Stage 4 — XSS scanner
    run_xss(urls, forms, scan_result, cookies=cookies, session=auth_session)

    # Stage 5 — Auth tester
    if not args.skip_auth:
        run_auth_tester(urls, forms, scan_result,
                        session=auth_session, cookies=cookies)
    else:
        print_stage(5, 8, "AUTH TESTER — Skipped")

    # Stage 6 — Plugin scanner
    if not args.skip_plugins:
        run_plugins(urls, forms, scan_result, session=auth_session)
    else:
        print_stage(6, 8, "PLUGIN SCANNER — Skipped")

    # Stage 7 — Port scanner
    if not args.skip_ports:
        run_port_scanner(target, scan_result)
    else:
        print_stage(7, 8, "PORT SCANNER — Skipped")

    # Stage 8 — AI + Reports
    scan_result.finalize()
    run_ai_and_reports(scan_result, args.output, args.use_ai)

    # ── Final summary ─────────────────────────────────────────────────────────
    print("\n")
    print_divider("═")
    print("  SCAN SUMMARY")
    print_divider("═")
    print(f"  Target          : {scan_result.target}")
    print(f"  URLs crawled    : {len(scan_result.urls_crawled)}")
    print(f"  Forms found     : {len(forms)}")
    print(f"  Vulnerabilities : {len(scan_result.vulnerabilities)}")
    print(f"  Open ports      : {len(scan_result.open_ports)}")
    print(f"  Errors          : {len(scan_result.errors)}")
    print(f"  Started         : {scan_result.start_time}")
    print(f"  Finished        : {scan_result.end_time}")
    print_divider("═")

    if scan_result.vulnerabilities:
        print("\n  FINDINGS:")
        for i, vuln in enumerate(scan_result.vulnerabilities, 1):
            print(f"  {i:>2}. [{vuln.severity.value:<8}] {vuln.vuln_type}")
            print(f"       URL       : {vuln.url}")
            print(f"       Parameter : {vuln.parameter}")
            if vuln.remediation:
                print(f"       Fix       : {vuln.remediation[:100]}...")

    if scan_result.open_ports:
        print("\n  OPEN PORTS:")
        for p in scan_result.open_ports:
            print(f"  {p.port:<6} {p.state:<10} {p.service}")

    print()


if __name__ == "__main__":
    main()