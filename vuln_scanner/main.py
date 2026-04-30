# main.py
"""
WASP — Web Application Security Probe v1.0
Usage:
    python main.py --target http://localhost --auto-login
    python main.py --target "http://localhost:8080/sqli_1.php?title=%25&action=search" --auto-login --app bwapp --skip-ports
    python main.py --target http://testphp.vulnweb.com --depth 2 --skip-ports
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
from scanner.crawler import Crawler
from scanner.sqli import SQLiScanner
from scanner.xss import XSSScanner
from scanner.port_scanner import PortScanner

log = get_logger("main")


# ── Argument parser ───────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="WASP — Web Application Security Probe (Educational Use Only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python main.py --target http://localhost --auto-login
    python main.py --target "http://localhost:8080/sqli_1.php?title=%25&action=search" --auto-login --app bwapp --skip-ports
    python main.py --target http://testphp.vulnweb.com --depth 2 --skip-ports
        """
    )
    parser.add_argument(
        "--target", required=True,
        help="Target URL to scan"
    )
    parser.add_argument(
        "--output", choices=["json", "txt", "both"], default="both",
        help="Report format (default: both)"
    )
    parser.add_argument(
        "--skip-ports", action="store_true",
        help="Skip port scanning"
    )
    parser.add_argument(
        "--depth", type=int, default=3,
        help="Crawler depth limit (default: 3)"
    )
    parser.add_argument(
        "--cookie", type=str, default=None,
        help="Cookie string e.g. NAME=VALUE,NAME2=VALUE2"
    )
    parser.add_argument(
        "--cookie-file", type=str, default=None,
        help="Path to cookie file (one NAME=VALUE per line)"
    )
    parser.add_argument(
        "--auto-login", action="store_true",
        help="Auto-login to DVWA or bWAPP"
    )
    parser.add_argument(
        "--app", choices=["dvwa", "bwapp"], default="dvwa",
        help="Target app type for auto-login (default: dvwa)"
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Enable DEBUG-level logging"
    )
    return parser.parse_args()


# ── Helpers ───────────────────────────────────────────────────────────────────

def parse_cookie_string(cookie_str: str) -> dict:
    cookies   = {}
    separator = ";" if ";" in cookie_str else ","
    for part in cookie_str.split(separator):
        part = part.strip()
        if "=" in part:
            key, value = part.split("=", 1)
            cookies[key.strip()] = value.strip()
    return cookies


def load_cookie_file(path: str) -> dict:
    cookies = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                key, value = line.split("=", 1)
                cookies[key.strip()] = value.strip()
    return cookies


def deduplicate_vulns(findings):
    """Remove duplicate findings by (url, parameter, vuln_type)."""
    seen   = set()
    unique = []
    for vuln in findings:
        key = (vuln.url, vuln.parameter, vuln.vuln_type)
        if key not in seen:
            seen.add(key)
            unique.append(vuln)
    return unique


def banner() -> None:
    print("""
╔══════════════════════════════════════════════════════╗
║     WASP — Web Application Security Probe v1.0       ║
║   For authorized testing only. Use responsibly.      ║
╚══════════════════════════════════════════════════════╝
    """)


def print_divider() -> None:
    print("  " + "─" * 52)


# ── Stage runners ─────────────────────────────────────────────────────────────

def run_crawler(
    target: str,
    depth: int,
    scan_result: ScanResult,
    cookies: dict | None = None,
    session=None,
) -> list[str]:
    print("\n[1/4] CRAWLER")
    print(f"      Target  : {target}")
    print(f"      Depth   : {depth}")
    if cookies:
        print(f"      Cookies : {list(cookies.keys())}")
    print("      Status  : Running...\n")

    crawler = Crawler(seed_url=target, max_depth=depth, cookies=cookies, session=session)
    urls    = crawler.crawl()
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


def run_sqli(
    urls: list[str],
    scan_result: ScanResult,
    cookies: dict | None = None,
    session=None,
) -> None:
    print("\n[2/4] SQL INJECTION SCANNER")
    injectable = [u for u in urls if "?" in u]

    if not injectable:
        print("      No URLs with parameters found. Skipping.")
        return

    print(f"      Targets : {len(injectable)} URL(s) with parameters")
    print("      Status  : Running...\n")

    scanner  = SQLiScanner(cookies=cookies, session=session)
    findings = deduplicate_vulns(scanner.scan(urls))

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
    scan_result: ScanResult,
    cookies: dict | None = None,
    session=None,
) -> None:
    print("\n[3/4] XSS SCANNER")
    print(f"      Targets : {len(urls)} URL(s)")
    print("      Status  : Running...\n")

    scanner  = XSSScanner(cookies=cookies, session=session)
    findings = deduplicate_vulns(scanner.scan(urls))

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


def run_port_scanner(target: str, scan_result: ScanResult) -> None:
    print("\n[4/4] PORT SCANNER")
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


def run_reporter(scan_result: ScanResult, output: str) -> None:
    print("\n[REPORTER]")
    from reporter import json_reporter, txt_reporter

    if output in ("json", "both"):
        path = json_reporter.generate(scan_result)
        print(f"      JSON report : {path}")

    if output in ("txt", "both"):
        path = txt_reporter.generate(scan_result)
        print(f"      TXT  report : {path}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    banner()
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    target = normalize_url(args.target)
    if not is_valid_url(target):
        log.error(f"Invalid target URL: {target}")
        sys.exit(1)

    # ── Session & Cookie loading ──────────────────────────────────────────────
    cookies      = None
    auth_session = None

    if args.auto_login:
        from urllib.parse import urlparse as _urlparse
        parsed = _urlparse(target)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        if args.app == "bwapp":
            from core.utils import bwapp_get_session
            log.info(f"Auto-logging into bWAPP at {base}...")
            auth_session = bwapp_get_session(base)
            if auth_session is None:
                log.error("bWAPP login failed. Is the container running?")
                log.error("Start it with: docker run --rm -d -p 8080:80 --name bwapp raesene/bwapp")
                sys.exit(1)
            cookies = {c.name: c.value for c in auth_session.cookies}
            cookies["security_level"] = "0"
            log.info(f"Auto-login successful: {list(cookies.keys())}")

        else:
            from core.utils import dvwa_login
            log.info(f"Auto-logging into DVWA at {base}...")
            cookies = dvwa_login(base)
            if not cookies:
                log.error("DVWA login failed. Is the container running?")
                log.error("Start it with: docker run --rm -d -p 80:80 --name dvwa vulnerables/web-dvwa")
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
    print(f"  Target  : {target}")
    print(f"  Output  : {args.output}")
    print(f"  Depth   : {args.depth}")
    print(f"  Ports   : {'skipped' if args.skip_ports else 'enabled'}")
    print(f"  Cookies : {list(cookies.keys()) if cookies else 'none'}")
    print_divider()

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    scan_result = ScanResult(target=target)

    # ── Pipeline ──────────────────────────────────────────────────────────────
    urls = run_crawler(
        target, args.depth, scan_result,
        cookies=cookies, session=auth_session
    )
    run_sqli(urls, scan_result, cookies=cookies, session=auth_session)
    run_xss(urls, scan_result, cookies=cookies, session=auth_session)

    if not args.skip_ports:
        run_port_scanner(target, scan_result)

    # ── Reports ───────────────────────────────────────────────────────────────
    scan_result.finalize()
    run_reporter(scan_result, args.output)

    # ── Summary ───────────────────────────────────────────────────────────────
    print("\n")
    print_divider()
    print("  SCAN SUMMARY")
    print_divider()
    print(f"  Target          : {scan_result.target}")
    print(f"  URLs crawled    : {len(scan_result.urls_crawled)}")
    print(f"  Vulnerabilities : {len(scan_result.vulnerabilities)}")
    print(f"  Open ports      : {len(scan_result.open_ports)}")
    print(f"  Errors          : {len(scan_result.errors)}")
    print(f"  Started         : {scan_result.start_time}")
    print(f"  Finished        : {scan_result.end_time}")
    print_divider()

    if scan_result.vulnerabilities:
        print("\n  FINDINGS:")
        for i, vuln in enumerate(scan_result.vulnerabilities, 1):
            print(f"  {i:>2}. [{vuln.severity.value}] {vuln.vuln_type}")
            print(f"       URL       : {vuln.url}")
            print(f"       Parameter : {vuln.parameter}")

    if scan_result.open_ports:
        print("\n  OPEN PORTS:")
        for p in scan_result.open_ports:
            print(f"  {p.port:<6} {p.state:<10} {p.service}")


if __name__ == "__main__":
    main()