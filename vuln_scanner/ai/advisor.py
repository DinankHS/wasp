# ai/advisor.py
"""
WASP AI Advisor — Phase 2
Uses Claude API to analyze vulnerability findings and generate:
  1. Plain-English explanation of each vulnerability
  2. Severity assessment with CVSS-like scoring rationale
  3. Step-by-step remediation advice
  4. Code examples showing the fix
  5. Executive summary for the full scan

Requires ANTHROPIC_API_KEY in .env file.
"""

import os
import json
import time
from dotenv import load_dotenv

from core.logger import get_logger
from core.models import Vulnerability, ScanResult

load_dotenv()
log = get_logger(__name__)


class AIAdvisor:
    """
    Wraps the Claude API to provide intelligent vulnerability analysis.
    Falls back gracefully if API key is missing or quota exceeded.
    """

    MODEL    = "claude-haiku-4-5-20251001"   # fastest + cheapest model
    MAX_TOKENS = 1024
    RETRY_DELAY = 2   # seconds between retries on rate limit

    def __init__(self):
        self.api_key = os.getenv("ANTHROPIC_API_KEY", "")
        self.enabled = bool(self.api_key)

        if not self.enabled:
            log.warning(
                "ANTHROPIC_API_KEY not set. "
                "AI analysis disabled. Add key to .env file."
            )
        else:
            log.info("AI Advisor initialized. Claude API ready.")

    # ── Public API ────────────────────────────────────────────────────────────

    def analyze_vulnerability(self, vuln: Vulnerability) -> dict:
        """
        Analyze a single vulnerability and return enriched data.

        Returns a dict with:
            explanation   — plain-English description
            impact        — what an attacker can do
            remediation   — how to fix it
            code_example  — code showing the fix
            cvss_score    — estimated CVSS score (0-10)
            references    — relevant links
        """
        if not self.enabled:
            return self._fallback_analysis(vuln)

        prompt = self._build_vuln_prompt(vuln)
        response = self._call_api(prompt)

        if response is None:
            return self._fallback_analysis(vuln)

        return self._parse_vuln_response(response, vuln)

    def generate_executive_summary(self, scan_result: ScanResult) -> str:
        """
        Generate an executive summary of the full scan.
        Suitable for including in a professional PDF report.
        """
        if not self.enabled:
            return self._fallback_summary(scan_result)

        prompt = self._build_summary_prompt(scan_result)
        response = self._call_api(prompt, max_tokens=1500)

        if response is None:
            return self._fallback_summary(scan_result)

        return response.strip()

    def enrich_findings(self, scan_result: ScanResult) -> ScanResult:
        """
        Enrich all vulnerabilities in a ScanResult with AI analysis.
        Updates each vulnerability's remediation field in-place.
        Returns the enriched ScanResult.
        """
        if not self.enabled:
            log.warning("AI enrichment skipped — no API key.")
            return scan_result

        total = len(scan_result.vulnerabilities)
        log.info(f"AI enrichment started for {total} finding(s).")

        for i, vuln in enumerate(scan_result.vulnerabilities, 1):
            log.info(f"  Analyzing finding {i}/{total}: {vuln.vuln_type}")
            analysis = self.analyze_vulnerability(vuln)
            vuln.remediation = analysis.get("remediation", "")
            # Small delay to avoid rate limiting
            if i < total:
                time.sleep(0.5)

        log.info("AI enrichment complete.")
        return scan_result

    # ── Prompt builders ───────────────────────────────────────────────────────

    def _build_vuln_prompt(self, vuln: Vulnerability) -> str:
        return f"""You are a senior cybersecurity engineer writing a professional
vulnerability report. Analyze this finding and respond ONLY with valid JSON.

FINDING:
- Type: {vuln.vuln_type}
- URL: {vuln.url}
- Parameter: {vuln.parameter}
- Payload used: {vuln.payload}
- Evidence: {vuln.evidence}
- Severity: {vuln.severity.value}

Respond with this exact JSON structure (no markdown, no extra text):
{{
  "explanation": "2-3 sentence plain English explanation of what this vulnerability is and why it exists",
  "impact": "What an attacker can do if they exploit this (be specific)",
  "remediation": "Step-by-step instructions to fix this vulnerability",
  "code_example": "A short code snippet showing the secure implementation",
  "cvss_score": <number between 0.0 and 10.0>,
  "references": ["URL1", "URL2"]
}}"""

    def _build_summary_prompt(self, scan_result: ScanResult) -> str:
        vuln_summary = ""
        severity_counts = {}

        for vuln in scan_result.vulnerabilities:
            sev = vuln.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        for sev, count in severity_counts.items():
            vuln_summary += f"  - {sev}: {count} finding(s)\n"

        vuln_types = list({v.vuln_type for v in scan_result.vulnerabilities})

        return f"""You are a senior cybersecurity engineer writing an executive
summary for a professional penetration testing report.

SCAN DETAILS:
- Target: {scan_result.target}
- URLs crawled: {len(scan_result.urls_crawled)}
- Total vulnerabilities: {len(scan_result.vulnerabilities)}
- Severity breakdown:
{vuln_summary}
- Vulnerability types found: {', '.join(vuln_types) if vuln_types else 'None'}
- Scan duration: {scan_result.start_time} to {scan_result.end_time}

Write a professional 3-paragraph executive summary suitable for a
C-level audience. Cover: (1) overall risk posture, (2) key findings,
(3) recommended immediate actions. Be concise and direct."""

    # ── API communication ─────────────────────────────────────────────────────

    def _call_api(
        self,
        prompt: str,
        max_tokens: int = MAX_TOKENS,
        retries: int = 2,
    ) -> str | None:
        """
        Call the Claude API with retry logic.
        Returns response text or None on failure.
        """
        import urllib.request
        import urllib.error

        headers = {
            "Content-Type":      "application/json",
            "X-API-Key":         self.api_key,
            "anthropic-version": "2023-06-01",
        }

        body = json.dumps({
            "model":      self.MODEL,
            "max_tokens": max_tokens,
            "messages":   [{"role": "user", "content": prompt}],
        }).encode("utf-8")

        for attempt in range(retries + 1):
            try:
                req = urllib.request.Request(
                    "https://api.anthropic.com/v1/messages",
                    data=body,
                    headers=headers,
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    return data["content"][0]["text"]

            except urllib.error.HTTPError as e:
                if e.code == 429:
                    log.warning(f"Rate limited. Waiting {self.RETRY_DELAY}s...")
                    time.sleep(self.RETRY_DELAY)
                elif e.code == 401:
                    log.error("Invalid API key. Check your .env file.")
                    self.enabled = False
                    return None
                elif e.code == 529:
                    log.warning("API overloaded. Waiting...")
                    time.sleep(self.RETRY_DELAY * 2)
                else:
                    log.error(f"API HTTP error {e.code}: {e.reason}")
                    return None

            except Exception as e:
                log.error(f"API call failed: {e}")
                if attempt < retries:
                    time.sleep(self.RETRY_DELAY)
                else:
                    return None

        return None

    # ── Response parsing ──────────────────────────────────────────────────────

    def _parse_vuln_response(
        self,
        response: str,
        vuln: Vulnerability,
    ) -> dict:
        """
        Parse JSON response from Claude.
        Falls back to raw response if JSON parsing fails.
        """
        try:
            # Strip any accidental markdown fences
            clean = response.strip()
            if clean.startswith("```"):
                clean = clean.split("```")[1]
                if clean.startswith("json"):
                    clean = clean[4:]
            return json.loads(clean.strip())
        except json.JSONDecodeError:
            log.warning("AI response was not valid JSON. Using raw text.")
            return {
                "explanation":  response[:500],
                "impact":       "See explanation above.",
                "remediation":  response[:500],
                "code_example": "",
                "cvss_score":   self._estimate_cvss(vuln),
                "references":   [],
            }

    # ── Fallback (no API key) ─────────────────────────────────────────────────

    def _fallback_analysis(self, vuln: Vulnerability) -> dict:
        """
        Return a pre-written analysis when the API is unavailable.
        Covers the most common vulnerability types with good advice.
        """
        templates = {
            "SQL Injection": {
                "explanation": (
                    "SQL Injection occurs when user-supplied input is "
                    "incorporated into a database query without proper "
                    "sanitization, allowing attackers to manipulate the query."
                ),
                "impact": (
                    "An attacker can read, modify, or delete any data in the "
                    "database, bypass authentication, and in some cases "
                    "execute operating system commands."
                ),
                "remediation": (
                    "1. Use parameterized queries or prepared statements.\n"
                    "2. Apply input validation and whitelist allowed characters.\n"
                    "3. Use an ORM with built-in protection.\n"
                    "4. Apply the principle of least privilege to DB accounts.\n"
                    "5. Enable a WAF to filter malicious input."
                ),
                "code_example": (
                    "# VULNERABLE:\n"
                    "query = f\"SELECT * FROM users WHERE id = {user_id}\"\n\n"
                    "# SECURE:\n"
                    "query = \"SELECT * FROM users WHERE id = %s\"\n"
                    "cursor.execute(query, (user_id,))"
                ),
                "cvss_score": 9.8,
                "references": [
                    "https://owasp.org/www-community/attacks/SQL_Injection",
                    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                ],
            },
            "Reflected XSS": {
                "explanation": (
                    "Reflected Cross-Site Scripting occurs when user input "
                    "is immediately included in the page response without "
                    "proper encoding, allowing script injection."
                ),
                "impact": (
                    "An attacker can steal session cookies, perform actions "
                    "on behalf of the victim, redirect to malicious sites, "
                    "or capture keystrokes."
                ),
                "remediation": (
                    "1. Encode all user-supplied output using context-aware encoding.\n"
                    "2. Implement Content Security Policy (CSP) headers.\n"
                    "3. Use HTTPOnly and Secure flags on session cookies.\n"
                    "4. Validate and sanitize all input server-side.\n"
                    "5. Use a template engine that auto-escapes by default."
                ),
                "code_example": (
                    "# VULNERABLE (PHP):\n"
                    "echo $_GET['name'];\n\n"
                    "# SECURE (PHP):\n"
                    "echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');"
                ),
                "cvss_score": 7.2,
                "references": [
                    "https://owasp.org/www-community/attacks/xss/",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                ],
            },
        }

        # Match template by vuln type
        for key, template in templates.items():
            if key.lower() in vuln.vuln_type.lower():
                template["cvss_score"] = self._estimate_cvss(vuln)
                return template

        # Generic fallback
        return {
            "explanation":  f"{vuln.vuln_type} was detected at {vuln.url}.",
            "impact":       "Review the finding manually to assess impact.",
            "remediation":  "Consult OWASP guidelines for this vulnerability type.",
            "code_example": "",
            "cvss_score":   self._estimate_cvss(vuln),
            "references":   ["https://owasp.org/www-project-top-ten/"],
        }

    def _fallback_summary(self, scan_result: ScanResult) -> str:
        total = len(scan_result.vulnerabilities)
        high  = sum(
            1 for v in scan_result.vulnerabilities
            if v.severity.value in ("HIGH", "CRITICAL")
        )
        return (
            f"WASP scanned {scan_result.target} and discovered "
            f"{total} vulnerability/vulnerabilities, of which {high} "
            f"are rated HIGH or CRITICAL severity. Immediate remediation "
            f"is recommended for all high-severity findings. A full review "
            f"of the application's input validation and output encoding "
            f"practices should be conducted."
        )

    def _estimate_cvss(self, vuln: Vulnerability) -> float:
        """Estimate a CVSS score from severity level."""
        return {
            "CRITICAL": 9.5,
            "HIGH":     7.5,
            "MEDIUM":   5.0,
            "LOW":      3.0,
            "INFO":     1.0,
        }.get(vuln.severity.value, 5.0)