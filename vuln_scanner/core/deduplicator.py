# core/deduplicator.py
"""
WASP Deduplicator — Comprehensive false positive filter and deduplication.

Handles:
1. Exact duplicates (url + parameter + vuln_type)
2. Same parameter across different URLs on same domain (e.g. index.jsp?content=X)
3. File inclusion parameters that load static content
4. Password field XSS (reflected but not exploitable)
5. Cross-scanner duplicates (URL scanner + form scanner same finding)
6. Mutation scanner duplicates (same vuln found by base + mutated payload)
"""

from urllib.parse import urlparse
from core.logger import get_logger

log = get_logger(__name__)

# ── Parameters that load static files — not injectable ───────────────────────
FILE_INCLUSION_PARAMS = {
    "content", "page", "file", "include", "template",
    "view", "load", "path", "doc", "document",
    "src", "source", "lang", "language", "module",
    "section", "tab", "frame", "layout",
}

# ── Field names that are password inputs — skip XSS on these ─────────────────
PASSWORD_FIELD_NAMES = {
    "password", "passwd", "pass", "pwd", "password_curr",
    "password_new", "password_conf", "new_password",
    "confirm_password", "current_password", "passw",
}

# ── XSS vuln types that come from form scanners ───────────────────────────────
FORM_XSS_TYPES = {
    "Reflected XSS (Form Input)",
    "Reflected XSS (Form - Mutated)",
}

# ── XSS vuln types from URL scanner ──────────────────────────────────────────
URL_XSS_TYPES = {
    "Reflected XSS (URL Parameter)",
}


def is_file_inclusion_param(param: str) -> bool:
    """Check if a parameter name is a file inclusion parameter."""
    return param.lower().strip() in FILE_INCLUSION_PARAMS


def is_password_field(param: str) -> bool:
    """Check if all fields in a (possibly comma-separated) parameter are password fields."""
    fields = [f.strip().lower() for f in param.split(",")]
    return all(f in PASSWORD_FIELD_NAMES for f in fields if f)


def get_base_vuln_type(vuln_type: str) -> str:
    """Normalize vuln type by stripping scanner-specific suffixes."""
    return (
        vuln_type
        .replace(" (Form - Mutated)", "")
        .replace(" (Form Input)", "")
        .replace(" (URL Parameter)", "")
        .replace(" (HTTP Header)", "")
        .replace(" (Form - Error-based)", "")
        .replace(" (Error-based)", "")
        .replace(" (Boolean-based)", "")
        .replace(" (Time-based)", "")
    )


def deduplicate(findings: list, aggressive: bool = True) -> list:
    """
    Deduplicate and filter false positives from a list of Vulnerability objects.

    Args:
        findings   — list of Vulnerability objects
        aggressive — if True, also apply domain-level dedup for same param

    Returns filtered, deduplicated list.
    """
    if not findings:
        return []

    original_count = len(findings)
    filtered = []

    # ── Pass 1: Filter obvious false positives ────────────────────────────────
    for v in findings:
        # Skip file inclusion parameters for XSS
        base_type = get_base_vuln_type(v.vuln_type)
        if base_type == "Reflected XSS":
            first_param = v.parameter.split(",")[0].strip()
            if is_file_inclusion_param(first_param):
                log.debug(f"FP filter: file inclusion param '{v.parameter}' at {v.url}")
                continue

        # Skip password-only fields for XSS (reflected but not exploitable)
        if v.vuln_type in FORM_XSS_TYPES or v.vuln_type in URL_XSS_TYPES:
            if is_password_field(v.parameter):
                log.debug(f"FP filter: password field '{v.parameter}' at {v.url}")
                continue

        filtered.append(v)

    # ── Pass 2: Exact dedup (url + parameter + base_type) ────────────────────
    seen_exact = set()
    exact_deduped = []
    for v in filtered:
        base_type   = get_base_vuln_type(v.vuln_type)
        first_param = v.parameter.split(",")[0].strip()
        key = (v.url, first_param, base_type)
        if key not in seen_exact:
            seen_exact.add(key)
            exact_deduped.append(v)

    # ── Pass 3: Cross-scanner dedup ───────────────────────────────────────────
    # If same URL+param found by both URL scanner and form scanner, keep one
    seen_cross = set()
    cross_deduped = []
    for v in exact_deduped:
        base_type   = get_base_vuln_type(v.vuln_type)
        first_param = v.parameter.split(",")[0].strip()
        parsed      = urlparse(v.url)
        # Normalize URL by removing query string for form findings
        if v.vuln_type in FORM_XSS_TYPES:
            url_key = parsed.netloc + parsed.path
        else:
            url_key = v.url
        key = (url_key, first_param, base_type)
        if key not in seen_cross:
            seen_cross.add(key)
            cross_deduped.append(v)

    # ── Pass 4: Domain-level dedup (aggressive) ───────────────────────────────
    # Same parameter on same domain path template = one finding
    # e.g. index.jsp?content=X for 30 different X values → one finding
    if not aggressive:
        result = cross_deduped
    else:
        seen_domain = set()
        domain_deduped = []
        for v in cross_deduped:
            base_type   = get_base_vuln_type(v.vuln_type)
            first_param = v.parameter.split(",")[0].strip()
            parsed      = urlparse(v.url)
            # Key: domain + path (without query) + param + base_type
            domain_key = (parsed.netloc, parsed.path, first_param, base_type)
            if domain_key not in seen_domain:
                seen_domain.add(domain_key)
                domain_deduped.append(v)
        result = domain_deduped

    removed = original_count - len(result)
    if removed > 0:
        log.info(
            f"Deduplicator: {original_count} → {len(result)} findings "
            f"({removed} removed as duplicates/false positives)"
        )

    return result