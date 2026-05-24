# db/models.py
"""
WASP PostgreSQL schema.

Tables
------
scans           — one row per scan run (config, status, timestamps)
vulnerabilities — one row per finding  (linked to scan)
ports           — one row per open port (linked to scan)
urls            — one row per crawled URL (linked to scan)
reports         — one row per generated report file (linked to scan)

All foreign keys reference scans.id (TEXT) which matches the
scan_id format already used in dashboard/app.py ("%Y%m%d_%H%M%S_%f").
"""

SCHEMA_SQL = """
-- ── scans ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scans (
    id              TEXT        PRIMARY KEY,            -- "20240101_120000_123456"
    target          TEXT        NOT NULL,
    status          TEXT        NOT NULL DEFAULT 'running',
                                                        -- running | complete | error | stopped
    depth           INTEGER     NOT NULL DEFAULT 2,
    app_type        TEXT        NOT NULL DEFAULT 'none',-- none | dvwa | bwapp
    skip_ports      BOOLEAN     NOT NULL DEFAULT FALSE,
    use_ai          BOOLEAN     NOT NULL DEFAULT FALSE,
    output_format   TEXT        NOT NULL DEFAULT 'all', -- all | json | txt | pdf
    cookie_supplied BOOLEAN     NOT NULL DEFAULT FALSE, -- true if a cookie was passed
    error_message   TEXT,                               -- populated on status=error
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at     TIMESTAMPTZ,
    urls_crawled    INTEGER     NOT NULL DEFAULT 0,
    vuln_count      INTEGER     NOT NULL DEFAULT 0,
    port_count      INTEGER     NOT NULL DEFAULT 0,
    error_count     INTEGER     NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans (started_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_target     ON scans (target);
CREATE INDEX IF NOT EXISTS idx_scans_status     ON scans (status);


-- ── vulnerabilities ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id          SERIAL      PRIMARY KEY,
    scan_id     TEXT        NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    vuln_type   TEXT        NOT NULL,   -- "SQL Injection" | "Reflected XSS" …
    url         TEXT        NOT NULL,
    parameter   TEXT        NOT NULL DEFAULT '',
    payload     TEXT        NOT NULL DEFAULT '',
    severity    TEXT        NOT NULL,   -- CRITICAL | HIGH | MEDIUM | LOW | INFO
    description TEXT        NOT NULL DEFAULT '',
    evidence    TEXT        NOT NULL DEFAULT '',
    remediation TEXT        NOT NULL DEFAULT '',  -- AI-generated when use_ai=true
    found_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_vulns_scan_id  ON vulnerabilities (scan_id);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities (severity);
CREATE INDEX IF NOT EXISTS idx_vulns_type     ON vulnerabilities (vuln_type);


-- ── ports ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ports (
    id       SERIAL  PRIMARY KEY,
    scan_id  TEXT    NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    port     INTEGER NOT NULL,
    state    TEXT    NOT NULL DEFAULT 'open',
    service  TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_ports_scan_id ON ports (scan_id);


-- ── urls ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS urls (
    id      SERIAL PRIMARY KEY,
    scan_id TEXT   NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    url     TEXT   NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_urls_scan_id ON urls (scan_id);


-- ── reports ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS reports (
    id          SERIAL      PRIMARY KEY,
    scan_id     TEXT        NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    report_type TEXT        NOT NULL,   -- json | txt | pdf | csv
    filename    TEXT        NOT NULL,   -- basename of the file
    filepath    TEXT        NOT NULL,   -- absolute path on disk
    file_size   BIGINT      NOT NULL DEFAULT 0,  -- bytes
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_reports_scan_id ON reports (scan_id);

-- ── aggregate view (handy for the dashboard /api/scans endpoint) ───────────
CREATE OR REPLACE VIEW scan_summary AS
    SELECT
        s.id,
        s.target,
        s.status,
        s.started_at,
        s.finished_at,
        s.urls_crawled,
        s.vuln_count,
        s.port_count,
        s.use_ai,
        s.app_type,
        COALESCE(
            json_agg(
                json_build_object(
                    'type', r.report_type,
                    'filename', r.filename
                )
            ) FILTER (WHERE r.id IS NOT NULL),
            '[]'
        ) AS report_files,
        COALESCE(
            json_agg(
                json_build_object(
                    'severity', v.severity,
                    'type', v.vuln_type
                )
            ) FILTER (WHERE v.id IS NOT NULL),
            '[]'
        ) AS vuln_summary
    FROM scans s
    LEFT JOIN reports       r ON r.scan_id = s.id
    LEFT JOIN vulnerabilities v ON v.scan_id = s.id
    GROUP BY s.id;
"""