# WASP — Web Application Security Probe v2.0

Automated web vulnerability scanner with AI-assisted reporting.

## Features
- SQL Injection detection (error + boolean + time-based)
- Reflected XSS detection (URL params + forms + headers)
- Form crawler with payload mutation engine (WAF bypass)
- Authentication testing (default creds + enumeration + lockout)
- Plugin architecture (drop-in vulnerability modules)
- Port scanner (multithreaded)
- AI-powered remediation advice (Claude API)
- Professional PDF reports with CVSS scoring
- Web dashboard with live scan progress

## Quick Start
pip install -r requirements.txt
python main.py --target "http://localhost:8080" --auto-login --app bwapp

## Dashboard
python main.py --dashboard
