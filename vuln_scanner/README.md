# docker setup and port connection 
docker ps

# bWAPP port connection
docker run --rm -d -p 8080:80 --name bwapp raesene/bwapp

# DVWA port connection
docker run --rm -d -p 80:80 --name dvwa vulnerables/web-dvwa

# WebGoat — OWASP's Java-based training app
docker run --rm -d -p 8080:8080 webgoat/goat-and-wolf

# Juice Shop — OWASP's modern Node.js vulnerable app
docker run --rm -d -p 3000:3000 bkimminich/juice-shop


# DVWA localhost
http://localhost/setup.php

# bWAPP localhost
http://localhost:8080/install.php

# Full scan with everything
python main.py --target "http://localhost:8080/sqli_1.php?title=%25&action=search" --auto-login --app bwapp --use-ai --output all

# Quick scan (no ports, no auth, no plugins)
python main.py --target "http://localhost:8080/sqli_1.php?title=%25&action=search" --auto-login --app bwapp --skip-ports --skip-auth --skip-plugins

# DVWA scan
python main.py --target "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit" --auto-login --app dvwa --skip-ports

# Dashboard mode
python main.py --dashboard
# Open http://localhost:5000

# Standard CLI scan
python main.py --target "URL" --auto-login --app bwapp

# Launch web dashboard
python main.py --dashboard
# Open http://localhost:5000

# Skip slow stages for quick scan
python main.py --target "URL" --auto-login --app bwapp \
  --skip-ports --skip-auth --skip-plugins

# Scan DVWA instead
python main.py --target "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --auto-login --app dvwa --skip-ports

# Enable AI when you add credits
python main.py --target "URL" --auto-login --app bwapp --use-ai

# Check vulnerabilities breakdown
psql -U postgres -d wasp -c "SELECT vuln_type, severity, COUNT(*) FROM vulnerabilities WHERE scan_id='20260515_131926_691754' GROUP BY vuln_type, severity ORDER BY severity;"

# Check reports saved
psql -U postgres -d wasp -c "SELECT report_type, filename, file_size FROM reports WHERE scan_id='20260515_131926_691754';"

# Check URLs crawled
psql -U postgres -d wasp -c "SELECT COUNT(*) as url_count FROM urls WHERE scan_id='20260515_131926_691754';"

# Live Public Test Sites (no setup needed)
http://testphp.vulnweb.com          — Acunetix PHP test site (SQLi, XSS, LFI)
http://testasp.vulnweb.com          — Acunetix ASP test site
http://testaspnet.vulnweb.com       — Acunetix ASP.NET test site
http://zero.webappsecurity.com      — IBM Rational AppScan test bank app
http://demo.testfire.net            — IBM Altoroj demo banking app (classic)
http://crackme.cenzic.com           — Cenzic test site
https://public-firing-range.appspot.com — Google XSS firing range