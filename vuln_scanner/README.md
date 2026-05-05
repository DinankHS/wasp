# docker setup and port connection 
docker ps

# bWAPP port connection
docker run --rm -d -p 8080:80 --name bwapp raesene/bwapp

# DVWA port connection
docker run --rm -d -p 80:80 --name dvwa vulnerables/web-dvwa

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