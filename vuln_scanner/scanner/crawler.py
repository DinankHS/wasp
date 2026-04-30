# scanner/crawler.py
"""
WASP Crawler — Phase 1
Discovers all reachable URLs from a seed URL.
Skips logout/destructive URLs to preserve session.
"""

import time
from collections import deque
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup

from config import (
    REQUEST_TIMEOUT,
    REQUEST_DELAY,
    MAX_CRAWL_DEPTH,
    MAX_URLS,
    USER_AGENT,
)
from core.logger import get_logger
from core.utils import is_same_domain, is_valid_url, normalize_url, build_cookie_jar

log = get_logger(__name__)

# Never follow these — they destroy session or cause damage
SKIP_PATTERNS = [
    "logout", "logoff", "signout", "sign-out",
    "delete", "remove", "reset", "drop",
]


class Crawler:
    def __init__(
        self,
        seed_url: str,
        max_depth: int = MAX_CRAWL_DEPTH,
        cookies: dict | None = None,
        session=None,
    ):
        self.seed_url  = normalize_url(seed_url)
        self.max_depth = max_depth
        self.visited:  set[str]  = set()
        self.found:    list[str] = []
        self.errors:   list[str] = []

        if session is not None:
            self.session = session
            self.session.headers.update({
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,*/*",
            })
            log.info("Using provided authenticated session for crawler.")
        else:
            self.session = requests.Session()
            self.session.headers.update({
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,*/*",
            })
            if cookies:
                self.session.cookies = build_cookie_jar(cookies, url=self.seed_url)
                log.info(f"Session cookies loaded: {list(cookies.keys())}")

    def crawl(self) -> list[str]:
        log.info(f"Starting crawl: {self.seed_url} (max depth={self.max_depth})")

        queue: deque[tuple[str, int]] = deque()
        queue.append((self.seed_url, 0))

        while queue:
            if len(self.found) >= MAX_URLS:
                log.warning(f"Reached URL cap ({MAX_URLS}). Stopping crawl.")
                break

            url, depth = queue.popleft()

            if url in self.visited:
                continue

            self.visited.add(url)
            log.info(f"[depth={depth}] Crawling: {url}")
            html = self._fetch(url)

            if html is None:
                if depth == 0:
                    log.info(f"Seed URL unreachable via crawler but added for scanning: {url}")
                    self.found.append(url)
                continue

            self.found.append(url)

            if depth >= self.max_depth:
                continue

            links = self._extract_links(html, base_url=url)
            for link in links:
                if link not in self.visited:
                    queue.append((link, depth + 1))

            time.sleep(REQUEST_DELAY)

        log.info(f"Crawl complete. {len(self.found)} URLs found, {len(self.errors)} errors.")
        return self.found

    def _fetch(self, url: str) -> str | None:
        try:
            response = self.session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)

            content_type = response.headers.get("Content-Type", "")
            if "text/html" not in content_type:
                log.debug(f"Skipping non-HTML ({content_type}): {url}")
                return None

            if "login" in response.url and "login" not in url:
                log.debug(f"Redirected to login (session expired?): {url}")
                return None

            if response.status_code not in (200, 301, 302):
                log.debug(f"Non-200 status ({response.status_code}): {url}")
                return None

            return response.text

        except requests.exceptions.Timeout:
            msg = f"Timeout fetching: {url}"
            log.warning(msg)
            self.errors.append(msg)
            return None
        except requests.exceptions.ConnectionError:
            msg = f"Connection error: {url}"
            log.warning(msg)
            self.errors.append(msg)
            return None
        except requests.exceptions.RequestException as e:
            msg = f"Request failed for {url}: {e}"
            log.warning(msg)
            self.errors.append(msg)
            return None

    def _extract_links(self, html: str, base_url: str) -> list[str]:
        links = []
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception as e:
            log.warning(f"HTML parse error for {base_url}: {e}")
            return links

        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if not href or href.startswith(("#", "mailto:", "javascript:", "tel:")):
                continue

            absolute = urljoin(base_url, href)
            parsed   = urlparse(absolute)
            absolute = parsed._replace(fragment="").geturl()

            # Skip logout and destructive URLs — they kill the session
            if any(pattern in absolute.lower() for pattern in SKIP_PATTERNS):
                log.debug(f"Skipping dangerous URL: {absolute}")
                continue

            if not is_same_domain(self.seed_url, absolute):
                continue
            if not is_valid_url(absolute):
                continue

            links.append(absolute)

        seen   = set()
        unique = []
        for link in links:
            if link not in seen:
                seen.add(link)
                unique.append(link)

        return unique