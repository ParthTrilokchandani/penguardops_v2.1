"""
Intelligent Web Crawler
Depth-controlled, scope-aware, with form and parameter discovery.
"""

import re
from typing import Set, List, Dict, Optional, Tuple
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
from collections import deque
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

from bs4 import BeautifulSoup

from core.config import ScanConfig
from core.http_session import HttpSession
from utils.logger import get_logger

logger = get_logger("crawler")


@dataclass
class FormField:
    name: str
    field_type: str  # text, password, hidden, textarea, select, etc.
    value: str = ""
    options: List[str] = field(default_factory=list)  # for select


@dataclass
class Form:
    url: str
    action: str
    method: str  # GET or POST
    fields: List[FormField]
    enctype: str = "application/x-www-form-urlencoded"

    @property
    def target_url(self) -> str:
        return self.action or self.url

    def to_data(self) -> Dict[str, str]:
        return {f.name: f.value or "test" for f in self.fields if f.name}


@dataclass
class CrawlResult:
    url: str
    depth: int
    status_code: int
    content_type: str
    forms: List[Form] = field(default_factory=list)
    links: List[str] = field(default_factory=list)
    parameters: Dict[str, List[str]] = field(default_factory=dict)  # url -> [param names]
    scripts: List[str] = field(default_factory=list)
    comments: List[str] = field(default_factory=list)


class Crawler:
    """
    Multi-threaded web crawler with:
    - Depth control
    - Scope enforcement
    - Form discovery and parsing
    - URL parameter extraction
    - JavaScript endpoint extraction
    - HTML comment mining
    """

    def __init__(self, config: ScanConfig, session: HttpSession):
        self.config = config
        self.session = session
        self.visited: Set[str] = set()
        self.queued: Set[str] = set()
        self._lock = threading.Lock()
        self.results: Dict[str, CrawlResult] = {}
        self.all_forms: List[Form] = []
        self.all_endpoints: Dict[str, List[str]] = {}  # url -> param names

        # Parse base domain
        parsed = urlparse(config.target_url)
        self.base_domain = parsed.netloc
        self.base_scheme = parsed.scheme

        # In-scope domains
        self.scope_domains = set([self.base_domain] + config.scope)

    def crawl(self) -> Dict[str, CrawlResult]:
        """Main crawl entry point. Returns all discovered resources."""
        logger.info(f"Starting crawl: {self.config.target_url} (depth={self.config.depth})")

        queue = deque([(self.config.target_url, 0)])
        self.queued.add(self.config.target_url)

        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = {}

            while queue or futures:
                # Submit batch of work
                while queue and len(futures) < self.config.threads * 2:
                    if len(self.visited) >= self.config.max_urls:
                        break
                    url, depth = queue.popleft()
                    future = executor.submit(self._crawl_url, url, depth)
                    futures[future] = (url, depth)

                if not futures:
                    break

                # Process completed
                done = {f for f in futures if f.done()}
                for future in done:
                    url, depth = futures.pop(future)
                    try:
                        result = future.result()
                        if result:
                            with self._lock:
                                self.results[url] = result
                                self.all_forms.extend(result.forms)
                                if result.parameters:
                                    self.all_endpoints.update(result.parameters)

                            # Enqueue discovered links
                            if depth < self.config.depth:
                                for link in result.links:
                                    with self._lock:
                                        if (link not in self.queued
                                                and link not in self.visited
                                                and len(self.visited) + len(self.queued) < self.config.max_urls):
                                            self.queued.add(link)
                                            queue.append((link, depth + 1))
                    except Exception as e:
                        logger.debug(f"Crawl error for {url}: {e}")

        logger.info(
            f"Crawl complete: {len(self.results)} URLs, "
            f"{len(self.all_forms)} forms, "
            f"{len(self.all_endpoints)} parameterized endpoints"
        )
        return self.results

    def _crawl_url(self, url: str, depth: int) -> Optional[CrawlResult]:
        """Crawl a single URL and extract all resources."""
        with self._lock:
            if url in self.visited:
                return None
            self.visited.add(url)

        if not self._in_scope(url):
            return None

        if self._is_excluded(url):
            return None

        resp = self.session.get(url)
        if not resp:
            return None

        content_type = resp.headers.get("Content-Type", "")
        result = CrawlResult(
            url=url,
            depth=depth,
            status_code=resp.status_code,
            content_type=content_type,
        )

        # Only parse HTML responses
        if "text/html" in content_type or "application/xhtml" in content_type:
            try:
                soup = BeautifulSoup(resp.text, "html.parser")
                result.links = self._extract_links(soup, url)
                result.forms = self._extract_forms(soup, url)
                result.parameters = self._extract_parameters(url)
                result.scripts = self._extract_js_endpoints(soup, url)
                result.comments = self._extract_comments(soup)
            except Exception as e:
                logger.debug(f"Parse error for {url}: {e}")

        # Extract params from URL itself
        url_params = self._extract_parameters(url)
        if url_params:
            result.parameters.update(url_params)

        if self.config.verbose:
            logger.debug(
                f"[{depth}] {url} → {resp.status_code} | "
                f"links={len(result.links)} forms={len(result.forms)}"
            )

        return result

    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract and normalize all links from the page."""
        links = []
        tags = [
            ("a", "href"),
            ("link", "href"),
            ("form", "action"),
            ("script", "src"),
            ("img", "src"),
            ("iframe", "src"),
            ("frame", "src"),
        ]

        for tag, attr in tags:
            for element in soup.find_all(tag, **{attr: True}):
                href = element.get(attr, "")
                if not href:
                    continue
                abs_url = self._normalize_url(href, base_url)
                if abs_url and self._in_scope(abs_url) and self._is_html_resource(abs_url):
                    links.append(abs_url)

        return list(set(links))

    def _extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[Form]:
        """Parse all HTML forms including fields."""
        forms = []
        for form_tag in soup.find_all("form"):
            action = form_tag.get("action", "")
            method = form_tag.get("method", "GET").upper()
            enctype = form_tag.get("enctype", "application/x-www-form-urlencoded")

            # Resolve action URL
            if action:
                action = urljoin(base_url, action)
            else:
                action = base_url

            fields = []

            # Input fields
            for inp in form_tag.find_all(["input", "textarea", "select"]):
                field_name = inp.get("name", "")
                if not field_name:
                    continue

                field_type = inp.get("type", "text").lower()
                field_value = inp.get("value", "")

                # Select options
                options = []
                if inp.name == "select":
                    options = [opt.get("value", opt.text) for opt in inp.find_all("option")]
                    field_value = options[0] if options else ""
                    field_type = "select"
                elif inp.name == "textarea":
                    field_type = "textarea"
                    field_value = inp.get_text()

                fields.append(FormField(
                    name=field_name,
                    field_type=field_type,
                    value=field_value,
                    options=options,
                ))

            if fields:
                forms.append(Form(
                    url=base_url,
                    action=action,
                    method=method,
                    fields=fields,
                    enctype=enctype,
                ))

        return forms

    def _extract_parameters(self, url: str) -> Dict[str, List[str]]:
        """Extract URL query parameters."""
        parsed = urlparse(url)
        if not parsed.query:
            return {}

        params = parse_qs(parsed.query, keep_blank_values=True)
        param_names = list(params.keys())

        if param_names:
            # Strip query for key, store param names
            base = urlunparse(parsed._replace(query="", fragment=""))
            return {base: param_names}

        return {}

    def _extract_js_endpoints(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract API endpoints and URLs from JavaScript."""
        endpoints = []
        patterns = [
            r'(?:url|href|src|action|endpoint|api)\s*[:=]\s*["\']([^"\']+)["\']',
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'axios\.\w+\s*\(\s*["\']([^"\']+)["\']',
            r'\$\.(?:ajax|get|post)\s*\(\s*["\']([^"\']+)["\']',
            r'"(\/[a-zA-Z0-9_\-\/]+(?:\?[^"]*)?)"',
        ]

        for script in soup.find_all("script"):
            src = script.get("src")
            if src:
                abs_src = self._normalize_url(src, base_url)
                if abs_src:
                    endpoints.append(abs_src)
                continue

            script_text = script.get_text()
            for pattern in patterns:
                matches = re.findall(pattern, script_text)
                for match in matches:
                    if match.startswith("/") or match.startswith("http"):
                        abs_url = self._normalize_url(match, base_url)
                        if abs_url and self._in_scope(abs_url):
                            endpoints.append(abs_url)

        return list(set(endpoints))

    def _extract_comments(self, soup: BeautifulSoup) -> List[str]:
        """Extract HTML comments that may reveal sensitive info."""
        from bs4 import Comment
        return [
            str(c).strip()
            for c in soup.find_all(string=lambda t: isinstance(t, Comment))
            if len(str(c).strip()) > 10
        ]

    def _normalize_url(self, href: str, base_url: str) -> Optional[str]:
        """Normalize and resolve URL."""
        if not href:
            return None

        # Skip non-HTTP schemes
        skip_schemes = {"javascript:", "mailto:", "tel:", "data:", "#", "ftp:"}
        for skip in skip_schemes:
            if href.lower().startswith(skip):
                return None

        try:
            abs_url = urljoin(base_url, href)
            parsed = urlparse(abs_url)

            # Normalize: remove fragments, lowercase scheme/host
            normalized = urlunparse((
                parsed.scheme.lower(),
                parsed.netloc.lower(),
                parsed.path,
                parsed.params,
                parsed.query,
                ""  # no fragment
            ))
            return normalized
        except Exception:
            return None

    def _in_scope(self, url: str) -> bool:
        """Check if URL is within defined scope."""
        try:
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https"):
                return False
            return parsed.netloc in self.scope_domains
        except Exception:
            return False

    def _is_excluded(self, url: str) -> bool:
        """Check if URL matches any exclusion pattern."""
        for pattern in self.config.exclude_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        return False

    def _is_html_resource(self, url: str) -> bool:
        """Filter out static assets."""
        skip_extensions = {
            ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".webp",
            ".pdf", ".doc", ".docx", ".zip", ".tar", ".gz",
            ".mp4", ".mp3", ".avi", ".mov", ".wmv",
            ".woff", ".woff2", ".ttf", ".eot",
            ".css",  # skip CSS (parse JS for endpoints)
        }
        parsed = urlparse(url)
        path = parsed.path.lower()
        for ext in skip_extensions:
            if path.endswith(ext):
                return False
        return True

    def get_attack_surface(self) -> Dict:
        """Summarize the full attack surface discovered."""
        parameterized_urls = []
        for result in self.results.values():
            parsed = urlparse(result.url)
            if parsed.query:
                parameterized_urls.append(result.url)

        return {
            "total_urls": len(self.results),
            "forms": len(self.all_forms),
            "parameterized_urls": len(parameterized_urls),
            "form_list": [
                {
                    "url": f.url,
                    "action": f.target_url,
                    "method": f.method,
                    "fields": [{"name": fld.name, "type": fld.field_type} for fld in f.fields]
                }
                for f in self.all_forms
            ],
            "parameterized_url_list": parameterized_urls,
        }
