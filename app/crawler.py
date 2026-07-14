"""
crawler.py — Crawls any web application (local or hosted).
Finds: HTML forms (with inputs), potential AI chatbot endpoints.
Also probes common vulnerable paths when crawling misses them.

NOTE: Only scan websites you are authorized to test.
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0"}

# Common paths to probe directly — most likely to have injectable forms
COMMON_PATHS = [
    "/login", "/login.php", "/signin",
    "/search", "/search.php",
    "/register", "/signup.php",
    "/contact", "/contact.php",
    "/guestbook", "/guestbook.php",
    "/comment", "/feedback.php",
    "/artists.php", "/listproducts.php",
    "/userinfo.php", "/secured/newuser.php",
]

# Heuristic patterns that suggest an AI chatbot endpoint
CHATBOT_PATH_HINTS = [
    "chat", "bot", "ask", "query", "ai", "gpt", "llm",
    "assistant", "message", "prompt", "inference"
]


def is_local(url: str) -> bool:
    """Check if URL is a local/private host."""
    try:
        host = urlparse(url).hostname or ""
        if host in LOCAL_HOSTS:
            return True
        if host.startswith("192.168.") or host.startswith("10.") or host.startswith("172."):
            return True
        if host.endswith(".local"):
            return True
        return False
    except Exception:
        return False


def _fetch(url: str, headers: dict) -> tuple:
    """Fetch a URL. Returns (response, error_string)."""
    try:
        resp = requests.get(
            url, timeout=3, headers=headers,
            allow_redirects=True, verify=False
        )
        return resp, None
    except requests.exceptions.ConnectionError as e:
        return None, f"Connection failed: {e}"
    except requests.exceptions.Timeout:
        return None, f"Timeout fetching: {url}"
    except Exception as e:
        return None, f"Error fetching {url}: {e}"


def _parse_forms(soup: BeautifulSoup, page_url: str) -> list:
    """Extract all forms with their inputs from a parsed page."""
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action") or ""
        method = (form.get("method") or "GET").upper()
        action_url = urljoin(page_url, action) if action else page_url

        inputs = []
        for tag in form.find_all(["input", "textarea", "select"]):
            name = tag.get("name")
            if name:
                inputs.append({
                    "name": name,
                    "type": tag.get("type", "text"),
                    "value": tag.get("value", "")
                })

        if inputs:
            forms.append({
                "url": page_url,
                "action": action_url,
                "method": method,
                "inputs": inputs,
                "form_id": form.get("id", ""),
                "form_name": form.get("name", "")
            })
    return forms


def crawl(seed_url: str, max_pages: int = 8) -> dict:
    """
    Crawl seed_url and return all forms + detected chatbot endpoints.
    Works on both local and hosted/live websites.
    Also probes common paths to find hidden forms.
    """
    errors = []
    if not is_local(seed_url):
        errors.append(f"INFO: Scanning hosted URL '{seed_url}'. Ensure you have authorization to test this target.")

    base = urlparse(seed_url)
    base_netloc = base.netloc
    base_origin = f"{base.scheme}://{base_netloc}"

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    }

    to_visit = [seed_url]
    visited = set()
    forms = []
    form_signatures = set()   # deduplicate forms by action+field combo
    chatbot_endpoints = []
    all_errors = list(errors)

    # ── Phase 1: Follow links from crawled pages ──────────────────────────────
    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)

        resp, err = _fetch(url, headers)
        if err:
            all_errors.append(err)
            continue
        if not resp or "text/html" not in resp.headers.get("Content-Type", ""):
            continue

        soup = BeautifulSoup(resp.text, "html.parser")

        # Extract forms
        for f in _parse_forms(soup, url):
            sig = f"{f['action']}:{','.join(i['name'] for i in f['inputs'])}"
            if sig not in form_signatures:
                form_signatures.add(sig)
                forms.append(f)

        # Detect chatbot endpoints from links and scripts
        for anchor in soup.find_all("a", href=True):
            href = urljoin(url, anchor["href"])
            path = urlparse(href).path.lower()
            if any(hint in path for hint in CHATBOT_PATH_HINTS):
                if href not in chatbot_endpoints:
                    chatbot_endpoints.append(href)

        for script in soup.find_all("script"):
            text = script.string or ""
            for hint in CHATBOT_PATH_HINTS:
                if f"/{hint}" in text or f'"{hint}' in text:
                    candidate = urljoin(url, f"/api/{hint}")
                    if candidate not in chatbot_endpoints:
                        chatbot_endpoints.append(candidate)
                    break

        # Queue internal links
        for a in soup.find_all("a", href=True):
            abs_url = urljoin(url, a["href"]).split("#")[0].split("?")[0]
            if urlparse(abs_url).netloc == base_netloc and abs_url not in visited:
                to_visit.append(abs_url)

    # ── Phase 2: Probe common vulnerable paths directly ───────────────────────
    probed = 0
    for path in COMMON_PATHS:
        probe_url = urljoin(base_origin + "/", path.lstrip("/"))
        if probe_url in visited:
            continue
        if probed >= 12:
            break

        resp, err = _fetch(probe_url, headers)
        probed += 1

        if err or not resp:
            continue
        if resp.status_code in (404, 403, 401, 500):
            continue
        if "text/html" not in resp.headers.get("Content-Type", ""):
            continue

        visited.add(probe_url)
        soup = BeautifulSoup(resp.text, "html.parser")

        for f in _parse_forms(soup, probe_url):
            sig = f"{f['action']}:{','.join(i['name'] for i in f['inputs'])}"
            if sig not in form_signatures:
                form_signatures.add(sig)
                forms.append(f)

    return {
        "seed": seed_url,
        "crawled_urls": list(visited),
        "forms": forms,
        "chatbot_endpoints": list(set(chatbot_endpoints)),
        "errors": all_errors
    }
