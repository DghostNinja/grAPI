// increased the speed of scan for big assests by reducing requests to 100


"""
grAPI - Aggressive & Stealthy API Recon Tool
Supports Active & Passive Discovery, Token Extraction, Spec Detection.
Optimized for performance and stealth.

Usage:
    python3 grAPI.py --url https://example.com --all -v
"""

import requests
import re
import time
import random
import argparse
import json
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
from concurrent.futures import ThreadPoolExecutor

ua = UserAgent()
visited = set()
endpoints = {}
verbose = False
root_url = ""

# Patterns
KEYWORDS = [
    'auth', 'login', 'logout', 'register', 'users?', 'admin', 'dashboard',
    'profile', 'settings', 'account', 'session', 'token', 'graphql', 'rest',
    'api', 'v1', 'v2', 'products?', 'items?', 'orders?', 'data', 'service'
]
WAF_SIGNATURES = ["cloudflare", "sucuri", "akamai", "imperva", "aws"]
BAD_EXTENSIONS = re.compile(r'\.(jpg|jpeg|png|gif|svg|css|woff|ico|ttf|eot|pdf)(\?|$)', re.IGNORECASE)

# Headers
HEADERS = lambda: {
    'User-Agent': ua.random,
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept': '*/*'
}

def log(msg):
    if verbose:
        print(msg)

def safe_get(url):
    try:
        return requests.get(url, headers=HEADERS(), timeout=8)
    except:
        return None

# Passive Recon (Wayback)
def passive_wayback(target, max_results=300):
    print("[*] Running passive scan via Wayback Machine...")
    domain = urlparse(target).netloc
    wayback_url = (
        f"http://web.archive.org/cdx/search/cdx?url={domain}/*"
        f"&output=json&fl=original&collapse=urlkey&limit={max_results}"
    )
    try:
        resp = requests.get(wayback_url, timeout=10)
        if resp.status_code == 200:
            entries = resp.json()[1:]
            for entry in entries:
                url = entry[0]
                if BAD_EXTENSIONS.search(url): continue
                if any(re.search(k, url, re.IGNORECASE) for k in KEYWORDS):
                    endpoints[url] = None
    except Exception as e:
        log(f"[!] Wayback failed: {e}")

# Fingerprint Detection
def fingerprint():
    print("[*] Running fingerprint scan...")
    try:
        r = safe_get(root_url)
        if r:
            print("[+] Headers:")
            for k, v in r.headers.items():
                print(f"  {k}: {v}")
            for sig in WAF_SIGNATURES:
                if sig in str(r.headers).lower():
                    print(f"[!] Possible WAF/CDN detected: {sig}")
        rt = safe_get(urljoin(root_url, "/robots.txt"))
        sm = safe_get(urljoin(root_url, "/sitemap.xml"))
        if rt and rt.status_code == 200:
            print("[+] robots.txt found")
        if sm and sm.status_code == 200:
            print("[+] sitemap.xml found")
    except:
        pass

# Swagger / OpenAPI
def scan_swagger():
    print("[*] Scanning for Swagger/OpenAPI...")
    candidates = ["/swagger.json", "/api-docs", "/v1/swagger.json", "/openapi.json"]
    for path in candidates:
        url = urljoin(root_url, path)
        resp = safe_get(url)
        if resp and resp.status_code == 200 and 'swagger' in resp.text.lower():
            print(f"[+] Swagger/OpenAPI found: {url}")
            endpoints[url] = 200

# GraphQL Detection
def scan_graphql():
    print("[*] Scanning for GraphQL endpoint...")
    graphql_url = urljoin(root_url, "/graphql")
    headers = HEADERS()
    headers['Content-Type'] = 'application/json'
    payload = {'query': '{ __schema { types { name } } }'}
    try:
        resp = requests.post(graphql_url, headers=headers, json=payload, timeout=8)
        if resp.status_code == 200 and 'data' in resp.text:
            print(f"[+] GraphQL endpoint detected: {graphql_url}")
            endpoints[graphql_url] = 200
    except:
        pass

# Token Extraction
def extract_tokens_from_text(text):
    pattern = r'(?:api_key|token|access_token|auth_token|jwt)["\']?\s*[:=]\s*["\']([^"\']+)'
    return re.findall(pattern, text, re.IGNORECASE)

def scan_for_tokens():
    print("[*] Searching for hardcoded tokens...")
    links = [root_url]
    html = safe_get(root_url)
    if not html:
        return []
    soup = BeautifulSoup(html.text, 'html.parser')
    for tag in soup.find_all(["script", "link"]):
        attr = tag.get('src') or tag.get('href')
        if attr and attr.endswith(".js"):
            links.append(urljoin(root_url, attr))

    found = []
    for link in links:
        resp = safe_get(link)
        if resp and resp.text:
            toks = extract_tokens_from_text(resp.text)
            for t in toks:
                print(f"[+] Token found in {link}: {t}")
                found.append((link, t))
    return found

# Active Crawling
def extract_links(html, base_url):
    soup = BeautifulSoup(html, 'html.parser')
    urls = set()
    for tag in soup.find_all(["a", "script", "link"]):
        attr = tag.get('href') or tag.get('src')
        if attr:
            full_url = urljoin(base_url, attr)
            if urlparse(full_url).netloc == urlparse(base_url).netloc:
                urls.add(full_url)
    return urls

def extract_endpoints(text):
    patterns = [
        r'(["\'`])(/[^"\'>\s]{1,200}?)\1',
        r'(["\'`])((?:https?:)?//[^"\'>\s]+/[^"\'>\s]+)\1'
    ]
    for pattern in patterns:
        matches = re.findall(pattern, text)
        for _, match in matches:
            if any(re.search(rf'\b{k}\b', match, re.IGNORECASE) for k in KEYWORDS):
                ep_url = match if match.startswith("http") else urljoin(root_url, match)
                if ep_url not in endpoints:
                    endpoints[ep_url] = None
                    log(f"[+] Found endpoint: {ep_url}")

def crawl(url, depth=2):
    if depth == 0 or url in visited:
        return
    visited.add(url)

    html = safe_get(url)
    if not html or not html.text:
        return

    extract_endpoints(html.text)
    for link in extract_links(html.text, url):
        if BAD_EXTENSIONS.search(link): continue
        time.sleep(random.uniform(0.8, 1.8))
        crawl(link, depth - 1)

# Parallel Status Check
def check_single_endpoint(ep):
    try:
        r = requests.head(ep, headers=HEADERS(), timeout=6)
        return ep, r.status_code
    except:
        return ep, "ERR"

def check_status():
    print("[*] Checking endpoint statuses (parallel)...")
    with ThreadPoolExecutor(max_workers=12) as executor:
        results = executor.map(check_single_endpoint, endpoints.keys())
    for ep, status in results:
        endpoints[ep] = status

# CLI Entry Point
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="grAPI - Stealthy API Recon Tool")
    parser.add_argument("--url", required=True, help="Target website URL")
    parser.add_argument("--active", action="store_true", help="Perform active crawling")
    parser.add_argument("--passive", action="store_true", help="Use passive Wayback scan")
    parser.add_argument("--fingerprint", action="store_true", help="Check for WAF, robots.txt, etc.")
    parser.add_argument("--swagger", action="store_true", help="Scan for Swagger/OpenAPI")
    parser.add_argument("--graphql", action="store_true", help="Detect GraphQL endpoints")
    parser.add_argument("--tokens", action="store_true", help="Find hardcoded tokens")
    parser.add_argument("--all", action="store_true", help="Run all scans")
    parser.add_argument("--output", help="Save results to file")
    parser.add_argument("--format", default="json", choices=["json", "txt"], help="Output file format")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode")

    args = parser.parse_args()
    verbose = args.verbose
    root_url = args.url if args.url.startswith("http") else f"https://{args.url}"

    if args.all or args.passive:
        passive_wayback(root_url)
    if args.all or args.fingerprint:
        fingerprint()
    if args.all or args.active:
        crawl(root_url)
    if args.all or args.swagger:
        scan_swagger()
    if args.all or args.graphql:
        scan_graphql()
    if args.all or args.tokens:
        scan_for_tokens()

    check_status()

    print("\n[+] API Endpoints Found:")
    for ep, code in sorted(endpoints.items()):
        print(f"{ep:<60} => {code}")

    if args.output:
        with open(args.output, 'w') as f:
            if args.format == "json":
                json.dump(endpoints, f, indent=2)
            else:
                for ep, code in endpoints.items():
                    f.write(f"{ep} => {code}\n")
        print(f"[+] Results saved to {args.output}")
