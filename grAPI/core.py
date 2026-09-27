import asyncio
import json
import os
import re
import subprocess
import sys
import threading
import urllib.request
import uuid
from urllib.parse import parse_qs, urljoin, urlparse
from playwright.async_api import async_playwright

GREEN = "\033[92m"
RESET = "\033[0m"
COLORS = {
    "GET": "\033[92m",
    "POST": "\033[93m",
    "PUT": "\033[94m",
    "PATCH": "\033[96m",
    "DELETE": "\033[95m",
    "HEAD": "\033[90m",
    "OPTIONS": "\033[90m",
    "TRACE": "\033[90m",
    "OTHER": "\033[0m",
}

HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
METHOD_ORDER = {m: i for i, m in enumerate(("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"))}
# Operation keys allowed in an OpenAPI/Swagger `paths` object.
SPEC_METHODS = frozenset(
    ("get", "put", "post", "delete", "options", "head", "patch", "trace")
)
METHOD_TOKEN_RE = re.compile(r"^[A-Z][A-Z0-9-]{1,19}$")
DEFAULT_WINDOW_SIZE = (1440, 900)


class MissingBrowserError(RuntimeError):
    """Raised when the Playwright browser binary has not been downloaded."""


BROWSER_HELP = """\
[!] The Playwright browser (Chromium) is not installed for this environment.
    Fix it by downloading it through grapi itself:

        grapi --install-browsers

    or, equivalently, with the same Python that runs grapi:

        {python} -m playwright install chromium

    Note: the Debian/Ubuntu package `node-playwright` is a different tool and
    does not provide these browsers (it fails with "onExit is not a function").
"""


def install_browsers() -> int:
    """Download the Chromium build Playwright needs, using this interpreter."""
    print(f"[*] Downloading the Playwright Chromium browser for {sys.executable} ...")
    try:
        result = subprocess.run([sys.executable, "-m", "playwright", "install", "chromium"])
    except OSError as exc:
        sys.stdout.write(f"[!] Could not run playwright installer ({exc}).\n")
        return 1
    if result.returncode == 0:
        print("[+] Browser installed. grapi is ready to use.")
    else:
        print("[!] Browser installation failed. See the output above for details.")
        print("    If shared libraries are missing, install the system packages "
              "listed in the README (Required Libraries section) and re-run.")
    return result.returncode

BANNER = f"""{GREEN}
            _   ___ ___ 
  __ _ _ _ /_\\ | _ \\_ _|
 / _` | '_/ _ \\|  _/| | 
 \\__, |_|/_/ \\_\\_| |___|
 |___/          by iPsalmy
{RESET}
"""

# Files that are never API endpoints (fonts, images, styles, scripts, media).
STATIC_ASSET_RE = re.compile(
    r"\.(?:woff2?|ttf|otf|eot|css|js|mjs|cjs|map|png|jpe?g|gif|svg|webp|avif|ico|"
    r"mp4|webm|ogv|mp3|wav|ogg|wasm)$",
    re.IGNORECASE,
)

PATH_RE = re.compile(r"(https?://[^\s'\"<>]+|/[A-Za-z0-9_\-/.{}]+)")

# Infrastructure endpoints (e.g. Cloudflare telemetry, PostHog analytics) that
# are not application APIs, even when they sit on the target's own host.
IGNORED_PATHS = (
    "/cdn-cgi/",
    "/i/v1/logs",
    "/i/v1/metrics",
    "/api/surveys/",
    "/api/web_experiments/",
    "/api/product_tours/",
    "/api/early_access_features/",
)

# Hosts that are APIs by construction (api.example.com, gql.example.com, ...).
API_HOST_RE = re.compile(r"^(?:api|api-v\d+|apis|gql|graphql|rest)[\w-]*\.", re.IGNORECASE)

# GraphQL detection: content type, JSON body ({"query": ...}) or a raw body
# that starts with an operation (query { ... }).
GRAPHQL_JSON_KEY_RE = re.compile(r"""["'](query|mutation|subscription)["']\s*:""", re.I)
GRAPHQL_RAW_START_RE = re.compile(r"""^\s*(?:query|mutation|subscription)\b""", re.I | re.S)
GRAPHQL_URL_PARAMS = frozenset({"query", "mutation", "variables", "operationname"})

# Request call sites in JavaScript: the path of a fetch/XHR/axios call is an
# API endpoint by definition, even when it carries no /api/ style keyword.
FETCH_CALL_RE = re.compile(
    r"""\bfetch\s*\(\s*['"`](?P<url>[^'"`]+)['"`]\s*(?:,\s*\{(?P<opts>[^}]{0,400})\})?""",
    re.I | re.S,
)
AXIOS_CALL_RE = re.compile(
    r"""\baxios\s*\.\s*(?P<method>get|post|put|patch|delete|head|options)\s*\(\s*['"`](?P<url>[^'"`]+)['"`]""",
    re.I,
)
XHR_OPEN_RE = re.compile(
    r"""\.open\s*\(\s*['"`](?P<method>[A-Za-z]+)['"`]\s*,\s*['"`](?P<url>[^'"`]+)['"`]"""
)
AJAX_CALL_RE = re.compile(r"""\$\.ajax\s*\(\s*\{(?P<opts>.*?)\}\s*\)""", re.I | re.S)
METHOD_RE = re.compile(r"""\b(?:type|method)\s*:\s*['"](\w+)['"]""", re.I)
AJAX_URL_RE = re.compile(r"""\burl\s*:\s*['"`]([^'"`]+)['"`]""", re.I)


def is_potential_api(url: str) -> bool:
    lowered = url.lower()
    return any(
        keyword in lowered
        for keyword in ["/api/", "/graphql", "/openapi", "/user", "/swagger", ".json"]
    ) or bool(re.search(r"/v[0-9]+(?:/|$)", lowered))


def normalize_method(method, default="GET"):
    """Upper-case and validate an HTTP method token.

    Accepts any verb-shaped token (GET, PATCH, QUERY, PROPFIND, ...) so methods
    outside the usual GET/POST/PUT/DELETE set are recorded as they are.
    """
    if not method:
        return default
    token = str(method).strip().upper()
    return token if METHOD_TOKEN_RE.match(token) else default


def method_color(method: str) -> str:
    return COLORS.get(method, COLORS["OTHER"])


def is_static_asset(url: str) -> bool:
    return bool(STATIC_ASSET_RE.search(urlparse(url).path))


def is_ignored_path(url: str) -> bool:
    path = urlparse(url).path
    return any(marker in path for marker in IGNORED_PATHS)


def is_graphql_request(url: str, post_data=None, content_type: str = "") -> bool:
    """True when a request is a GraphQL operation, whatever the URL looks like."""
    if (content_type or "").lower().startswith("application/graphql"):
        return True
    if post_data:
        body = post_data[:4000]
        if GRAPHQL_JSON_KEY_RE.search(body) or GRAPHQL_RAW_START_RE.match(body):
            return True
    query = urlparse(url).query
    if query:
        params = {key.lower() for key in parse_qs(query, keep_blank_values=True)}
        if params & GRAPHQL_URL_PARAMS:
            return True
    return False


def looks_like_api_host(url: str) -> bool:
    return bool(API_HOST_RE.match(urlparse(url).hostname or ""))


def is_api_request(
    url: str,
    resource_type: str = "",
    same_origin: bool = True,
    post_data=None,
    content_type: str = "",
) -> bool:
    """Decide whether a live request should be reported as an API endpoint.

    Same-origin XHR/fetch traffic is always reported (no keyword guessing),
    static assets and infrastructure beacons never are, and cross-origin
    traffic still has to look like an API to avoid CDN/analytics noise.
    GraphQL operations are recognised from their payload or content type even
    when the URL (e.g. POST /) carries no API keyword at all.
    """
    if is_static_asset(url) or is_ignored_path(url):
        return False
    if same_origin and resource_type in ("xhr", "fetch"):
        return True
    if is_graphql_request(url, post_data, content_type):
        return True
    if resource_type in ("xhr", "fetch") and looks_like_api_host(url):
        return True
    return is_potential_api(url)


def extract_script_calls(text: str) -> dict:
    """Return {path: METHOD} for fetch/axios/XHR/ajax call sites in JS text."""
    calls = {}
    for match in FETCH_CALL_RE.finditer(text):
        method = "GET"
        options = match.group("opts") or ""
        found = METHOD_RE.search(options)
        if found:
            method = found.group(1).upper()
        calls.setdefault(match.group("url"), method)
    for match in AXIOS_CALL_RE.finditer(text):
        calls.setdefault(match.group("url"), match.group("method").upper())
    for match in XHR_OPEN_RE.finditer(text):
        method = match.group("method").upper()
        calls.setdefault(match.group("url"), normalize_method(method))
    for match in AJAX_CALL_RE.finditer(text):
        options = match.group("opts") or ""
        url = AJAX_URL_RE.search(options)
        if not url:
            continue
        found = METHOD_RE.search(options)
        calls.setdefault(url.group(1), (found.group(1) if found else "GET").upper())
    return calls


def save_output(endpoints, filename):
    if filename.endswith(".json"):
        with open(filename, "w") as f:
            json.dump(sorted(endpoints), f, indent=2)
    else:
        with open(filename, "w") as f:
            f.write("\n".join(sorted(endpoints)))
    print(f"[+] Saved {len(endpoints)} endpoints to {filename}")


def _methods_for(endpoints, url):
    if isinstance(endpoints, dict):
        methods = endpoints.get(url) or set()
        return {m.upper() for m in methods if m} or {"GET"}
    return {"GET"}


def generate_postman_collection(endpoints, filename):
    items = []
    for url in sorted(endpoints):
        methods = sorted(
            _methods_for(endpoints, url),
            key=lambda m: METHOD_ORDER.get(m, len(METHOD_ORDER)),
        )
        postman_url = re.sub(r"\{([^}]+)\}", r":\1", url)
        for method in methods:
            items.append(
                {
                    "name": f"{method} {url}",
                    "request": {
                        "method": method,
                        "header": [],
                        "url": {"raw": postman_url},
                    },
                    "response": [],
                }
            )
    collection = {
        "info": {
            "name": "Extracted API Endpoints",
            "_postman_id": str(uuid.uuid4()),
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "item": items,
    }
    with open(filename, "w") as f:
        json.dump(collection, f, indent=2)
    print(f"[+] Saved Postman collection to {filename}")


def _fetch_json(url, timeout=20):
    request = urllib.request.Request(url, headers={"User-Agent": "grAPI"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8", "replace"))


def load_openapi_spec(spec_url, base_url, timeout=20):
    """Pull endpoints out of an OpenAPI/Swagger document.

    Returns {url: {METHOD, ...}} with relative paths resolved against the
    target site origin. Paths with parameters keep their {param} form.
    """
    try:
        spec = _fetch_json(spec_url, timeout=timeout)
    except Exception as exc:
        sys.stdout.write(f"[!] Could not load spec from {spec_url} ({exc})\n")
        sys.stdout.flush()
        return {}

    paths = spec.get("paths") or {}
    base = "{0.scheme}://{0.netloc}/".format(urlparse(base_url))
    endpoints = {}
    for path, operations in paths.items():
        if not isinstance(operations, dict) or not isinstance(path, str):
            continue
        url = urljoin(base, path)
        for key in operations:
            if key.lower() not in SPEC_METHODS:
                continue
            endpoints.setdefault(url, set()).add(key.upper())
    for url in sorted(endpoints):
        for method in sorted(
            endpoints[url],
            key=lambda m: (METHOD_ORDER.get(m, len(METHOD_ORDER)), m),
        ):
            color = method_color(method)
            sys.stdout.write(f"{color}[spec] {method}: {url}{RESET}\n")
    sys.stdout.flush()
    return endpoints


async def scan_scripts(page):
    """Scan inline page scripts and external JS files.

    Returns {"keyword": set of API-looking paths, "calls": {path: METHOD}}.
    """
    scripts = await page.evaluate(
        """() => ({
            external: Array.from(document.querySelectorAll('script[src]')).map(s => s.src),
            inline: Array.from(document.querySelectorAll('script:not([src])'))
                       .map(s => s.textContent || '')
        })"""
    )
    keyword_paths = set()
    call_paths = {}

    def scan_text(text):
        for match in PATH_RE.findall(text):
            if is_potential_api(match):
                keyword_paths.add(match)
        for path, method in extract_script_calls(text).items():
            call_paths.setdefault(path, method)

    for text in scripts.get("inline", []):
        scan_text(text)
    for js_url in scripts.get("external", []):
        try:
            content = await (await page.request.get(js_url)).text()
        except Exception:
            continue
        scan_text(content)
    return {"keyword": keyword_paths, "calls": call_paths}


async def scan_js_files(page):
    """Backwards-compatible wrapper: every API path found in page scripts."""
    data = await scan_scripts(page)
    return set(data["keyword"]) | set(data["calls"])


async def intercept_apis(
    target_url,
    timeout,
    auto_scroll=False,
    headless=False,
    duration=None,
    extra_endpoints=None,
    window_size=None,
    maximized=False,
):
    width, height = window_size or DEFAULT_WINDOW_SIZE
    apis = {}
    seen = set()
    stop_event = threading.Event()
    target_host = urlparse(target_url).netloc

    def add_endpoint(url, method, label="API detected"):
        key = (method, url)
        if key in seen:
            return False
        seen.add(key)
        apis.setdefault(url, set()).add(method)
        color = method_color(method)
        sys.stdout.write(f"{color}[{label}] {method}: {url}{RESET}\n")
        sys.stdout.flush()
        return True

    def record_js_path(url):
        if url in apis:
            return
        same_origin = not urlparse(url).netloc or urlparse(url).netloc == target_host
        if is_api_request(url, resource_type="", same_origin=same_origin):
            add_endpoint(url, "GET", label="JS-detected")

    def record_script_call(url, method):
        absolute = urljoin(target_url, url)
        if absolute in apis or is_static_asset(absolute) or is_ignored_path(absolute):
            return
        host = urlparse(absolute).netloc
        if host and host != target_host and not is_potential_api(absolute):
            return
        add_endpoint(absolute, normalize_method(method), label="JS-detected")

    for url, methods in (extra_endpoints or {}).items():
        apis.setdefault(url, set()).update(methods)
        seen.update((m, url) for m in methods)

    async with async_playwright() as p:
        launch_args = []
        if maximized:
            launch_args.append("--start-maximized")
        else:
            launch_args.append(f"--window-size={width},{height}")
        try:
            browser = await p.chromium.launch(headless=headless, args=launch_args)
        except Exception as exc:
            if "Executable doesn't exist" in str(exc) or "playwright install" in str(exc):
                raise MissingBrowserError(
                    BROWSER_HELP.format(python=sys.executable)
                ) from exc
            raise
        if headless:
            # No window to resize: use the requested size as a fixed viewport.
            context = await browser.new_context(viewport={"width": width, "height": height})
        else:
            # Let the page follow the real window size, so maximizing/resizing
            # the browser reflows the layout instead of cutting content off.
            context = await browser.new_context(no_viewport=True)

        def handle_request(request):
            url = request.url
            same_origin = urlparse(url).netloc == target_host
            try:
                post_data = request.post_data
            except Exception:
                post_data = None
            content_type = ""
            try:
                content_type = request.headers.get("content-type", "")
            except Exception:
                pass
            if is_api_request(
                url,
                request.resource_type,
                same_origin,
                post_data=post_data,
                content_type=content_type,
            ):
                add_endpoint(url, request.method.upper())

        def handle_response(response):
            try:
                content_type = (response.headers.get("content-type", "") or "").lower()
            except Exception:
                return
            if not content_type.startswith("application/graphql"):
                return
            url = response.url
            if is_static_asset(url) or is_ignored_path(url):
                return
            add_endpoint(url, response.request.method.upper())

        context.on("request", handle_request)
        context.on("response", handle_response)
        page = await context.new_page()

        def wait_for_user():
            sys.stdout.write("[*] Interactive mode — hit ENTER in terminal when you’re finished\n")
            sys.stdout.flush()
            try:
                input()
            except EOFError:
                if duration is None:
                    sys.stdout.write("[*] stdin closed — stopping capture.\n")
                    sys.stdout.flush()
                return
            stop_event.set()

        threading.Thread(target=wait_for_user, daemon=True).start()

        if duration:
            sys.stdout.write(f"[*] Auto-stop in {duration}s.\n")
            sys.stdout.flush()
            threading.Timer(duration, stop_event.set).start()

        sys.stdout.write(f"[*] Visiting {target_url}. Interact manually.\n")
        sys.stdout.flush()

        try:
            await page.goto(
                target_url,
                wait_until="domcontentloaded",
                timeout=timeout * 1000 if timeout > 0 else 0,
            )
        except Exception as e:
            sys.stdout.write(f"[!] Could not fully load page ({e}), continuing to intercept requests...\n")

        if auto_scroll:
            for _ in range(10):
                if stop_event.is_set():
                    break
                try:
                    await page.evaluate("window.scrollBy(0, document.body.scrollHeight);")
                except Exception:
                    break
                await asyncio.sleep(1)

        try:
            scripts = await scan_scripts(page)
        except Exception as exc:
            sys.stdout.write(f"[!] Could not scan page scripts ({exc}), continuing...\n")
            sys.stdout.flush()
            scripts = {"keyword": set(), "calls": {}}
        for path, method in scripts["calls"].items():
            record_script_call(path, method)
        for path in scripts["keyword"]:
            record_js_path(urljoin(target_url, path))

        while not stop_event.is_set():
            await asyncio.sleep(0.2)

        await browser.close()

    return apis
