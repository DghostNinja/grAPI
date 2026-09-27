from grAPI.core import (
    intercept_apis,
    install_browsers,
    load_openapi_spec,
    save_output,
    generate_postman_collection,
    MissingBrowserError,
    BANNER,
)
import argparse
import asyncio
import sys

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(
        description="Manually browse a site and capture its API endpoints."
    )
    parser.add_argument("--url", help="Target page URL")
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Page load timeout (seconds). Enter 0 for unlimited.",
    )
    parser.add_argument(
        "--scroll",
        action="store_true",
        help="Auto-scroll the page to trigger lazy-loaded content.",
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help="Run the browser without a visible window.",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=None,
        help="Stop automatically after N seconds (non-interactive mode).",
    )
    parser.add_argument(
        "--spec",
        help="OpenAPI/Swagger JSON URL to import known endpoints from.",
    )
    parser.add_argument(
        "--install-browsers",
        action="store_true",
        help="Download the Chromium browser used by grapi, then exit.",
    )
    parser.add_argument("-o", "--output", help="Output file (.json or .txt)")
    parser.add_argument(
        "-p",
        "--postman",
        help="Postman collection file (.postman.json)",
    )
    args = parser.parse_args()

    if args.install_browsers:
        sys.exit(install_browsers())
    if not args.url:
        parser.error("--url is required unless --install-browsers is used")

    extra_endpoints = load_openapi_spec(args.spec, args.url) if args.spec else {}

    try:
        endpoints = asyncio.run(
            intercept_apis(
                args.url,
                timeout=args.timeout,
                auto_scroll=args.scroll,
                headless=args.headless,
                duration=args.duration,
                extra_endpoints=extra_endpoints,
            )
        )
    except MissingBrowserError as exc:
        sys.stdout.flush()
        sys.stderr.write(f"{exc}\n")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Interrupted.")
        sys.exit(130)

    if endpoints:
        print(f"\n[+] Total API endpoints captured: {len(endpoints)}")
    else:
        print("[!] No API endpoints detected.")

    if args.output:
        save_output(endpoints, args.output)
    if args.postman:
        generate_postman_collection(endpoints, args.postman)
