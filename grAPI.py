#!/usr/bin/env python3
"""Thin wrapper so `python3 grAPI.py` runs the same code as the `grapi` entry point."""
import sys

try:
    from grAPI.cli import main
except ModuleNotFoundError as exc:
    if exc.name in ("playwright", "greenlet", "pyee", "typing_extensions"):
        sys.stderr.write(
            f"[!] {exc.name} is not installed for {sys.executable}.\n"
            "\n"
            "    Install grAPI in a virtual environment (recommended):\n"
            "        python3 -m venv .venv && source .venv/bin/activate\n"
            "        pip install . && grapi --install-browsers\n"
            "\n"
            "    or install it once, globally, with pipx:\n"
            "        pipx install . && grapi --install-browsers\n"
            "\n"
            "    Note: running grAPI.py with the system python3 only works if\n"
            "    playwright was installed for that interpreter.\n"
        )
        sys.exit(1)
    raise

if __name__ == "__main__":
    main()
