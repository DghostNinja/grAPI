# grAPI — Live API Discovery Tool

**grAPI** is a simple but powerful utility for pentesters and security researchers who need to discover API endpoints on websites by interacting with them in real time. It uses Playwright under the hood to launch a real browser so you can explore the target and see API calls pop up in your terminal as they happen.

---

## Contents

| Section | What it covers |
| ------- | -------------- |
| [What It Does](#what-it-does) | What grAPI captures, in bullets |
| [Installation](#installation) | Step-by-step from zero to your first scan |
| [System libraries](#system-libraries-only-if-the-browser-fails-to-start) | Only needed if the browser fails to start |
| [Troubleshooting](#troubleshooting) | Every common error message and its fix |
| [Usage](#usage) | How to run a scan |
| [Optional Arguments](#optional-arguments) | All command-line flags |
| [Example Output](#example-output) | What a finished run looks like |
| [How Endpoints Are Detected](#how-endpoints-are-detected) | The rules used to decide what counts as an API |


---

## What It Does

This tool:

* Opens your target URL in a real browser so you can click around just like a user.
* Captures any API endpoints the page hits via XHR, Fetch or other network calls — every same-origin XHR/fetch request is reported, no keyword guessing needed.
* Scans loaded JavaScript files **and inline page scripts** for hidden API paths, including `fetch()`, `axios.*`, `XMLHttpRequest.open()` and `$.ajax()` call sites (with their HTTP method when one is specified).
* Filters out static assets (fonts, images, CSS, JS, media) and infrastructure beacons such as Cloudflare's `/cdn-cgi/` so the output stays free of noise.
* Gives you color coded output instantly so you don’t have to wait.
* Lets you save the endpoints in a simple txt or json file.
* Generates a Postman collection with the real HTTP methods for easy import into Postman or Burp.
* Can import known endpoints straight from an OpenAPI/Swagger document (`--spec`).
* Can run headless and stop itself after a fixed duration, so it works in scripts and CI.

---

## Why It’s Useful

Unlike traditional scanners that only look at source code, grAPI listens to actual traffic as you use the page. That means it catches dynamic APIs that appear after a click, form submit or other interaction.

And because you do the browsing yourself, you control exactly which parts of the app you want to explore. The output is kept clean and minimal so you can jump straight into testing.

---

## Installation

grAPI needs three things:

1. **Python 3.10+** — the language it's written in
2. **grAPI itself** — installed with `pipx` (recommended) or in a virtual environment
3. **A Chromium browser** — downloaded once for you by `grapi --install-browsers`

No idea what those are? The [What did I just install?](#what-did-i-just-install) box at
the end of this section explains them in plain words. If anything fails, jump to
[Troubleshooting](#troubleshooting) — every error message is listed there.

---

### Step 0 — Check your prerequisites

Open a terminal and run:

```bash
python3 --version     # should print Python 3.10 or newer
git --version         # should print git version ...
pipx --version        # should print pipx ...
```

Missing `git` or `pipx`? Install them:

```bash
sudo apt update && sudo apt install -y git pipx    # Debian/Ubuntu
brew install git pipx                             # macOS
```

> On Debian/Ubuntu, if `python3 -m venv` later fails with
> `No module named venv` / `ensurepip is not available`, also run:
> `sudo apt install -y python3-venv`

---

### Step 1 — Download the source code

```bash
git clone https://github.com/DghostNinja/grAPI.git
cd grAPI
```

You must be inside this `grAPI` folder for the next steps — every command below is
run from there.

---

### Step 2 — Install grAPI (pick **one** of the two options)

#### Option A — pipx (recommended, no virtual environment to manage)

```bash
pipx install .
```

This installs the `grapi` command, available anywhere in your terminal.

#### Option B — virtual environment (standard Python way)

```bash
python3 -m venv .venv      # create an isolated environment (once)
source .venv/bin/activate  # switch into it — run this in EVERY new terminal
pip install .              # install grAPI inside it
```

While the venv is active your prompt usually shows `(.venv)` at the start.
Type `deactivate` to leave it.

Windows activation instead:

```powershell
.venv\Scripts\activate        # cmd
.venv\Scripts\Activate.ps1    # PowerShell
```

> If `pip install` stops you with `error: externally-managed-environment` or
> `Permission denied`, you skipped the venv — go with Option A or Option B.
> Never use `sudo pip install` (it can break your system Python).

---

### Step 3 — Download the browser (one time only)

```bash
grapi --install-browsers
```

This downloads Chromium (about 130 MB) into `~/.cache/ms-playwright`, where every
future run reuses it. You only ever do this once per machine.

> If you used **Option B** and get `grapi: command not found`, either activate the
> venv first (`source .venv/bin/activate`) or run it as `.venv/bin/grapi --install-browsers`.

---

### Step 4 — First run (verify the install)

```bash
grapi --url https://vulnbank.org/ --headless --duration 20
```

What you should see: a grAPI banner, then lines like
`[API detected] GET: https://vulnbank.org/...` as endpoints are found, and finally
`[+] Total API endpoints captured: N`.

If you see that, you're done — go to [Usage](#usage).

---

### Quick install (for the impatient)

```bash
git clone https://github.com/DghostNinja/grAPI.git && cd grAPI
pipx install .
grapi --install-browsers
grapi --url https://vulnbank.org/ --headless --duration 20
```

---

### Other ways to install

- **From PyPI**, inside a virtual environment (Installation, Option B):

  ```bash
  pip install grapix
  ```

  Only do this if `grapi --help` lists `--install-browsers`. If it doesn't, the
  published package is older than this README — install from source (Step 1 + 2) instead.

- **From PyPI with pipx:**

  ```bash
  pipx install grapix     # same caveat as above
  ```

---

### Optional: add `grapi` to your PATH

Only needed if `grapi: command not found` after an install (common with pipx):

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc      # or: source ~/.zshrc
```

Then open a new terminal and try `grapi --help`.

---

### What did I just install?

| Thing        | Plain-language explanation                                                                 |
| ------------ | ------------------------------------------------------------------------------------------ |
| `python3`    | The programming language grAPI is written in. grAPI does not work without it.               |
| `pip`        | Python's package installer (`pip install something`).                                       |
| `pipx`       | Installs Python tools as isolated commands on your PATH, so they never clash with other Python projects. Recommended for end users. |
| `venv`       | A private Python environment living inside the project folder (`.venv`). Use it when you don't want or can't use pipx. |
| `playwright` | The Python library grAPI uses to drive a real browser. It comes with grAPI automatically — you don't install it separately. |
| `--install-browsers` | Downloads the actual Chromium browser binary that Playwright drives. One-time, ~130 MB. |
| `node-playwright` | **Not this project.** An unrelated Ubuntu package. Do not install it — see Troubleshooting. |

---

## System libraries (only if the browser fails to start)

You can skip this section unless an error mentions a missing library, e.g.
`error while loading shared libraries: libnss3.so: cannot open shared object file`,
or the browser exits immediately.

On Debian/Ubuntu, install them with:

```bash
sudo apt update && sudo apt install -y \
    libicu-dev \
    libjpeg-dev \
    libwebp-dev \
    libffi-dev \
    libnss3 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libxcomposite1 \
    libxdamage1 \
    libxrandr2 \
    libgbm1 \
    libpango-1.0-0 \
    libcairo2 \
    libasound2t64 \
    libxss1 \
    libxtst6
```

(`libasound2` on older Ubuntu releases.) Then re-run `grapi --install-browsers`.

On macOS and Windows these libraries are not needed — Playwright installs what it needs.

---

## Troubleshooting

Find your error message below, then run the command shown under it.

| If you see... | Go to |
| --- | --- |
| `ModuleNotFoundError: No module named 'playwright'` | [1](#1-no-module-named-playwright) |
| `grapi: command not found` | [2](#2-grapi-command-not-found) |
| `playwright: command not found` / `onExit is not a function` | [3](#3-playwright-command-not-found) |
| `Executable doesn't exist at .../chromium-...` | [4](#4-executable-does-not-exist) |
| `error while loading shared libraries: lib....so` | [5](#5-missing-shared-libraries) |
| Nothing happens / no browser window appears | [6](#6-no-browser-window) |
| The scan seems to hang after loading the page | [7](#7-scan-seems-to-hang) |
| Page layout is cut off / ignores the window size | [8](#8-page-layout-cut-off) |

#### 1. No module named playwright

```text
ModuleNotFoundError: No module named 'playwright'
```

Your system `python3` doesn't have grAPI's dependencies. Install grAPI first —
with `pipx install .` (Installation, Option A) or inside a virtual environment
(Installation, Option B) — then run the `grapi` command instead of
`python3 grAPI.py`. Running `python3 grAPI.py` only works inside an environment
where `pip install .` was done.

#### 2. grapi command not found

```text
grapi: command not found
```

The folder with the `grapi` command is not in your PATH. Run:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc
```

Still nothing? If you installed with Option B (venv), activate it first:
`source .venv/bin/activate`.

#### 3. playwright command not found

```text
playwright: command not found
# or:
TypeError: onExit is not a function
```

Do **not** install the Debian/Ubuntu package `node-playwright`: it is an unrelated
Node.js project that shadows the Python CLI and is broken on recent Ubuntu. Remove it
and download the browser through grapi instead:

```bash
sudo apt remove node-playwright
grapi --install-browsers
```

#### 4. Executable does not exist

```text
Executable doesn't exist at .../chromium-...
```

The browser binaries were never downloaded for the environment grapi runs from:

```bash
grapi --install-browsers
# equivalent: <the python running grapi> -m playwright install chromium
```

Browsers are stored once per user in `~/.cache/ms-playwright` and are shared by all
virtual environments, so you only ever need to download them once.

#### 5. Missing shared libraries

```text
error while loading shared libraries: libnss3.so: cannot open shared object file
```

Install the packages from the *System libraries* section above, then re-run
`grapi --install-browsers`.

#### 6. No browser window

- Working over SSH or on a server without a screen? Add `--headless`:

  ```bash
  grapi --url https://targetsite.com --headless --duration 30
  ```

- Still nothing? Run `grapi --install-browsers` again and read any error it prints.

#### 7. Scan seems to hang

That's normal: grAPI is waiting for you to browse the page. Stop it by pressing
**Enter** in the terminal, or run with a timer so it stops by itself:

```bash
grapi --url https://targetsite.com --duration 30
```

#### 8. Page layout cut off

Older grAPI builds pinned the page to a fixed 1280x720 viewport, so maximizing the
window did nothing and content stayed cut off. Update to the current version:

```bash
pipx install --force .        # inside your grAPI folder (or: pip install . in your venv)
```

Then the window resizes normally, or start it at the size you want:

```bash
grapi --url https://targetsite.com --maximized
grapi --url https://targetsite.com --window-size 1920x1080
```

---

## Usage

Interactive mode — a window opens, you browse like a normal user, grAPI prints the
endpoints it sees:

```bash
grapi --url https://targetsite.com -o apis.txt -p apis.postman.json
```

This will:

1. Launch the browser and open the target.
2. Print API endpoints as they happen — color coded by HTTP method.
3. Save them into a file (`apis.txt`) and a Postman collection (`apis.postman.json`).

When you’re done exploring the app, hit **Enter** in your terminal to stop the scan.

The browser window is fully resizable: maximize it, restore it, or drag it to another
monitor and the page reflows to match (grAPI does not force a fixed 1280x720 viewport,
so nothing gets cut off). You can also pick a size up front:

```bash
grapi --url https://targetsite.com --window-size 1920x1080   # specific size
grapi --url https://targetsite.com --maximized               # start maximized
```

Prefer to run it from the script instead of the installed command? This works too
(only inside the project folder, and only if grAPI's dependencies are installed for
your Python):

```bash
python3 grAPI.py --url https://targetsite.com -o apis.txt -p apis.postman.json
```

For a non-interactive run (CI, scripts, headless servers), let it stop itself:

```bash
grapi --url https://targetsite.com --headless --duration 30 -o apis.txt -p apis.postman.json
```

If the target publishes an OpenAPI/Swagger document, import it alongside the live traffic:

```bash
grapi --url https://vulnbank.org/ --spec https://vulnbank.org/static/openapi.json \
      --headless --duration 30 -o apis.txt -p apis.postman.json
```

---

## Optional Arguments

| Argument    | Description                                                                  |
| ----------- | ---------------------------------------------------------------------------- |
| `--url`     | Target page URL                                                              |
| `--timeout` | Page load timeout in seconds. `0` disables timeout                           |
| `--scroll`  | Automatically scrolls the page to trigger more API calls                     |
| `--headless`| Run the browser without a visible window                                     |
| `--window-size` | Browser window size as `WxH` (default `1440x900`). In headless mode it sets the page viewport. |
| `--maximized`| Start the browser window maximized (windowed mode only)                     |
| `--duration`| Stop automatically after N seconds instead of waiting for ENTER              |
| `--spec`    | OpenAPI/Swagger JSON URL; its endpoints are merged with the captured ones    |
| `--install-browsers` | One-time setup: download the Chromium browser, then exit (no `--url` needed) |
| `-o`        | Output filename for saving endpoints (txt or json)                           |
| `-p`        | Export captured endpoints as a Postman collection file                       |

---

## Example Output

```bash
[API detected] POST: http://crapi.apisec.ai/identity/api/auth/forget-password
[API detected] GET: http://crapi.apisec.ai/shop/api/products
[JS-detected] POST: https://targetsite.com/login
[JS-detected] GET: https://targetsite.com/user/profile/update-profile-picture/
[spec] GET: https://vulnbank.org/api/transactions
```

After hitting Enter:

```bash
[+] Total API endpoints captured: 3
[+] Saved 3 endpoints to apis.txt
[+] Saved Postman collection to apis.postman.json
```

---

## How Endpoints Are Detected

| Source                | Rule                                                                 |
| --------------------- | -------------------------------------------------------------------- |
| Live traffic          | Every same-origin `xhr`/`fetch` request                              |
| Live traffic          | Cross-origin requests that look like an API (`/api/`, `/v1/`, `.json`, `/graphql`, ...) |
| Live traffic          | GraphQL operations — detected from the payload (`{"query": ...}` / `query { ... }`), `application/graphql*` content type or a `?query=` URL, even when the path has no API keyword |
| Live traffic          | XHR/fetch to API hosts such as `api.example.com`, `gql.example.com`  |
| Page scripts          | `fetch()` / `axios.*` / `XHR.open()` / `$.ajax()` call sites (method included) |
| Page scripts          | Any API-looking path string in inline or external JavaScript         |
| `--spec`              | Every operation listed in the OpenAPI/Swagger document               |

Static assets (fonts, images, CSS, JS, media) and infrastructure endpoints
(`/cdn-cgi/`, PostHog telemetry paths) are never reported.

**Every HTTP method is recorded** — not just GET/POST/PUT/DELETE: PATCH, HEAD,
OPTIONS, TRACE, GraphQL's `QUERY`, WebDAV verbs like `PROPFIND`, and any other verb
the page sends all appear in the output and in the Postman collection with their
real method.

| Method     | Colour  |
| ---------- | ------- |
| `GET`      | green   |
| `POST`     | yellow  |
| `PUT`      | blue    |
| `PATCH`    | cyan    |
| `DELETE`   | magenta |
| `HEAD` / `OPTIONS` / `TRACE` | grey |

---

## Tests

The test suite needs `pytest`, installed inside your virtual environment
(Installation, Option B):

```bash
source .venv/bin/activate   # if not already active
pip install pytest
make test
```

Without `make`, run `pytest tests/` directly.

---

## License

This project is licensed under the terms of the [MIT License](LICENSE). You are free to use, modify, and distribute it as needed.

---

## Contribute

If you’ve got feature ideas or improvements, feel free to open an issue or send a pull request.

That’s it. Have fun breaking things and stay curious.

Made with ☕ by [iPsalmy](https://github.com/DghostNinja)
