# AGENTS.md

## Cursor Cloud specific instructions

### Product

**BeydaScanner** is a Python 3 CLI toolkit under `scanner_toolkits/`. There is no web server, database, Docker Compose stack, or automated test/lint suite in this repository. All scanners run in-process and write to `scanner_toolkits/logs/` and `scanner_toolkits/reports/`.

### Dependencies

Install from the repo root (see `README.md`):

```bash
pip3 install -r scanner_toolkits/requirements.txt
```

The only third-party dependency is `requests` (used by the web scanner).

### Running the application

Always run commands with `scanner_toolkits/` as the working directory so package imports resolve:

```bash
cd scanner_toolkits
python3 main.py
```

### Non-interactive / scripted usage

The CLI is menu-driven (`input()`). For automation, pipe answers on stdin.

- **Main menu exit:** `printf '4\n' | python3 main.py`
- **Port scanner (CLI args still show the port-mode submenu):** from `scanner_toolkits/`, use module form and select custom range when `range` args were passed:
  ```bash
  printf '2\n' | python3 -m scanners.port_scanner 127.0.0.1 range 22 80
  ```
  Running `python3 scanners/port_scanner.py` directly fails with `ModuleNotFoundError` because `scanners` is not on `PYTHONPATH`; prefer `python3 -m scanners.port_scanner` or `main.py`.
- **Web scanner:** needs a reachable `http:///` or `https:///` target. For local E2E, start a throwaway server (not required for the app itself):
  ```bash
  python3 -m http.server 8000
  ```
  Then scan `http://127.0.0.1:8000/` (only on hosts you are authorized to test).

### Optional scan targets

No in-repo services must be running. Meaningful scans need authorized targets (localhost, lab hosts, or public URLs). The web scanner comments mention `https://postman-echo.com/get` for external testing.

### Lint / tests

There are no `pytest`, `ruff`, `flake8`, or CI workflows configured. Verification is manual: run `main.py` or individual scanner modules as above.
