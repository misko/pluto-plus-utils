# Embedded UI browser lane

The browser tests run the packaged FastAPI application with a deterministic fake
radio, then drive the real embedded HTML, JavaScript, HTTP API, and WebSocket using
headless Chromium.

The lane is deliberately opt-in so that the normal offline unit-test suite does not
download or require a browser:

```console
uv sync --extra dev --extra browser
uv run playwright install chromium
PLUTO_BROWSER_TESTS=1 uv run pytest -m browser tests/browser
```

The attached-radio waterfall acceptance is additionally hardware-gated. It
attaches read-only when a preview is already running, or starts and cleans up its
own non-persistent preview when the radio is ready:

```bash
PLUTO_BROWSER_TESTS=1 \
PLUTO_BROWSER_LIVE_ORIGIN=http://127.0.0.1:8765 \
PLUTO_BROWSER_LIVE_SERIAL=1040007c4a94000211000b009186843ef2 \
PLUTO_BROWSER_LIVE_URI=ip:192.168.1.165 \
uv run pytest -q tests/browser/test_live_waterfall_hardware.py
```

On a minimal Linux host or in CI, install Chromium and its operating-system
dependencies together with `uv run playwright install --with-deps chromium`.

When `PLUTO_BROWSER_TESTS=1` is set, a missing Playwright package, Chromium binary,
or required host library is a test failure with an installation hint. Without that
environment variable, browser tests are reported as skipped.
