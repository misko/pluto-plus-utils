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

On a minimal Linux host or in CI, install Chromium and its operating-system
dependencies together with `uv run playwright install --with-deps chromium`.

When `PLUTO_BROWSER_TESTS=1` is set, a missing Playwright package, Chromium binary,
or required host library is a test failure with an installation hint. Without that
environment variable, browser tests are reported as skipped.
