"""Opt-in fixtures for genuine browser tests of the embedded application."""

from __future__ import annotations

import os
import socket
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.error import URLError
from urllib.request import urlopen

import pytest
import uvicorn

from pluto_plus.api import create_app
from pluto_plus.hardware.fake import FakeRadioDevice
from pluto_plus.service import PlutoService

if TYPE_CHECKING:
    from playwright.sync_api import Browser, Playwright


_BROWSER_ENVIRONMENT = "PLUTO_BROWSER_TESTS"


def _browser_lane_enabled() -> bool:
    return os.environ.get(_BROWSER_ENVIRONMENT, "").strip().lower() in {"1", "true", "yes"}


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Keep normal pytest runs independent of Playwright and browser downloads."""

    if _browser_lane_enabled():
        return
    skip = pytest.mark.skip(
        reason=f"set {_BROWSER_ENVIRONMENT}=1 to run the explicit Playwright lane"
    )
    for item in items:
        if item.get_closest_marker("browser") is not None:
            item.add_marker(skip)


@pytest.fixture(scope="session")
def playwright_runtime() -> Iterator[Playwright]:
    if not _browser_lane_enabled():
        pytest.skip(f"set {_BROWSER_ENVIRONMENT}=1 to run browser tests")
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.fail(
            "the browser lane is enabled but Playwright is not installed; "
            "run `uv sync --extra dev --extra browser`",
            pytrace=False,
        )

    try:
        runtime = sync_playwright().start()
    except PlaywrightError as error:
        pytest.fail(f"could not start Playwright: {error}", pytrace=False)
    try:
        yield runtime
    finally:
        runtime.stop()


@pytest.fixture(scope="session")
def chromium(playwright_runtime: Playwright) -> Iterator[Browser]:
    try:
        browser = playwright_runtime.chromium.launch(headless=True)
    except Exception as error:
        pytest.fail(
            "the browser lane is enabled but Chromium could not launch; "
            "run `uv run playwright install chromium` (or `install --with-deps chromium` "
            f"when host libraries are absent). Original error: {error}",
            pytrace=False,
        )
    try:
        yield browser
    finally:
        browser.close()


def _unused_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _wait_for_daemon(origin: str, thread: threading.Thread, timeout: float = 10) -> None:
    deadline = time.monotonic() + timeout
    last_error: BaseException | None = None
    while time.monotonic() < deadline:
        if not thread.is_alive():
            pytest.fail("the browser-test daemon exited before becoming ready", pytrace=False)
        try:
            with urlopen(f"{origin}/api/v1/health", timeout=0.25) as response:  # noqa: S310
                if response.status == 200:
                    return
        except (OSError, URLError) as error:
            last_error = error
        time.sleep(0.025)
    pytest.fail(f"browser-test daemon did not become ready: {last_error}", pytrace=False)


@pytest.fixture
def fake_daemon_origin(tmp_path: Path) -> Iterator[str]:
    """Serve the genuine ASGI app over loopback with one realtime fake radio."""

    service = PlutoService(
        tmp_path / "state",
        (FakeRadioDevice(serial="fake-001", realtime=True, firmware_capable=True),),
    )
    port = _unused_loopback_port()
    origin = f"http://127.0.0.1:{port}"
    config = uvicorn.Config(
        create_app(service),
        host="127.0.0.1",
        port=port,
        log_level="warning",
        access_log=False,
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, name="browser-test-plutod", daemon=True)
    thread.start()
    _wait_for_daemon(origin, thread)
    try:
        yield origin
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        if thread.is_alive():
            pytest.fail("browser-test daemon did not stop cleanly", pytrace=False)


@pytest.fixture
def browser_page(chromium: Browser, fake_daemon_origin: str) -> Iterator[Any]:
    # Depending on the daemon here guarantees that the browser context (and its
    # WebSocket) closes before Uvicorn is asked to shut down.
    context = chromium.new_context(
        base_url=fake_daemon_origin,
        viewport={"width": 1440, "height": 1100},
    )
    page = context.new_page()
    try:
        yield page
    finally:
        context.close()
