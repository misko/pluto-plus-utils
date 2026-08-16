"""Attached-radio browser acceptance for a populated dual-RX waterfall."""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest

pytestmark = [pytest.mark.browser, pytest.mark.hardware]

_ORIGIN_ENV = "PLUTO_BROWSER_LIVE_ORIGIN"
_SERIAL_ENV = "PLUTO_BROWSER_LIVE_SERIAL"
_URI_ENV = "PLUTO_BROWSER_LIVE_URI"
_MINIMUM_ROWS = 50


def _live_target() -> tuple[str, str, str]:
    origin = os.environ.get(_ORIGIN_ENV, "").rstrip("/")
    serial = os.environ.get(_SERIAL_ENV, "").strip()
    uri = os.environ.get(_URI_ENV, "").strip()
    if not origin or not serial or not uri:
        pytest.skip(
            f"set {_ORIGIN_ENV}, {_SERIAL_ENV}, and {_URI_ENV} to run the attached-radio test"
        )
    return origin, serial, uri


def _install_row_counter(page: Any) -> None:
    page.evaluate(
        """() => {
          window.__waterfallRows = {'waterfall-rx0': 0, 'waterfall-rx1': 0};
          const original = CanvasRenderingContext2D.prototype.putImageData;
          CanvasRenderingContext2D.prototype.putImageData = function(...args) {
            if (Object.hasOwn(window.__waterfallRows, this.canvas.id)) {
              window.__waterfallRows[this.canvas.id] += 1;
            }
            return original.apply(this, args);
          };
        }"""
    )


def _waterfall_statistics(page: Any) -> dict[str, dict[str, float]]:
    return page.evaluate(
        """minimumRows => {
          const summarize = id => {
            const canvas = document.getElementById(id);
            const rows = Math.min(minimumRows, canvas.height);
            const data = canvas.getContext('2d')
              .getImageData(0, 0, canvas.width, rows).data;
            let nonBlack = 0;
            let opaque = 0;
            let minimum = 255;
            let maximum = 0;
            let sum = 0;
            let sumSquares = 0;
            const colors = new Set();
            const rowMeans = [];
            for (let y = 0; y < rows; y += 1) {
              let rowSum = 0;
              for (let x = 0; x < canvas.width; x += 1) {
                const offset = (y * canvas.width + x) * 4;
                const red = data[offset];
                const green = data[offset + 1];
                const blue = data[offset + 2];
                const alpha = data[offset + 3];
                const luminance = (red + green + blue) / 3;
                if (red || green || blue) nonBlack += 1;
                if (alpha === 255) opaque += 1;
                minimum = Math.min(minimum, luminance);
                maximum = Math.max(maximum, luminance);
                sum += luminance;
                sumSquares += luminance * luminance;
                rowSum += luminance;
                colors.add(`${red >> 3},${green >> 3},${blue >> 3}`);
              }
              rowMeans.push(rowSum / canvas.width);
            }
            let adjacentDifference = 0;
            for (let index = 1; index < rowMeans.length; index += 1) {
              adjacentDifference += Math.abs(rowMeans[index] - rowMeans[index - 1]);
            }
            const pixels = canvas.width * rows;
            const mean = sum / pixels;
            return {
              width: canvas.width,
              height: canvas.height,
              cssHeight: canvas.clientHeight,
              populatedRows: rows,
              renderedRows: window.__waterfallRows[id],
              nonBlackRatio: nonBlack / pixels,
              opaqueRatio: opaque / pixels,
              quantizedColors: colors.size,
              luminanceRange: maximum - minimum,
              luminanceStdDev: Math.sqrt(sumSquares / pixels - mean * mean),
              adjacentRowDifference:
                adjacentDifference / Math.max(1, rowMeans.length - 1),
            };
          };
          return {
            rx0: summarize('waterfall-rx0'),
            rx1: summarize('waterfall-rx1'),
          };
        }""",
        _MINIMUM_ROWS,
    )


@contextmanager
def _waterfall_connection(page: Any, radio_id: str, initial_state: str) -> Iterator[None]:
    started_by_test = initial_state == "ready"
    if started_by_test:
        page.locator("#start-preview").click()
    elif initial_state == "streaming":
        # Loading a page mid-stream must attach a read-only subscriber itself.
        # Do not cancel a stream that may belong to another operator.
        page.wait_for_function(
            "window.plutoDiagnostics().waterfall.socketState === 'open'",
            timeout=10_000,
        )
    else:
        pytest.fail(f".15 must be ready or streaming, not {initial_state!r}")
    try:
        yield
    finally:
        if started_by_test:
            page.locator("#stop-preview").click()
            page.wait_for_function(
                "document.querySelector('#radio-state').textContent === 'ready'",
                timeout=10_000,
            )
        else:
            page.evaluate("disconnectWaterfall()")


def test_attached_radio_waterfall_populates_fifty_reasonable_rows(chromium: Any) -> None:
    origin, serial, expected_uri = _live_target()
    context = chromium.new_context(viewport={"width": 1440, "height": 1100})
    page = context.new_page()
    page_errors: list[str] = []
    console_errors: list[str] = []
    page.on("pageerror", lambda error: page_errors.append(str(error)))
    page.on(
        "console",
        lambda message: console_errors.append(message.text) if message.type == "error" else None,
    )
    try:
        response = page.goto(origin, wait_until="networkidle", timeout=10_000)
        assert response is not None and response.ok
        inventory = page.request.get(f"{origin}/api/v1/radios")
        assert inventory.ok
        targets = [item for item in inventory.json() if item["identity"]["serial"] == serial]
        assert len(targets) == 1
        assert targets[0]["identity"]["uri"] == expected_uri
        assert targets[0]["managed"] is True

        page.locator("#radio-select").select_option(serial)
        page.wait_for_function(
            "selected => document.querySelector('#radio-serial').textContent === selected",
            arg=serial,
            timeout=10_000,
        )
        initial_state = page.locator("#radio-state").inner_text()
        _install_row_counter(page)
        with _waterfall_connection(page, serial, initial_state):
            page.wait_for_function(
                "minimum => Object.values(window.__waterfallRows).every(count => count >= minimum)",
                arg=_MINIMUM_ROWS,
                timeout=15_000,
            )
            statistics = _waterfall_statistics(page)

        for receiver in ("rx0", "rx1"):
            measured = statistics[receiver]
            assert measured["renderedRows"] >= _MINIMUM_ROWS
            assert measured["populatedRows"] == _MINIMUM_ROWS
            assert 280 <= measured["cssHeight"] <= 360
            assert measured["height"] == measured["cssHeight"]
            assert 200 <= measured["width"] <= 1_024
            assert measured["nonBlackRatio"] >= 0.95
            assert measured["opaqueRatio"] >= 0.99
            assert measured["quantizedColors"] >= 16
            assert measured["luminanceRange"] >= 40
            assert measured["luminanceStdDev"] >= 5
            assert measured["adjacentRowDifference"] >= 0.1
        assert page_errors == []
        assert console_errors == []
    finally:
        context.close()
