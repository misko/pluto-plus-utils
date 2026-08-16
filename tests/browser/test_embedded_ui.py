"""Playwright acceptance flow through the real embedded web application."""

from __future__ import annotations

import time
from typing import Any

import pytest

pytestmark = pytest.mark.browser


def _wait_for_api_collection(
    page: Any,
    path: str,
    *,
    timeout: float = 10,
) -> list[dict[str, Any]]:
    deadline = time.monotonic() + timeout
    last_status: int | None = None
    while time.monotonic() < deadline:
        response = page.request.get(path)
        last_status = response.status
        if response.ok:
            document = response.json()
            if isinstance(document, list) and document:
                return document
        time.sleep(0.05)
    pytest.fail(f"{path} stayed empty or unhealthy (last HTTP status: {last_status})")


def _canvas_has_rendered_pixels(page: Any, selector: str) -> bool:
    return bool(
        page.locator(selector).evaluate(
            """canvas => {
              const context = canvas.getContext("2d");
              const pixels = context.getImageData(0, 0, canvas.width, canvas.height).data;
              for (let index = 0; index < pixels.length; index += 4) {
                if (pixels[index] || pixels[index + 1] || pixels[index + 2]) return true;
              }
              return false;
            }"""
        )
    )


def test_complete_fake_radio_browser_workflow(browser_page: Any, fake_daemon_origin: str) -> None:
    page = browser_page
    javascript_errors: list[str] = []
    console_errors: list[str] = []
    page.on("pageerror", lambda error: javascript_errors.append(str(error)))
    page.on(
        "console",
        lambda message: console_errors.append(message.text) if message.type == "error" else None,
    )

    response = page.goto(fake_daemon_origin, wait_until="networkidle")
    assert response is not None and response.ok
    page.locator("#radio-state").wait_for(state="visible")
    page.wait_for_function("document.querySelector('#radio-state').textContent === 'ready'")
    assert page.locator("#radio-select").input_value() == "fake-001"
    assert page.locator("#radio-serial").text_content() == "fake-001"
    assert page.locator("#radio-transport").text_content() == "fake"
    assert page.locator("#radio-revision").text_content() == "0"

    # Prove the form uses optimistic revisions: mutate through another client, submit
    # the stale form, observe a 409/reload, then apply and verify hardware read-back.
    external = page.request.patch(
        f"{fake_daemon_origin}/api/v1/radios/fake-001/settings",
        data={"expected_revision": 0, "center_frequency_hz": 920_000_000},
    )
    assert external.ok
    page.locator("#center-frequency").fill("921250000")
    with page.expect_response(
        lambda reply: reply.request.method == "PATCH"
        and reply.url.endswith("/api/v1/radios/fake-001/settings")
    ) as stale_submission:
        page.locator("#apply-settings").click()
    assert stale_submission.value.status == 409
    page.wait_for_function("document.querySelector('#radio-revision').textContent === '1'")
    expected_conflicts = [message for message in console_errors if "409 (Conflict)" in message]
    assert len(expected_conflicts) == 1
    console_errors.clear()

    page.locator("#center-frequency").fill("921250000")
    with page.expect_response(
        lambda reply: reply.request.method == "PATCH"
        and reply.url.endswith("/api/v1/radios/fake-001/settings")
    ) as applied_submission:
        page.locator("#apply-settings").click()
    assert applied_submission.value.status == 200
    page.wait_for_function("document.querySelector('#radio-revision').textContent === '2'")
    assert "921.250 MHz" in page.locator("#requested-settings").inner_text()
    assert "921.250 MHz" in page.locator("#actual-settings").inner_text()

    # Exercise the real WebSocket and require evidence that a frame reached both the
    # metadata view and canvas renderer, rather than merely opening a connection.
    assert page.locator("#fft-size").input_value() == "512"
    page.locator("#fft-size").select_option("1024")
    page.locator("#start-preview").click()
    page.wait_for_function(
        "document.querySelector('#frame-metadata').textContent.includes('Frame ')"
    )
    page.wait_for_function("document.querySelector('#rx0-level').textContent.includes('dB peak')")
    page.wait_for_function("document.querySelector('#rx1-level').textContent.includes('dB peak')")
    assert _canvas_has_rendered_pixels(page, "#spectrum-canvas")
    assert _canvas_has_rendered_pixels(page, "#waterfall-rx0")
    assert _canvas_has_rendered_pixels(page, "#waterfall-rx1")
    canvas_sizes = page.evaluate(
        """() => Object.fromEntries(
          ['spectrum-canvas', 'waterfall-rx0', 'waterfall-rx1'].map(id => {
            const canvas = document.getElementById(id);
            return [id, {
              pixels: [canvas.width, canvas.height],
              css: [canvas.clientWidth, canvas.clientHeight],
            }];
          })
        )"""
    )
    assert canvas_sizes["spectrum-canvas"]["css"][1] <= 56
    assert canvas_sizes["spectrum-canvas"]["pixels"][0] <= 1_024
    assert canvas_sizes["waterfall-rx0"]["css"][1] >= 280
    assert canvas_sizes["waterfall-rx1"]["css"][1] >= 280
    assert canvas_sizes["waterfall-rx0"]["pixels"][0] <= 1_024
    assert canvas_sizes["waterfall-rx1"]["pixels"][0] <= 1_024
    page.locator("#stop-preview").click()
    page.wait_for_function("document.querySelector('#radio-state').textContent === 'ready'")

    # Persist a genuinely bounded capture, then select its artifact and run an
    # analyzer through the browser UI.
    page.locator("#capture-duration").fill("0.1")
    page.locator("#capture-label").fill("browser acceptance capture")
    page.locator("#start-capture").click()
    artifacts = _wait_for_api_collection(page, f"{fake_daemon_origin}/api/v1/artifacts")
    artifact_id = artifacts[0]["artifact_id"]
    page.locator("#refresh-artifacts").click()
    page.wait_for_function(
        "artifactId => Array.from(document.querySelector('#analysis-artifact').options)"
        ".some(option => option.value === artifactId)",
        arg=artifact_id,
    )
    page.locator("#analysis-artifact").select_option(artifact_id)
    page.locator("#analyzer-select").select_option("spectrum")
    page.locator("#analysis-parameters").fill('{"fft_size": 256}')
    page.locator("#run-analysis").click()
    page.wait_for_function(
        "document.querySelector('#analysis-summary').textContent.startsWith('spectrum v')"
    )
    assert '"fft_size": 256' in page.locator("#analysis-result").inner_text()

    # Refresh state after the bounded capture, run a short exclusive sweep, and
    # wait for its persisted result to appear in the actual results table.
    page.locator("#refresh-radios").click()
    page.wait_for_function("document.querySelector('#radio-state').textContent === 'ready'")
    page.locator("#scan-start").fill("900000000")
    page.locator("#scan-stop").fill("902000000")
    page.locator("#scan-step").fill("1000000")
    page.locator("#scan-samples").fill("1024")
    page.locator("#start-scan").click()
    scans = _wait_for_api_collection(page, f"{fake_daemon_origin}/api/v1/scans")
    scan_id = scans[0]["scan_id"]
    assert len(scans[0]["points"]) == 3
    page.wait_for_function(
        "scanId => document.querySelector('#scans-body').textContent.includes(scanId.slice(0, 12))",
        arg=scan_id,
        timeout=10_000,
    )

    # No privileged firmware helper was composed for this daemon; the UI must say
    # so and prevent either planning or execution.
    assert (
        page.locator("#firmware-availability").text_content()
        == "Privileged helper not configured"
    )
    assert page.locator("#firmware-fieldset").evaluate("fieldset => fieldset.disabled") is True
    assert page.locator("#execute-firmware").is_disabled()
    assert javascript_errors == []
    assert console_errors == []
