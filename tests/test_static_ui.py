"""Low-cost contract and safety checks for the dependency-free embedded UI."""

from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path

STATIC_ROOT = Path(__file__).parents[1] / "src" / "pluto_plus" / "static"


class UiDocumentParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: set[str] = set()
        self.labels_for: set[str] = set()
        self.disabled_ids: set[str] = set()
        self.canvas_labels: dict[str, str] = {}
        self.scripts: list[str] = []
        self.stylesheets: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        element_id = attributes.get("id")
        if element_id:
            self.ids.add(element_id)
            if "disabled" in attributes:
                self.disabled_ids.add(element_id)
        if tag == "label" and attributes.get("for"):
            self.labels_for.add(str(attributes["for"]))
        if tag == "canvas" and element_id:
            self.canvas_labels[element_id] = str(attributes.get("aria-label", ""))
        if tag == "script" and attributes.get("src"):
            self.scripts.append(str(attributes["src"]))
        if tag == "link" and attributes.get("rel") == "stylesheet":
            self.stylesheets.append(str(attributes.get("href", "")))


def _assets() -> tuple[str, str, str, UiDocumentParser]:
    html = (STATIC_ROOT / "index.html").read_text()
    javascript = (STATIC_ROOT / "app.js").read_text()
    css = (STATIC_ROOT / "styles.css").read_text()
    parser = UiDocumentParser()
    parser.feed(html)
    return html, javascript, css, parser


def test_embedded_assets_exist_and_are_linked_from_index() -> None:
    html, javascript, css, parser = _assets()

    assert html.startswith("<!doctype html>")
    assert javascript.startswith('"use strict";')
    assert ":root" in css
    assert parser.scripts == ["/static/app.js"]
    assert parser.stylesheets == ["/static/styles.css"]


def test_ui_exposes_required_radio_settings_and_capture_controls() -> None:
    _, _, _, parser = _assets()
    required_ids = {
        "radio-select",
        "radio-state",
        "radio-serial",
        "radio-transport",
        "radio-firmware",
        "recover-radio",
        "requested-settings",
        "actual-settings",
        "settings-form",
        "center-frequency",
        "sample-rate",
        "bandwidth",
        "gain-mode",
        "gain-db",
        "start-preview",
        "stop-preview",
        "capture-form",
        "capture-duration",
        "capture-label",
        "jobs-body",
    }

    assert required_ids <= parser.ids
    assert {
        "radio-select",
        "center-frequency",
        "sample-rate",
        "bandwidth",
        "gain-mode",
        "gain-db",
        "capture-duration",
        "capture-label",
    } <= parser.labels_for


def test_ui_exposes_dual_rx_visualization_and_analysis_controls() -> None:
    _, _, _, parser = _assets()

    assert {"spectrum-canvas", "waterfall-rx0", "waterfall-rx1"} <= parser.canvas_labels.keys()
    assert all(parser.canvas_labels[canvas_id] for canvas_id in parser.canvas_labels)
    assert {
        "artifacts-body",
        "analysis-artifact",
        "analyzer-select",
        "analysis-parameters",
        "run-analysis",
        "analysis-result",
    } <= parser.ids


def test_ui_exposes_exclusive_scan_controls_and_results() -> None:
    _, javascript, _, parser = _assets()

    assert {
        "scan-form",
        "scan-fieldset",
        "scan-start",
        "scan-stop",
        "scan-step",
        "scan-samples",
        "start-scan",
        "stop-scan",
        "scans-body",
    } <= parser.ids
    assert {"scan-start", "scan-stop", "scan-step", "scan-samples"} <= parser.labels_for
    assert 'apiRequest("/scans")' in javascript
    assert '}/scans/current`' in javascript


def test_ui_uses_versioned_api_and_canonical_waterfall_websocket() -> None:
    _, javascript, _, _ = _assets()

    assert 'const API_ROOT = "/api/v1"' in javascript
    for endpoint in (
        "/health",
        "/radios",
        "/artifacts",
        "/analyzers",
        "/analyses",
        "/streams",
        "/streams/current",
        "/settings",
        "/jobs",
    ):
        assert endpoint in javascript
    assert "/ws/radios/${encodeURIComponent(radioId)}/waterfall" in javascript
    assert "new WebSocket(url)" in javascript


def test_websocket_rendering_is_bounded_to_latest_animation_frame() -> None:
    _, javascript, _, _ = _assets()

    assert "state.latestFrame = frame" in javascript
    assert "if (state.frameScheduled) return" in javascript
    assert "window.requestAnimationFrame" in javascript
    assert "state.latestFrame = null" in javascript


def test_dynamic_api_data_is_never_rendered_as_html() -> None:
    _, javascript, _, _ = _assets()
    unsafe_rendering = (".innerHTML", ".outerHTML", "insertAdjacentHTML", "document.write", "eval(")

    assert not any(token in javascript for token in unsafe_rendering)
    assert "element.textContent" in javascript
    assert "replaceChildren" in javascript


def test_firmware_controls_enforce_guarded_plan_then_execute_flow() -> None:
    html, javascript, _, parser = _assets()

    assert {
        "firmware-fieldset",
        "firmware-image",
        "firmware-mode",
        "firmware-expected-version",
        "plan-firmware",
        "firmware-confirm-serial",
        "execute-firmware",
        "firmware-plan-output",
    } <= parser.ids
    assert "firmware-fieldset" in parser.disabled_ids
    assert "execute-firmware" in parser.disabled_ids
    assert "guarded privileged helper" in html
    assert "/firmware/images?filename=" in javascript
    assert "/firmware/executions" in javascript
    assert 'ui["firmware-confirm-serial"].value !== state.snapshot.identity.serial' in javascript


def test_doctor_is_read_only_and_routes_repairs_into_guarded_firmware_plan() -> None:
    html, javascript, _, parser = _assets()

    assert {
        "doctor-health",
        "run-doctor",
        "prepare-doctor-fix",
        "doctor-profile",
        "doctor-release",
        "doctor-sha",
        "doctor-findings",
    } <= parser.ids
    assert "run-doctor" in parser.disabled_ids
    assert "prepare-doctor-fix" in parser.disabled_ids
    assert "Persistent AD9361/2R2T provisioning" in html
    assert "}/doctor`)" in javascript
    assert 'ui["firmware-mode"].value = "volatile_dfu"' in javascript
    assert "flash_canonical_firmware_mtd3" in javascript
    assert '"/doctor/firmware-plans"' in javascript
    assert 'setText(ui["run-doctor"], "Checking…")' in javascript
    assert 'statusOrder = { fail: 0, warn: 1, unknown: 2, pass: 3 }' in javascript
    assert 'ui["doctor-findings"].scrollIntoView' in javascript


def test_css_has_responsive_and_reduced_motion_layouts() -> None:
    _, _, css, _ = _assets()

    assert "@media (max-width: 820px)" in css
    assert "@media (max-width: 520px)" in css
    assert "@media (prefers-reduced-motion: reduce)" in css
