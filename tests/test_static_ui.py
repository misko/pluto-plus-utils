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
        self.canvas_heights: dict[str, int] = {}
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
            self.canvas_heights[element_id] = int(str(attributes.get("height", "0")))
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
        "disconnect-radio",
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


def test_ui_explicitly_releases_page_owned_preview_control() -> None:
    html, javascript, _, parser = _assets()

    assert "disconnect-radio" in parser.ids
    assert "Disconnect &amp; release" in html
    assert "releaseOwnedPreviewForPageExit" in javascript
    assert 'window.addEventListener("pagehide", releaseOwnedPreviewForPageExit)' in javascript
    assert "navigator.sendBeacon(path)" in javascript
    assert 'fetch(path, { method: "POST", keepalive: true })' in javascript
    assert "/streams/${encodeURIComponent(previewJobId)}/release" in javascript
    assert 'ui["disconnect-radio"].addEventListener("click", disconnectAndRelease)' in javascript


def test_ui_exposes_dual_rx_visualization_and_analysis_controls() -> None:
    html, javascript, css, parser = _assets()

    assert {"spectrum-canvas", "waterfall-rx0", "waterfall-rx1"} <= parser.canvas_labels.keys()
    assert all(parser.canvas_labels[canvas_id] for canvas_id in parser.canvas_labels)
    assert parser.canvas_heights["spectrum-canvas"] <= 80
    assert parser.canvas_heights["waterfall-rx0"] >= 280
    assert parser.canvas_heights["waterfall-rx1"] >= 280
    assert html.index("waterfall-grid") < html.index("spectrum-canvas")
    assert '<option value="512" selected>' in html
    assert '<option value="4096"' not in html
    assert '<option value="8192"' not in html
    assert '<option value="16384"' not in html
    assert ".spectrum-overview canvas" in css
    assert "const PREVIEW_MAX_FPS = 12" in javascript
    assert "const SPECTRUM_MAX_FPS = 4" in javascript
    assert "const MAX_CANVAS_WIDTH = 1024" in javascript
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
    assert "}/scans/current`" in javascript


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


def test_ui_exposes_bounded_runtime_diagnostics_and_midstream_reconnect() -> None:
    _, javascript, _, _ = _assets()

    assert "window.plutoDiagnostics" in javascript
    assert "PerformanceObserver" in javascript
    assert 'window.addEventListener("unhandledrejection"' in javascript
    assert 'diagnosticLog("info", "waterfall.auto_attach"' in javascript
    assert 'diagnosticLog("info", "waterfall.render_summary"' in javascript
    assert "scheduleWaterfallReconnect" in javascript
    assert "DIAGNOSTIC_SUMMARY_INTERVAL_MS = 5000" in javascript
    assert 'radio.managed === false ? "discovered" : radio.state' in javascript
    assert "const managed = snapshot.managed !== false" in javascript


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
        "firmware-transport",
        "firmware-transport-ssh",
        "firmware-transport-evidence",
        "firmware-mode",
        "firmware-expected-version",
        "plan-firmware",
        "firmware-confirm-serial",
        "firmware-confirmation-requirement",
        "execute-firmware",
        "reconcile-firmware",
        "firmware-plan-output",
    } <= parser.ids
    assert "firmware-fieldset" in parser.disabled_ids
    assert "execute-firmware" in parser.disabled_ids
    assert "reconcile-firmware" in parser.disabled_ids
    assert "guarded privileged helper" in html
    assert "/firmware/images?filename=" in javascript
    assert "/firmware/executions" in javascript
    assert "`FLASH ${state.snapshot.identity.serial}`" in javascript
    assert "headers: adminHeaders()" in javascript


def test_network_firmware_is_enrollment_gated_identity_bound_and_one_shot() -> None:
    html, javascript, css, parser = _assets()

    assert {"firmware-transport", "firmware-confirm-serial"} <= parser.labels_for
    assert "firmware-transport-ssh" in parser.disabled_ids
    assert "Network flashing is enrollment-only" in html
    assert "Discovering a radio never enables SSH firmware access" in html
    assert "ssh_frm" in javascript
    assert "capability.enrolled_radio_ids.includes(serial)" in javascript
    assert "capability.enrolled_radio_ids)" in javascript
    assert "enrollment?.mutation_available !== false" in javascript
    assert "key_reconciliation_required" in javascript
    assert "verify and re-enroll" in javascript
    assert "plan.transport !== requestedTransport" in javascript
    assert "summary.serial !== selected.serial" in javascript
    assert "summary.host_key_fingerprint" in javascript
    assert "summary.current_firmware" in javascript
    assert "summary.expected_firmware" in javascript
    assert "summary.source_sha256" in javascript
    assert "summary.image_sha256" in javascript
    assert "phases: [...plan.phases]" in javascript
    assert 'transport === "ssh_frm"' in javascript
    assert 'mode === "persistent_qspi"' in javascript
    assert "transport," in javascript
    assert "operator_confirmation: required" in javascript
    assert 'clearFirmwarePlan("Plan submitted exactly once.' in javascript
    assert "confirmationToken" in javascript
    assert "confirmation_token: plan.confirmationToken" in javascript
    assert "JSON.stringify(state.firmwarePlan.plan, null, 2)" in javascript
    assert "JSON.stringify(planned, null, 2)" not in javascript
    assert "firmware-host" not in parser.ids
    assert "firmware-path" not in parser.ids
    assert "firmware-command" not in parser.ids
    assert ".firmware-warning" in css


def test_uncertain_network_flash_is_not_replayed_and_has_read_only_reconcile() -> None:
    html, javascript, _, parser = _assets()

    assert "reconcile-firmware" in parser.ids
    assert "Run read-only reconcile" in html
    assert 'receipt?.outcome === "unknown"' in javascript
    assert "Outcome unknown · Do not retry" in javascript
    assert "receipt.completed_phases" in javascript
    assert "receipt.failure_phase" in javascript
    assert "receipt.reconciliation_required" in javascript
    assert "/firmware/receipts/${encodeURIComponent(uncertain.receipt_id)}/reconcile" in javascript
    assert "Running read-only firmware and target attestation" in javascript
    assert "Do not retry flashing" in javascript
    assert "Outcome remains unknown. Do not retry flashing" in javascript
    assert "state.uncertainFirmwareReceipt = receipt.reconciliation_required" in javascript
    assert "Firmware bytes and reboot verified" not in javascript


def test_doctor_is_read_only_and_routes_repairs_into_guarded_firmware_plan() -> None:
    html, javascript, _, parser = _assets()

    assert {
        "doctor-health",
        "run-doctor",
        "prepare-doctor-fix",
        "prepare-setup-fix",
        "doctor-profile",
        "doctor-release",
        "doctor-sha",
        "doctor-findings",
    } <= parser.ids
    assert "run-doctor" in parser.disabled_ids
    assert "Diagnostic profile" in html
    assert "Guarded repair target" in html
    assert "report.diagnostic_profile?.profile_id" in javascript
    assert "prepare-doctor-fix" in parser.disabled_ids
    assert "prepare-setup-fix" in parser.disabled_ids
    assert "Persistent AD9361/2R2T provisioning" in html
    assert "}/doctor`)" in javascript
    assert 'useSsh ? "ssh_frm" : "usb"' in javascript
    assert 'useSsh ? "persistent_qspi" : "volatile_dfu"' in javascript
    assert "hardware-qualified canonical release" in javascript
    assert "flash_canonical_firmware_mtd3" in javascript
    assert '"/doctor/firmware-plans"' in javascript
    assert 'setText(ui["run-doctor"], "Checking…")' in javascript
    assert "statusOrder = { fail: 0, warn: 1, unknown: 2, pass: 3 }" in javascript
    assert 'ui["doctor-findings"].scrollIntoView' in javascript


def test_setup_repair_is_separate_authenticated_and_canonical_only() -> None:
    html, javascript, css, parser = _assets()

    assert {
        "setup-availability",
        "setup-admin-token",
        "setup-confirm-serial",
        "setup-plan-output",
        "execute-setup",
        "setup-result",
    } <= parser.ids
    assert {"setup-admin-token", "setup-confirm-serial"} <= parser.labels_for
    assert "execute-setup" in parser.disabled_ids
    assert 'apiRequest("/setup")' in javascript
    assert "}/doctor/setup-plans`" in javascript
    assert 'apiRequest("/setup/executions"' in javascript
    assert "Authorization: `Bearer ${token}`" in javascript
    assert "PROVISION ${state.snapshot.identity.serial}" in javascript
    assert "confirmation_token: plan.confirmationToken" in javascript
    assert (
        'setText(ui["setup-plan-output"], JSON.stringify(state.setupPlan.plan, null, 2))'
        in javascript
    )
    assert 'ui["setup-admin-token"].value = ""' in javascript
    assert "localStorage" not in javascript and "sessionStorage" not in javascript
    assert "attr_name" in javascript and "compatible" in javascript and "2r2t" in javascript
    assert "arbitrary" not in html.lower()
    assert "Transmit safety is mandatory" in html
    assert ".setup-warning" in css


def test_network_config_is_redacted_structured_and_restart_separate() -> None:
    html, javascript, _, parser = _assets()

    assert {
        "network-config-availability",
        "read-network-config",
        "config-txt-output",
        "network-config-fieldset",
        "network-config-interface",
        "network-config-mode",
        "network-config-address",
        "network-config-netmask",
        "network-config-host-address",
        "network-config-plan-output",
        "network-config-confirmation",
        "execute-network-config",
    } <= parser.ids
    assert {
        "network-config-interface",
        "network-config-mode",
        "network-config-address",
        "network-config-netmask",
        "network-config-host-address",
        "network-config-confirmation",
    } <= parser.labels_for
    assert "network-config-fieldset" in parser.disabled_ids
    assert "execute-network-config" in parser.disabled_ids
    assert "password-redacted" in html
    assert "Restart is deliberately separate" in html
    assert 'apiRequest("/network-config")' in javascript
    assert "}/config`" in javascript
    assert "}/config/plans`" in javascript
    assert 'apiRequest("/network-config/executions"' in javascript
    assert "ipaddr_eth" in javascript and "ipaddr_host" in javascript
    assert "plan.confirmation.startsWith(\"SET \"" in javascript
    assert "confirmation_token: planned.confirmationToken" in javascript
    assert "JSON.stringify(state.networkConfigPlan.plan, null, 2)" in javascript
    assert "JSON.stringify(planned, null, 2)" not in javascript
    assert "Persisting network variables without restarting the radio" in javascript
    assert "config_txt_redacted" in javascript
    assert "config-put" not in javascript
    assert "reboot_network" not in javascript


def test_css_has_responsive_and_reduced_motion_layouts() -> None:
    _, _, css, _ = _assets()

    assert "@media (max-width: 820px)" in css
    assert "@media (max-width: 520px)" in css
    assert "@media (prefers-reduced-motion: reduce)" in css
