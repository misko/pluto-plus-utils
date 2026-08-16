"""Browser contract for enrollment-gated, one-shot SSH firmware updates."""

from __future__ import annotations

from typing import Any

import pytest

pytestmark = pytest.mark.browser

SERIAL = "fake-001"
ADMIN_TOKEN = "browser-admin-token-is-at-least-32-bytes"
SOURCE_SHA256 = "1" * 64
IMAGE_SHA256 = "2" * 64
HOST_KEY = "SHA256:pinned-host-key-fingerprint"


def test_enrolled_network_flash_is_identity_bound_one_shot_and_reconciled(
    browser_page: Any,
    fake_daemon_origin: str,
) -> None:
    page = browser_page
    enrolled = {"value": False}
    plan_requests: list[Any] = []
    execution_requests: list[Any] = []
    reconciliation_requests: list[Any] = []
    reconciliation_attempts = {"value": 0}
    javascript_errors: list[str] = []
    page.on("pageerror", lambda error: javascript_errors.append(str(error)))

    def firmware_status(route: Any) -> None:
        route.fulfill(
            json={
                "available": True,
                "transports": {
                    "usb": {"available": True},
                    "ssh_frm": {
                        "available": True,
                        "enrolled_radio_ids": [SERIAL] if enrolled["value"] else [],
                    },
                },
            }
        )

    def upload(route: Any) -> None:
        route.fulfill(
            status=201,
            json={
                "image_id": SOURCE_SHA256,
                "original_name": "canonical.dfu",
                "sha256": SOURCE_SHA256,
                "size": 16,
            },
        )

    def plan(route: Any, request: Any) -> None:
        plan_requests.append(request)
        route.fulfill(
            status=201,
            json={
                "plan": {
                    "plan_id": "network-plan-15",
                    "expires_at": "2026-08-16T12:05:00Z",
                    "mode": "persistent_qspi",
                    "transport": "ssh_frm",
                    "transport_summary": {
                        "serial": SERIAL,
                        "endpoint": "enrolled-radio-15",
                        "host_key_fingerprint": HOST_KEY,
                        "current_firmware": "v0.38-old",
                        "expected_firmware": "v0.38-current",
                        "source_sha256": SOURCE_SHA256,
                        "image_sha256": IMAGE_SHA256,
                    },
                    "phases": [
                        "preflight",
                        "upload_firmware_only_frm",
                        "disconnect_observed",
                        "post_boot_attestation",
                    ],
                    # These must never be reflected even if a compromised daemon
                    # adds them outside the sanitized transport summary.
                    "staged_path": "/private/staging/secret/pluto.frm",
                    "ssh_password": "must-not-render",
                    "command": "must-not-render",
                },
                "confirmation_token": "one-time-network-token",
            },
        )

    def execute_unknown(route: Any, request: Any) -> None:
        execution_requests.append(request)
        route.fulfill(
            status=500,
            json={
                "error": {
                    "code": "firmware_execution_failed",
                    "message": "connection dropped after updater accepted pluto.frm",
                },
                "receipt": {
                    "receipt_id": "unknown-network-receipt",
                    "success": False,
                    "transport": "ssh_frm",
                    "outcome": "unknown",
                    "completed_phases": ["preflight", "upload_firmware_only_frm"],
                    "failure_phase": "disconnect_observed",
                    "reconciliation_required": True,
                },
            },
        )

    def reconcile(route: Any, request: Any) -> None:
        reconciliation_requests.append(request)
        reconciliation_attempts["value"] += 1
        if reconciliation_attempts["value"] == 1:
            route.fulfill(
                status=200,
                json={
                    "receipt_id": "unknown-network-receipt",
                    "transport": "ssh_frm",
                    "success": False,
                    "outcome": "unknown",
                    "failure_phase": "reconciliation",
                    "reconciliation_required": True,
                },
            )
            return
        route.fulfill(
            status=201,
            json={
                "receipt_id": "network-reconcile-receipt",
                "transport": "ssh_frm",
                "outcome": "reconciled_verified",
                "reconciliation_of": "unknown-network-receipt",
                "reconciliation_required": False,
            },
        )

    page.route("**/api/v1/firmware", firmware_status)
    page.route("**/api/v1/firmware/images*", upload)
    page.route(f"**/api/v1/radios/{SERIAL}/doctor/firmware-plans", plan)
    page.route("**/api/v1/firmware/executions", execute_unknown)
    page.route(
        "**/api/v1/firmware/receipts/unknown-network-receipt/reconcile",
        reconcile,
    )

    response = page.goto(fake_daemon_origin, wait_until="networkidle")
    assert response is not None and response.ok
    ssh_option = page.locator("#firmware-transport-ssh")
    # Chromium does not report an <option> as geometrically visible while its
    # collapsed <select> is closed. Assert the actual disclosure attribute.
    assert ssh_option.get_attribute("hidden") is not None
    assert ssh_option.is_disabled()
    assert "Discovery does not enroll" in page.locator("#firmware-transport-evidence").inner_text()

    # Enrollment is a server-side capability transition. Merely discovering the
    # fake radio above did not expose or enable the SSH choice.
    enrolled["value"] = True
    page.locator("#inspect-firmware").click()
    page.wait_for_function("!document.querySelector('#firmware-transport-ssh').disabled")
    assert ssh_option.get_attribute("hidden") is None
    page.locator("#firmware-transport").select_option("ssh_frm")
    assert page.locator("#firmware-mode").input_value() == "persistent_qspi"
    assert f"FLASH {SERIAL}" in page.locator("#firmware-confirmation-requirement").inner_text()

    page.locator("#setup-admin-token").fill(ADMIN_TOKEN)
    page.locator("#firmware-expected-version").fill("v0.38-current")
    page.locator("#firmware-image").set_input_files(
        {
            "name": "canonical.dfu",
            "mimeType": "application/octet-stream",
            "buffer": b"firmware fixture",
        }
    )
    with page.expect_response(
        lambda reply: (
            reply.request.method == "POST"
            and reply.url.endswith(f"/radios/{SERIAL}/doctor/firmware-plans")
        )
    ):
        page.locator("#plan-firmware").click()

    assert len(plan_requests) == 1
    assert plan_requests[0].post_data_json["transport"] == "ssh_frm"
    assert plan_requests[0].post_data_json["mode"] == "persistent_qspi"
    assert plan_requests[0].headers["authorization"] == f"Bearer {ADMIN_TOKEN}"
    output = page.locator("#firmware-plan-output").inner_text()
    for expected in (
        SERIAL,
        "enrolled-radio-15",
        HOST_KEY,
        "v0.38-old",
        "v0.38-current",
        SOURCE_SHA256,
        IMAGE_SHA256,
        "upload_firmware_only_frm",
        "post_boot_attestation",
    ):
        assert expected in output
    for secret in (
        "one-time-network-token",
        "/private/staging/secret",
        "must-not-render",
    ):
        assert secret not in output

    page.locator("#firmware-confirm-serial").fill(SERIAL)
    page.locator("#execute-firmware").click()
    assert execution_requests == []
    assert f"exactly match FLASH {SERIAL}" in page.locator("#firmware-result").inner_text()

    page.locator("#firmware-confirm-serial").fill(f"FLASH {SERIAL}")
    with page.expect_response(
        lambda reply: (
            reply.request.method == "POST" and reply.url.endswith("/api/v1/firmware/executions")
        )
    ):
        page.locator("#execute-firmware").click()

    assert len(execution_requests) == 1
    assert execution_requests[0].post_data_json == {
        "plan_id": "network-plan-15",
        "confirmation_token": "one-time-network-token",
        "operator_confirmation": f"FLASH {SERIAL}",
    }
    page.wait_for_function(
        "document.querySelector('#firmware-result').textContent.includes('Outcome unknown')"
    )
    result = page.locator("#firmware-result").inner_text()
    assert "Do not retry" in result
    assert "unknown-network-receipt" in result
    assert "disconnect_observed" in result
    assert "upload_firmware_only_frm" in result
    assert page.locator("#execute-firmware").is_disabled()
    assert page.locator("#reconcile-firmware").is_enabled()

    with page.expect_response(
        lambda reply: (
            reply.request.method == "POST"
            and reply.url.endswith("/api/v1/firmware/receipts/unknown-network-receipt/reconcile")
        )
    ):
        page.locator("#reconcile-firmware").click()
    assert len(reconciliation_requests) == 1
    assert reconciliation_requests[0].post_data_json == {}
    assert len(execution_requests) == 1
    page.wait_for_function(
        "document.querySelector('#firmware-result').textContent.includes('Outcome remains unknown')"
    )
    assert page.locator("#reconcile-firmware").is_enabled()
    assert "Do not retry flashing" in page.locator("#firmware-result").inner_text()

    with page.expect_response(
        lambda reply: (
            reply.request.method == "POST"
            and reply.url.endswith("/api/v1/firmware/receipts/unknown-network-receipt/reconcile")
        )
    ):
        page.locator("#reconcile-firmware").click()
    assert len(reconciliation_requests) == 2
    assert len(execution_requests) == 1
    page.wait_for_function(
        "document.querySelector('#firmware-result').textContent.includes('verified firmware')"
    )
    assert page.locator("#reconcile-firmware").is_disabled()
    assert javascript_errors == []
