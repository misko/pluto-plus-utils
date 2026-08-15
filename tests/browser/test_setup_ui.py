"""Browser acceptance for a doctor-driven canonical setup repair."""

from __future__ import annotations

from typing import Any

import pytest

from pluto_plus.doctor import CANONICAL_POLICY, CANONICAL_UBOOT

pytestmark = pytest.mark.browser

SERIAL = "fake-001"
ADMIN_TOKEN = "browser-admin-token-is-at-least-32-bytes"


def _finding(
    code: str,
    status: str,
    summary: str,
    actual: object,
    expected: object,
    *,
    repair: bool = False,
) -> dict[str, object]:
    remediation = None
    if repair:
        remediation = {
            "remediation_id": "provision_ad9361_2r2t",
            "title": "Provision the persistent AD9361/2R2T tuple",
            "description": "Back up, write the canonical tuple, reboot, and re-attest.",
            "automatable": True,
            "mutation": True,
            "requires_privileged_helper": True,
            "cli_hint": "pluto setup plan fake-001",
        }
    return {
        "code": code,
        "status": status,
        "summary": summary,
        "actual": actual,
        "expected": expected,
        "evidence": "browser acceptance fixture",
        "remediation": remediation,
    }


def _doctor(*, repaired: bool) -> dict[str, object]:
    status = "pass" if repaired else "fail"
    return {
        "radio_id": SERIAL,
        "checked_at": "2026-08-15T12:00:00Z",
        "canonical_policy": CANONICAL_POLICY.model_dump(mode="json"),
        "healthy": repaired,
        "findings": [
            _finding(
                "rf.phy_model",
                status,
                "RF PHY identifies as AD9361" if repaired else "RF PHY is not canonical AD9361",
                "ad9361" if repaired else "ad9363a",
                "ad9361",
                repair=not repaired,
            ),
            _finding(
                "setup.uboot_2r2t",
                status,
                "Persistent AD9361/2R2T U-Boot tuple is canonical"
                if repaired
                else "Persistent AD9361/2R2T U-Boot tuple is not canonical",
                dict(CANONICAL_UBOOT) if repaired else None,
                dict(CANONICAL_UBOOT),
                repair=not repaired,
            ),
        ],
    }


def _plan() -> dict[str, object]:
    return {
        "plan": {
            "plan_id": "setup-plan-15",
            "created_at": "2026-08-15T12:00:00Z",
            "expires_at": "2026-08-15T12:05:00Z",
            "identity": {
                "serial": SERIAL,
                "usb_sysfs_path": "/sys/bus/usb/devices/fake-001",
                "observed_firmware": CANONICAL_POLICY.device_firmware,
            },
            "profile_id": CANONICAL_POLICY.profile_id,
            "environment_sha256": "1" * 64,
            "changes_items": [
                ["attr_name", "compatible"],
                ["attr_val", "ad9361"],
                ["compatible", "ad9361"],
            ],
            "tx_mute_required": True,
        },
        "confirmation_token": "one-time-setup-token",
    }


def test_doctor_repairs_noncanonical_radio_through_guarded_web_flow(
    browser_page: Any,
    fake_daemon_origin: str,
) -> None:
    page = browser_page
    repaired = {"value": False}
    plan_requests: list[Any] = []
    execution_requests: list[Any] = []
    javascript_errors: list[str] = []
    page.on("pageerror", lambda error: javascript_errors.append(str(error)))

    def setup_status(route: Any) -> None:
        route.fulfill(json={"available": True, "profile_id": CANONICAL_POLICY.profile_id})

    def doctor(route: Any) -> None:
        route.fulfill(json=_doctor(repaired=repaired["value"]))

    def plan(route: Any, request: Any) -> None:
        plan_requests.append(request)
        route.fulfill(status=201, json=_plan())

    def execute(route: Any, request: Any) -> None:
        execution_requests.append(request)
        repaired["value"] = True
        route.fulfill(
            status=201,
            json={
                "receipt_id": "setup-receipt-15",
                "plan_id": "setup-plan-15",
                "success": True,
                "backup_sha256": "4" * 64,
            },
        )

    page.route("**/api/v1/setup", setup_status)
    page.route(f"**/api/v1/radios/{SERIAL}/doctor", doctor)
    page.route(f"**/api/v1/radios/{SERIAL}/doctor/setup-plans", plan)
    page.route("**/api/v1/setup/executions", execute)

    response = page.goto(fake_daemon_origin, wait_until="networkidle")
    assert response is not None and response.ok
    page.wait_for_function(
        "document.querySelector('#doctor-findings').textContent.includes('not canonical AD9361')"
    )
    assert page.locator("#prepare-setup-fix").is_enabled()
    assert page.locator("#setup-availability").text_content() == "Guarded setup helper ready"

    page.locator("#setup-admin-token").fill(ADMIN_TOKEN)
    with page.expect_response(
        lambda reply: (
            reply.request.method == "POST"
            and reply.url.endswith(f"/radios/{SERIAL}/doctor/setup-plans")
        )
    ):
        page.locator("#prepare-setup-fix").click()

    assert len(plan_requests) == 1
    assert plan_requests[0].post_data_json == {}
    assert plan_requests[0].headers["authorization"] == f"Bearer {ADMIN_TOKEN}"
    assert plan_requests[0].headers["origin"] == fake_daemon_origin
    plan_output = page.locator("#setup-plan-output").inner_text()
    assert SERIAL in plan_output
    assert "attr_name" in plan_output and "ad9361" in plan_output
    assert "one-time-setup-token" not in plan_output

    page.locator("#setup-confirm-serial").fill("wrong-radio")
    page.locator("#execute-setup").click()
    assert execution_requests == []
    assert "exactly match" in page.locator("#setup-result").inner_text()

    page.locator("#setup-confirm-serial").fill(f"PROVISION {SERIAL}")
    with page.expect_response(
        lambda reply: (
            reply.request.method == "POST" and reply.url.endswith("/api/v1/setup/executions")
        )
    ):
        page.locator("#execute-setup").click()

    assert len(execution_requests) == 1
    assert execution_requests[0].post_data_json == {
        "plan_id": "setup-plan-15",
        "confirmation_token": "one-time-setup-token",
    }
    assert execution_requests[0].headers["authorization"] == f"Bearer {ADMIN_TOKEN}"
    page.wait_for_function(
        "document.querySelector('#doctor-health').textContent.includes('Canonical')"
    )
    assert "setup-receipt-15" in page.locator("#setup-result").inner_text()
    assert page.locator("#setup-confirm-serial").input_value() == ""
    assert page.locator("#execute-setup").is_disabled()
    assert javascript_errors == []


def test_failed_setup_is_visible_consumes_plan_and_keeps_doctor_noncanonical(
    browser_page: Any,
    fake_daemon_origin: str,
) -> None:
    page = browser_page
    execution_count = {"value": 0}
    reconciliation_count = {"value": 0}

    page.route(
        "**/api/v1/setup",
        lambda route: route.fulfill(json={"available": True}),
    )
    page.route(
        f"**/api/v1/radios/{SERIAL}/doctor",
        lambda route: route.fulfill(json=_doctor(repaired=False)),
    )
    page.route(
        f"**/api/v1/radios/{SERIAL}/doctor/setup-plans",
        lambda route: route.fulfill(status=201, json=_plan()),
    )

    def fail_execution(route: Any) -> None:
        execution_count["value"] += 1
        route.fulfill(
            status=500,
            json={
                "error": {
                    "code": "setup_execution_failed",
                    "message": "radio did not return after reboot",
                },
                "receipt": {
                    "receipt_id": "failed-receipt",
                    "success": False,
                    "outcome": "unknown",
                    "failure_phase": "post_reboot_attestation",
                    "completed_phases": [
                        "preflight",
                        "backup",
                        "mutation_dispatched",
                        "reboot_observed",
                    ],
                    "backup_path": "setup-backups/fake-001-before.txt",
                    "backup_sha256": "4" * 64,
                    "reconciliation_required": True,
                },
            },
        )

    page.route("**/api/v1/setup/executions", fail_execution)

    def reconcile(route: Any, request: Any) -> None:
        reconciliation_count["value"] += 1
        assert request.post_data_json == {}
        route.fulfill(
            status=201,
            json={
                "receipt_id": "reconcile-receipt",
                "success": False,
                "outcome": "reconciled_not_canonical",
                "reconciliation_of": "failed-receipt",
                "reconciliation_required": False,
            },
        )

    page.route("**/api/v1/setup/receipts/failed-receipt/reconcile", reconcile)
    page.goto(fake_daemon_origin, wait_until="networkidle")
    page.locator("#setup-admin-token").fill(ADMIN_TOKEN)
    page.locator("#prepare-setup-fix").click()
    page.wait_for_function("!document.querySelector('#execute-setup').disabled")
    page.locator("#setup-confirm-serial").fill(f"PROVISION {SERIAL}")
    page.locator("#execute-setup").click()

    page.wait_for_function(
        "document.querySelector('#setup-result').textContent.includes('Outcome unknown')"
    )
    assert execution_count["value"] == 1
    assert page.locator("#execute-setup").is_disabled()
    result = page.locator("#setup-result").inner_text()
    assert "Do not retry" in result
    assert "setup-backups/fake-001-before.txt" in result
    assert "4" * 64 in result
    assert "not canonical AD9361" in page.locator("#doctor-findings").inner_text()

    # This action must use the dedicated read-only reconciliation endpoint;
    # execution remains one-shot and is never retried by the browser.
    page.locator("#setup-admin-token").fill(ADMIN_TOKEN)
    assert page.locator("#reconcile-setup").is_enabled()
    with page.expect_response(
        lambda reply: (
            reply.request.method == "POST"
            and reply.url.endswith("/api/v1/setup/receipts/failed-receipt/reconcile")
        )
    ):
        page.locator("#reconcile-setup").click()
    assert reconciliation_count["value"] == 1
    assert execution_count["value"] == 1
    page.wait_for_function(
        "document.querySelector('#setup-result').textContent.includes('not canonical')"
    )
