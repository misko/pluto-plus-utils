"""Browser acceptance for redacted config.txt and guarded static-IP changes."""

from __future__ import annotations

from typing import Any

import pytest

pytestmark = pytest.mark.browser

SERIAL = "fake-001"
ADMIN_TOKEN = "browser-admin-token-is-at-least-32-bytes"


def test_static_ip_is_read_redacted_planned_and_persisted_without_restart(
    browser_page: Any,
    fake_daemon_origin: str,
) -> None:
    page = browser_page
    plans: list[Any] = []
    executions: list[Any] = []
    javascript_errors: list[str] = []
    page.on("pageerror", lambda error: javascript_errors.append(str(error)))

    page.route(
        "**/api/v1/network-config",
        lambda route: route.fulfill(
            json={
                "available": True,
                "secure_transport": True,
                "enrolled_radio_ids": [SERIAL],
                "mutable_fields": [
                    "ipaddr",
                    "ipaddr_host",
                    "netmask",
                    "ipaddr_eth",
                    "netmask_eth",
                ],
            }
        ),
    )

    def inspect(route: Any) -> None:
        route.fulfill(
            json={
                "identity": {
                    "serial": SERIAL,
                    "endpoint": "192.168.1.165",
                    "host_key_fingerprint": "SHA256:" + "A" * 43,
                },
                "config_txt_sha256": "1" * 64,
                "environment_sha256": "2" * 64,
                "config_txt_redacted": (
                    "[NETWORK]\r\nipaddr_eth = 192.168.1.165\r\n"
                    "[WLAN]\r\npwd_wlan = <redacted>\r\n"
                ),
                "hostname": "pluto-165",
                "usb_radio_address": "192.168.2.1",
                "usb_host_address": "192.168.2.10",
                "usb_netmask": "255.255.255.0",
                "ethernet_address": "192.168.1.165",
                "ethernet_netmask": "255.255.255.0",
            }
        )

    def plan(route: Any, request: Any) -> None:
        plans.append(request)
        route.fulfill(
            status=201,
            json={
                "plan": {
                    "plan_id": "static-ip-plan-165",
                    "expires_at": "2026-08-16T12:05:00Z",
                    "identity": {
                        "serial": SERIAL,
                        "endpoint": "192.168.1.165",
                        "host_key_fingerprint": "SHA256:" + "A" * 43,
                    },
                    "interface": "ethernet",
                    "mode": "static",
                    "changes_items": [
                        ["ipaddr_eth", "192.168.1.183"],
                        ["netmask_eth", "255.255.255.0"],
                    ],
                    "confirmation": f"SET STATIC IP {SERIAL} 192.168.1.183",
                    "endpoint_after_restart": "192.168.1.183",
                    "restart_required": True,
                    "before": {
                        "config_txt_redacted": "must-not-render-full-before-document"
                    },
                },
                "confirmation_token": "one-time-network-config-token",
            },
        )

    def execute(route: Any, request: Any) -> None:
        executions.append(request)
        route.fulfill(
            status=201,
            json={
                "receipt_id": "network-config-receipt-165",
                "outcome": "persisted_restart_required",
                "success": True,
                "restart_required": True,
                "endpoint_after_restart": "192.168.1.183",
            },
        )

    page.route(f"**/api/v1/radios/{SERIAL}/config", inspect)
    page.route(f"**/api/v1/radios/{SERIAL}/config/plans", plan)
    page.route("**/api/v1/network-config/executions", execute)

    response = page.goto(fake_daemon_origin, wait_until="networkidle")
    assert response is not None and response.ok
    assert page.locator("#read-network-config").is_enabled()
    page.locator("#setup-admin-token").fill(ADMIN_TOKEN)
    page.locator("#read-network-config").click()
    page.wait_for_function(
        "document.querySelector('#config-txt-output').textContent.includes('<redacted>')"
    )
    # The redacted document is inside a closed <details>; text_content observes
    # the DOM value without requiring this test to open the disclosure widget.
    config_output = page.locator("#config-txt-output").text_content() or ""
    assert "<redacted>" in config_output
    assert "secret" not in config_output
    assert page.locator("#config-ethernet-current").inner_text().startswith("192.168.1.165")

    page.locator("#network-config-address").fill("192.168.1.183")
    with page.expect_response(
        lambda reply: reply.request.method == "POST"
        and reply.url.endswith(f"/radios/{SERIAL}/config/plans")
    ):
        page.locator("#plan-network-config").click()

    assert len(plans) == 1
    assert plans[0].post_data_json == {
        "interface": "ethernet",
        "mode": "static",
        "address": "192.168.1.183",
        "netmask": "255.255.255.0",
        "host_address": None,
    }
    assert plans[0].headers["authorization"] == f"Bearer {ADMIN_TOKEN}"
    plan_output = page.locator("#network-config-plan-output").inner_text()
    assert "192.168.1.183" in plan_output
    assert f"SET STATIC IP {SERIAL} 192.168.1.183" in plan_output
    assert "one-time-network-config-token" not in plan_output
    assert "must-not-render-full-before-document" not in plan_output

    page.locator("#network-config-confirmation").fill("wrong")
    page.locator("#execute-network-config").click()
    assert executions == []
    assert "exactly match" in page.locator("#network-config-result").inner_text()

    page.locator("#network-config-confirmation").fill(
        f"SET STATIC IP {SERIAL} 192.168.1.183"
    )
    with page.expect_response(
        lambda reply: reply.request.method == "POST"
        and reply.url.endswith("/api/v1/network-config/executions")
    ):
        page.locator("#execute-network-config").click()

    assert len(executions) == 1
    assert executions[0].post_data_json == {
        "plan_id": "static-ip-plan-165",
        "confirmation_token": "one-time-network-config-token",
        "operator_confirmation": f"SET STATIC IP {SERIAL} 192.168.1.183",
    }
    result = page.locator("#network-config-result").inner_text()
    assert "Saved and read back" in result
    assert "Restart required" in result
    assert "192.168.1.183" in result
    assert page.locator("#execute-network-config").is_disabled()
    assert javascript_errors == []
