from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from pluto_plus.cli import app
from pluto_plus.ip_firmware import UsbSshRouteObservation
from pluto_plus.local_reboot import LocalRebootPlan

runner = CliRunner()
SERIAL = "SERIAL_A"


def _plan() -> LocalRebootPlan:
    return LocalRebootPlan(
        schema_version=2,
        plan_id="plan-a",
        created_at="2026-08-18T00:00:00+00:00",
        serial=SERIAL,
        usb_sysfs_path="/sys/bus/usb/devices/3-8",
        usb_interface="enx001",
        ssh_host="192.168.2.1",
        ssh_route_mode="usb_gadget",
        known_hosts_sha256="a" * 64,
        route_observation=UsbSshRouteObservation(
            interface_addresses=(("enx001", ("192.168.2.10",)),),
            destination_routes=(("enx001", "192.168.2.0/24"),),
        ),
        confirmation_phrase="REBOOT SERIAL_A",
    )


def test_reboot_local_defaults_to_read_only_plan(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("pluto_plus.local_reboot.prepare_local_reboot", lambda *a, **k: _plan())

    result = runner.invoke(
        app,
        [
            "radio",
            "reboot-local",
            SERIAL,
            "--usb-sysfs-path",
            "/sys/bus/usb/devices/3-8",
            "--ssh-known-hosts-file",
            "/private/radio.known_hosts",
        ],
    )

    assert result.exit_code == 0, result.output
    document = json.loads(result.output)
    assert document["mode"] == "dry_run"
    assert document["will_reboot"] is False
    assert document["plan"]["confirmation_phrase"] == "REBOOT SERIAL_A"


def test_reboot_local_execute_requires_exact_confirmation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("pluto_plus.local_reboot.prepare_local_reboot", lambda *a, **k: _plan())

    result = runner.invoke(
        app,
        [
            "radio",
            "reboot-local",
            SERIAL,
            "--usb-sysfs-path",
            "/sys/bus/usb/devices/3-8",
            "--ssh-known-hosts-file",
            "/private/radio.known_hosts",
            "--execute",
        ],
    )

    assert result.exit_code == 2
    error = json.loads(result.stderr)["error"]
    assert error["code"] == "local_reboot_confirmation_required"
    assert "REBOOT SERIAL_A" in error["message"]

    wrong = runner.invoke(
        app,
        [
            "radio",
            "reboot-local",
            SERIAL,
            "--usb-sysfs-path",
            "/sys/bus/usb/devices/3-8",
            "--ssh-known-hosts-file",
            "/private/radio.known_hosts",
            "--execute",
            "--confirm",
            "REBOOT SERIAL_B",
        ],
    )
    assert wrong.exit_code == 2
    assert json.loads(wrong.stderr)["error"]["code"] == "local_reboot_confirmation_required"
