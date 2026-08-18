from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from pluto_plus.cli import app
from pluto_plus.host_isolation import HostIsolationPlan, HostRoute
from pluto_plus.inventory import HostNetworkInterface, LocalUsbPluto
from pluto_plus.ip_firmware import UsbSshRouteObservation
from pluto_plus.local_reboot import LocalRebootPlan

runner = CliRunner()
SERIAL = "SERIAL_A"


def _plan(*, raw_usb_write_access: bool = True) -> LocalRebootPlan:
    return LocalRebootPlan(
        schema_version=3,
        plan_id="plan-a",
        created_at="2026-08-18T00:00:00+00:00",
        serial=SERIAL,
        usb_sysfs_path="/sys/bus/usb/devices/3-8",
        usb_interface="enx001",
        runtime_usb_device_node="/dev/bus/usb/003/011",
        raw_usb_write_access=raw_usb_write_access,
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


def test_reboot_local_isolation_dry_run_exposes_separate_plan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    radio = LocalUsbPluto(
        usb_path="/sys/bus/usb/devices/3-8",
        bus_number=3,
        device_number=11,
        product="PlutoSDR+",
        serial=SERIAL,
        speed_mbps=480,
        interface_count=7,
        host_network_interfaces=(
            HostNetworkInterface(name="enx001", ipv4_addresses=("192.168.2.10",)),
        ),
    )
    isolation = HostIsolationPlan(
        schema_version=1,
        plan_id="isolation-a",
        created_at="2026-08-18T00:00:00+00:00",
        selected_interface="enx001",
        endpoint="192.168.2.1",
        selected_addresses=("192.168.2.10",),
        peer_interfaces=("enx002",),
        peer_addresses=(("enx002", ("192.168.2.10",)),),
        competing_routes=(HostRoute("192.168.2.0/24", "enx002"),),
        sudo_ready=True,
        confirmation_phrase="ISOLATE USB SSH enx001",
    )
    monkeypatch.setattr("pluto_plus.cli.scan_local_usb_plutos", lambda: (radio,))
    monkeypatch.setattr(
        "pluto_plus.host_isolation.prepare_usb_ssh_isolation", lambda *a, **k: isolation
    )
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
            "--isolate-usb-route",
        ],
    )

    assert result.exit_code == 0, result.output
    document = json.loads(result.output)
    assert document["will_reboot"] is False
    assert document["host_isolation"]["selected_interface"] == "enx001"
    assert document["host_isolation"]["confirmation_phrase"] == (
        "ISOLATE USB SSH enx001"
    )


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


def test_reboot_local_refuses_raw_usb_permission_before_prompt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "pluto_plus.local_reboot.prepare_local_reboot",
        lambda *a, **k: _plan(raw_usb_write_access=False),
    )

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
            "--confirm",
            "REBOOT SERIAL_A",
        ],
    )

    assert result.exit_code == 4
    error = json.loads(result.stderr)["error"]
    assert error["code"] == "local_reboot_usb_permission_denied"
    assert "udev" in error["message"]
