from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from pluto_plus.cli import app
from pluto_plus.host_isolation import HostIsolationPlan
from pluto_plus.volatile_firmware import VolatileFirmwarePlan

runner = CliRunner()


def _plan(*, raw_usb_write_access: bool = True) -> VolatileFirmwarePlan:
    return VolatileFirmwarePlan(
        schema_version=1,
        plan_id="plan-a",
        created_at="2026-08-18T00:00:00+00:00",
        serial="SERIAL_A",
        usb_sysfs_path="/sys/bus/usb/devices/3-7",
        usb_port="3-7",
        runtime_usb_device_node="/dev/bus/usb/003/007",
        raw_usb_write_access=raw_usb_write_access,
        usb_interface="enx001",
        transition_host="192.168.1.15",
        transition_route_mode="lan",
        known_hosts_sha256="a" * 64,
        before_firmware="v6",
        before_model="PlutoSDR Rev.C",
        before_phy="ad9361",
        image_path="/candidate.dfu",
        image_sha256="b" * 64,
        fit_sha256="c" * 64,
        fit_size=100,
        profile_id="candidate-a",
        expected_firmware="candidate-v1",
        expected_metadata_abi=2,
        expected_tandem_agc=True,
        confirmation_phrase="RAM BOOT SERIAL_A",
    )


def _arguments(tmp_path: Path) -> list[str]:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("placeholder\n")
    known_hosts.chmod(0o600)
    return [
        "firmware",
        "ram-boot",
        str(tmp_path / "candidate.dfu"),
        "--usb-sysfs-path",
        "/sys/bus/usb/devices/3-7",
        "--profile",
        "candidate-a",
        "--ssh-known-hosts-file",
        str(known_hosts),
        "--ssh-host",
        "192.168.1.15",
    ]


def test_ram_boot_cli_defaults_to_read_only_plan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "pluto_plus.volatile_firmware.prepare_ram_boot_plan",
        lambda *args, **kwargs: _plan(),
    )

    result = runner.invoke(app, _arguments(tmp_path))

    assert result.exit_code == 0, result.output
    document = json.loads(result.output)
    assert document["mode"] == "dry_run"
    assert document["will_write_qspi"] is False
    assert document["will_load_volatile_ram"] is False
    assert document["plan"]["confirmation_phrase"] == "RAM BOOT SERIAL_A"


def test_ram_boot_cli_execute_requires_exact_confirmation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "pluto_plus.volatile_firmware.prepare_ram_boot_plan",
        lambda *args, **kwargs: _plan(),
    )

    result = runner.invoke(app, [*_arguments(tmp_path), "--execute"])

    assert result.exit_code == 2
    error = json.loads(result.stderr)["error"]
    assert error["code"] == "ram_boot_confirmation_required"
    assert "RAM BOOT SERIAL_A" in error["message"]


def test_ram_boot_cli_refuses_raw_usb_permission_before_prompt_or_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "pluto_plus.volatile_firmware.prepare_ram_boot_plan",
        lambda *args, **kwargs: _plan(raw_usb_write_access=False),
    )

    result = runner.invoke(
        app,
        [
            *_arguments(tmp_path),
            "--execute",
            "--confirm",
            "RAM BOOT SERIAL_A",
        ],
    )

    assert result.exit_code == 4
    error = json.loads(result.stderr)["error"]
    assert error["code"] == "ram_boot_usb_permission_denied"
    assert "udev" in error["message"]


def test_ram_boot_route_isolation_requires_exact_generated_confirmation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = replace(
        _plan(),
        transition_host="192.168.2.1",
        transition_route_mode="usb_gadget",
    )
    isolation_plan = HostIsolationPlan(
        schema_version=1,
        plan_id="isolate-a",
        created_at="2026-08-27T00:00:00+00:00",
        selected_interface="enx001",
        endpoint="192.168.2.1",
        selected_addresses=("192.168.2.10",),
        peer_interfaces=("enx002",),
        peer_addresses=(("enx002", ("192.168.2.10",)),),
        competing_routes=(),
        sudo_ready=True,
        confirmation_phrase="ISOLATE USB SSH enx001",
    )
    monkeypatch.setattr(
        "pluto_plus.volatile_firmware.prepare_ram_boot_plan",
        lambda *args, **kwargs: plan,
    )
    monkeypatch.setattr(
        "pluto_plus.cli.scan_local_usb_plutos",
        lambda: (
            SimpleNamespace(
                serial="SERIAL_A",
                usb_path="/sys/bus/usb/devices/3-7",
                host_network_interfaces=(SimpleNamespace(name="enx001"),),
            ),
            SimpleNamespace(
                serial="SERIAL_B",
                usb_path="/sys/bus/usb/devices/3-8",
                host_network_interfaces=(SimpleNamespace(name="enx002"),),
            ),
        ),
    )
    monkeypatch.setattr(
        "pluto_plus.host_isolation.prepare_usb_ssh_isolation",
        lambda *args, **kwargs: isolation_plan,
    )
    arguments = _arguments(tmp_path)[:-2]

    result = runner.invoke(
        app,
        [
            *arguments,
            "--isolate-usb-route",
            "--execute",
            "--confirm",
            "RAM BOOT SERIAL_A",
        ],
    )

    assert result.exit_code == 2
    error = json.loads(result.stderr)["error"]
    assert error["code"] == "host_isolation_confirmation_required"
    assert "ISOLATE USB SSH enx001" in error["message"]
