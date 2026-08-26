from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from pluto_plus.cli import app
from pluto_plus.inventory import HostNetworkInterface, LocalUsbPluto
from pluto_plus.release_candidate import (
    ContentIdentity,
    DfuIdentity,
    ExpectedRuntime,
    FileIdentity,
    ReleaseCandidateOperationPlan,
    ReleaseCandidatePlan,
    ReleaseUsbInventory,
    build_release_usb_inventory,
    load_private_contract,
    write_private_contract,
)

runner = CliRunner()
NOW = datetime(2026, 8, 26, 18, 0, tzinfo=UTC)
SERIAL = "winbond-db6968136727402c"


def _local() -> LocalUsbPluto:
    return LocalUsbPluto(
        usb_path="/sys/bus/usb/devices/3-7",
        bus_number=3,
        device_number=29,
        product="PlutoSDR+",
        serial=SERIAL,
        speed_mbps=480.0,
        interface_count=7,
        host_network_interfaces=(
            HostNetworkInterface(name="enx00e02215c53b", ipv4_addresses=("192.168.2.10",)),
        ),
    )


def _candidate(root: Path) -> ReleaseCandidatePlan:
    return ReleaseCandidatePlan(
        candidate_id="1" * 32,
        created_at=NOW,
        source_repository="misko/plutosdr-fw",
        source_commit="2" * 40,
        device_tool_repository="misko/pluto-plus-utils",
        device_tool_version="0.1.0",
        device_tool_source_commit="5" * 40,
        artifact_index=FileIdentity(path=root / "candidate-index.json", bytes=100, sha256="3" * 64),
        dfu=FileIdentity(path=root / "candidate.dfu", bytes=101, sha256="4" * 64),
        fit=ContentIdentity(bytes=100, sha256="5" * 64),
        expected_runtime=ExpectedRuntime(
            firmware_version="v0.41-plutoplus-spf-tandem-agc-v8-rc14",
            hardware_model="Analog Devices PlutoSDR Rev.C (Z7010-AD9361)",
            metadata_abi="frame-metadata-v5",
            capabilities=("tandem-agc",),
        ),
        dfu_identity=DfuIdentity(),
    )


def test_candidate_ram_help_has_native_plan_execute_and_no_known_hosts() -> None:
    result = runner.invoke(app, ["firmware", "candidate-ram", "--help"])

    assert result.exit_code == 0, result.output
    assert "inventory" in result.output
    assert "plan" in result.output
    assert "execute" in result.output
    assert "receipt-verify" in result.output
    execute = runner.invoke(app, ["firmware", "candidate-ram", "execute", "--help"])
    assert execute.exit_code == 0, execute.output
    assert "--ssh-password-file" in execute.output
    assert "known-host" not in execute.output.lower()


def test_candidate_ram_inventory_is_read_only_and_private(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tmp_path.chmod(0o700)
    output = tmp_path / "usb-inventory.json"
    monkeypatch.setattr("pluto_plus.cli.scan_local_usb_plutos", lambda: (_local(),))

    result = runner.invoke(app, ["firmware", "candidate-ram", "inventory", "--output", str(output)])

    assert result.exit_code == 0, result.output
    document = json.loads(result.output)
    assert document["mode"] == "read_only_usb_inventory"
    assert document["hardware_accessed"] is False
    assert document["device_count"] == 1
    assert document["sha256"] == hashlib.sha256(output.read_bytes()).hexdigest()
    assert output.stat().st_mode & 0o777 == 0o600
    inventory = load_private_contract(output, ReleaseUsbInventory)
    assert inventory.devices[0].serial == SERIAL


def test_candidate_ram_plan_consumes_retained_files_only(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    candidate = _candidate(tmp_path)
    candidate_path = tmp_path / "candidate-plan.json"
    write_private_contract(candidate_path, candidate)
    inventory = build_release_usb_inventory((_local(),), created_at=NOW)
    inventory_path = tmp_path / "usb-inventory.json"
    write_private_contract(inventory_path, inventory)
    receipt_parent = tmp_path / "hardware" / "deploy" / SERIAL
    receipt_parent.mkdir(parents=True, mode=0o700)
    receipt = receipt_parent / "ram-receipt.json"
    output = tmp_path / "operation-plan.json"

    result = runner.invoke(
        app,
        [
            "firmware",
            "candidate-ram",
            "plan",
            "--candidate-plan",
            str(candidate_path),
            "--usb-inventory",
            str(inventory_path),
            "--serial",
            SERIAL,
            "--expected-current-firmware",
            "v0.41-plutoplus-spf-tandem-agc-v8-rc12",
            "--receipt",
            str(receipt),
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0, result.output
    document = json.loads(result.output)
    assert document["mode"] == "offline_plan"
    assert document["hardware_accessed"] is False
    assert document["will_write_qspi"] is False
    assert document["will_load_volatile_ram"] is False
    assert "RAM BOOT RELEASE CANDIDATE" in document["next_command"]
    operation = load_private_contract(output, ReleaseCandidateOperationPlan)
    assert operation.target.serial == SERIAL
    assert operation.receipt_path == receipt
    assert operation.hardware_accessed is False
