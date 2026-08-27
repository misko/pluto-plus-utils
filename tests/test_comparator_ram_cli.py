from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.main import get_command
from typer.testing import CliRunner

import pluto_plus.comparator_ram as comparator
from pluto_plus.cli import app
from pluto_plus.comparator_ram import ComparatorRamPlan, ComparatorToolIdentity
from pluto_plus.firmware import (
    DFU_PRODUCT_ID,
    DFU_SPECIFICATION,
    DFU_VENDOR_ID,
    FIT_MAGIC,
    PLUTO_FRM_MAGIC,
)
from pluto_plus.release_candidate import (
    FileIdentity,
    ReleaseUsbInventory,
    UsbInventoryTarget,
    load_private_contract,
    write_private_contract,
)

runner = CliRunner()
NOW = datetime(2026, 8, 27, 13, 0, tzinfo=UTC)
SERIAL = "winbond-db6968136727402c"


def _raw_dfu_crc(data: bytes) -> int:
    accumulator = 0xFFFFFFFF
    for byte in data:
        accumulator ^= byte
        for _ in range(8):
            accumulator = (accumulator >> 1) ^ 0xEDB88320 if accumulator & 1 else accumulator >> 1
    return accumulator


def _fit() -> bytes:
    body = bytearray(96)
    body[:4] = FIT_MAGIC
    body[4:8] = len(body).to_bytes(4, "big")
    body[40 : 40 + len(PLUTO_FRM_MAGIC)] = PLUTO_FRM_MAGIC
    return bytes(body)


def _dfu() -> bytes:
    suffix = b"".join(
        (
            (0xFFFF).to_bytes(2, "little"),
            DFU_PRODUCT_ID.to_bytes(2, "little"),
            DFU_VENDOR_ID.to_bytes(2, "little"),
            DFU_SPECIFICATION.to_bytes(2, "little"),
            b"UFD",
            b"\x10",
        )
    )
    partial = _fit() + suffix
    return partial + _raw_dfu_crc(partial).to_bytes(4, "little")


def test_comparator_ram_help_exposes_only_native_plan_execute_verify() -> None:
    result = runner.invoke(app, ["firmware", "comparator-ram", "--help"])

    assert result.exit_code == 0, result.output
    assert "plan" in result.output
    assert "execute" in result.output
    assert "receipt-verify" in result.output
    root = get_command(app)
    commands = root.commands["firmware"].commands["comparator-ram"].commands  # type: ignore[attr-defined]
    assert set(commands) == {"plan", "execute", "receipt-verify"}
    execute_options = {
        option
        for parameter in commands["execute"].params
        for option in getattr(parameter, "opts", ())
    }
    assert {
        "--plan",
        "--expected-plan-sha256",
        "--ssh-password-file",
        "--confirm",
    }.issubset(execute_options)
    assert not any("known-host" in option for option in execute_options)


def test_comparator_plan_cli_is_file_only_private_and_prints_exact_confirmation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tmp_path.chmod(0o700)
    bundle_payload = b"approved-v7-cli-bundle\n"
    monkeypatch.setattr(comparator, "APPROVED_V7_BUNDLE_BYTES", len(bundle_payload))
    monkeypatch.setattr(
        comparator,
        "APPROVED_V7_BUNDLE_SHA256",
        hashlib.sha256(bundle_payload).hexdigest(),
    )
    monkeypatch.setattr(comparator, "APPROVED_V7_DFU_BYTES", len(_dfu()))
    monkeypatch.setattr(comparator, "APPROVED_V7_DFU_SHA256", hashlib.sha256(_dfu()).hexdigest())
    monkeypatch.setattr(comparator, "APPROVED_V7_FIT_BYTES", len(_fit()))
    monkeypatch.setattr(comparator, "APPROVED_V7_FIT_SHA256", hashlib.sha256(_fit()).hexdigest())
    archive = tmp_path / "archive"
    archive.mkdir(mode=0o700)
    bundle = archive / comparator.APPROVED_V7_BUNDLE_NAME
    bundle.write_bytes(bundle_payload)
    bundle.chmod(0o600)
    dfu = archive / comparator.APPROVED_V7_DFU_NAME
    dfu.write_bytes(_dfu())
    dfu.chmod(0o600)
    target = UsbInventoryTarget(
        serial=SERIAL,
        topology="3-7",
        sysfs_path=Path("/sys/bus/usb/devices/3-7"),
        bus_number=3,
        device_number=29,
        network_interface="enx00e02215c53b",
        source_ipv4="192.168.2.10",
    )
    inventory = ReleaseUsbInventory(created_at=NOW, devices=(target,))
    inventory_path = tmp_path / "inventory.json"
    write_private_contract(inventory_path, inventory)
    receipt_parent = tmp_path / "receipts" / SERIAL
    receipt_parent.mkdir(parents=True, mode=0o700)
    receipt = receipt_parent / "comparator.json"
    output = tmp_path / "plan.json"
    repository = tmp_path / "tool"
    tool = ComparatorToolIdentity(
        repository_path=repository,
        version="0.1.0",
        source_commit="5" * 40,
        source_tree_sha256="6" * 64,
        execution_wrapper=FileIdentity(
            path=repository / comparator.COMPARATOR_WRAPPER_RELATIVE,
            bytes=100,
            sha256="7" * 64,
        ),
    )
    monkeypatch.setattr(comparator, "attest_comparator_tool_repository", lambda *a, **k: tool)

    result = runner.invoke(
        app,
        [
            "firmware",
            "comparator-ram",
            "plan",
            "--retained-bundle",
            str(bundle),
            "--dfu",
            str(dfu),
            "--usb-inventory",
            str(inventory_path),
            "--serial",
            SERIAL,
            "--expected-current-firmware",
            "v0.41-plutoplus-spf-tandem-agc-v8-rc20",
            "--expected-current-hardware-model",
            "Analog Devices PlutoSDR Rev.C (Z7010-AD9361)",
            "--expected-current-metadata-abi",
            "frame-metadata-v5",
            "--expected-current-capability",
            "tandem-agc",
            "--receipt",
            str(receipt),
            "--output",
            str(output),
            "--tool-repository",
            str(repository),
        ],
    )

    assert result.exit_code == 0, result.output
    document = json.loads(result.output)
    assert document["mode"] == "offline_plan"
    assert document["hardware_accessed"] is False
    assert document["will_write_qspi"] is False
    assert document["will_load_volatile_ram"] is False
    assert f"COMPARATOR RAM BOOT {SERIAL}" in document["next_command"]
    assert output.stat().st_mode & 0o777 == 0o600
    plan = load_private_contract(output, ComparatorRamPlan)
    assert plan.receipt_path == receipt
    assert plan.target == target
    assert plan.artifact.dfu.sha256 == hashlib.sha256(_dfu()).hexdigest()
