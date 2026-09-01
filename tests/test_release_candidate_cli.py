from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.main import get_command
from typer.testing import CliRunner

from pluto_plus.cli import DEFAULT_TOOL_REPOSITORY, app
from pluto_plus.inventory import HostNetworkInterface, LocalUsbPluto
from pluto_plus.release_candidate import (
    PLUTO_REV_C_AD9361_MODEL,
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
from pluto_plus.release_candidate_rx_only import (
    ExpectedRuntimeV2,
    ReleaseCandidateOperationPlanV2,
    ReleaseCandidatePlanV2,
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


def _candidate_v2(root: Path) -> ReleaseCandidatePlanV2:
    return ReleaseCandidatePlanV2(
        candidate_id="a" * 32,
        created_at=NOW,
        source_repository="misko/plutosdr-fw",
        source_commit="b" * 40,
        device_tool_repository="misko/pluto-plus-utils",
        device_tool_version="0.1.0",
        device_tool_source_commit="c" * 40,
        artifact_index=FileIdentity(
            path=root / "candidate-index-v2.json", bytes=100, sha256="d" * 64
        ),
        dfu=FileIdentity(path=root / "candidate-v2.dfu", bytes=101, sha256="e" * 64),
        fit=ContentIdentity(bytes=100, sha256="f" * 64),
        expected_runtime=ExpectedRuntimeV2(
            firmware_version="v0.49-plutoplus-rx-only",
            hardware_model=PLUTO_REV_C_AD9361_MODEL,
        ),
    )


def test_candidate_ram_help_has_native_plan_execute_and_no_known_hosts() -> None:
    result = runner.invoke(app, ["firmware", "candidate-ram", "--help"])

    assert result.exit_code == 0, result.output
    assert "inventory" in result.output
    assert "plan" in result.output
    assert "execute" in result.output
    assert "recover" in result.output
    assert "receipt-verify" in result.output
    assert "qualification-plan" in result.output
    assert "qualification-execute" in result.output
    root = get_command(app)
    candidate = root.commands["firmware"].commands["candidate-ram"]  # type: ignore[attr-defined]

    def options(command_name: str) -> set[str]:
        command = candidate.commands[command_name]  # type: ignore[attr-defined]
        return {option for parameter in command.params for option in getattr(parameter, "opts", ())}

    execute_options = options("execute")
    assert "--ssh-password-file" in execute_options
    assert not any("known-host" in option for option in execute_options)
    recover_options = options("recover")
    assert "--ssh-password-file" in recover_options
    assert "--expected-return-firmware" in recover_options
    assert "--output" in recover_options
    assert not any("known-host" in option for option in recover_options)
    assert "--serial" in options("inventory")
    assert "--runtime-target" in options("plan")
    assert "--physical-ip" in options("qualification-plan")
    qualification_execute_options = options("qualification-execute")
    assert "--ssh-password-file" in qualification_execute_options
    assert "--confirm" in qualification_execute_options
    assert not any("known-host" in option for option in qualification_execute_options)


def test_candidate_ram_defaults_to_the_source_checkout() -> None:
    assert Path(__file__).resolve().parents[1] == DEFAULT_TOOL_REPOSITORY


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


def test_candidate_ram_inventory_can_select_one_plus_from_a_mixed_usb_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tmp_path.chmod(0o700)
    output = tmp_path / "usb-inventory.json"
    ordinary = _local().model_copy(
        update={
            "usb_path": "/sys/bus/usb/devices/3-11",
            "bus_number": 3,
            "device_number": 31,
            "product": "PlutoSDR (ADALM-PLUTO)",
            "serial": "104473b80a16000de6ff2000f8a6beca79",
            "host_network_interfaces": (
                HostNetworkInterface(
                    name="enx00e022abcdef", ipv4_addresses=("192.168.4.10",)
                ),
            ),
        }
    )
    monkeypatch.setattr(
        "pluto_plus.cli.scan_local_usb_plutos", lambda: (ordinary, _local())
    )

    result = runner.invoke(
        app,
        [
            "firmware",
            "candidate-ram",
            "inventory",
            "--serial",
            SERIAL,
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0, result.output
    document = json.loads(result.output)
    assert document["hardware_accessed"] is False
    assert document["scanned_device_count"] == 2
    assert document["device_count"] == 1
    assert document["serial_filter"] == SERIAL
    inventory = load_private_contract(output, ReleaseUsbInventory)
    assert tuple(device.serial for device in inventory.devices) == (SERIAL,)


@pytest.mark.parametrize("matches", [0, 2])
def test_candidate_ram_inventory_serial_filter_requires_one_exact_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, matches: int
) -> None:
    tmp_path.chmod(0o700)
    devices = tuple(
        _local().model_copy(
            update={
                "usb_path": f"/sys/bus/usb/devices/3-{7 + index}",
                "device_number": 29 + index,
            }
        )
        for index in range(matches)
    )
    monkeypatch.setattr("pluto_plus.cli.scan_local_usb_plutos", lambda: devices)

    result = runner.invoke(
        app,
        [
            "firmware",
            "candidate-ram",
            "inventory",
            "--serial",
            SERIAL,
            "--output",
            str(tmp_path / "usb-inventory.json"),
        ],
    )

    assert result.exit_code == 4
    assert "requires exactly one runtime matching --serial" in result.output


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


def _plan_inputs_v2(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    tmp_path.chmod(0o700)
    candidate_path = tmp_path / "candidate-plan-v2.json"
    write_private_contract(candidate_path, _candidate_v2(tmp_path))
    inventory_path = tmp_path / "usb-inventory.json"
    write_private_contract(
        inventory_path,
        build_release_usb_inventory((_local(),), created_at=NOW),
    )
    receipt_parent = tmp_path / "hardware" / "deploy" / SERIAL
    receipt_parent.mkdir(parents=True, mode=0o700)
    return (
        candidate_path,
        inventory_path,
        receipt_parent / "ram-receipt-v2.json",
        tmp_path / "operation-plan-v2.json",
    )


def _plan_v2_argv(
    candidate: Path,
    inventory: Path,
    receipt: Path,
    output: Path,
    *,
    target: str | None,
) -> list[str]:
    argv = [
        "firmware",
        "candidate-ram",
        "plan",
        "--candidate-plan",
        str(candidate),
        "--usb-inventory",
        str(inventory),
        "--serial",
        SERIAL,
        "--expected-current-firmware",
        "v0.48-plutoplus-spf-iq-direct-async-v3",
        "--receipt",
        str(receipt),
        "--output",
        str(output),
    ]
    if target is not None:
        argv.extend(("--runtime-target", target))
    return argv


def test_candidate_ram_v2_plan_requires_explicit_1r1t_target(tmp_path: Path) -> None:
    candidate, inventory, receipt, output = _plan_inputs_v2(tmp_path)

    missing = runner.invoke(
        app,
        _plan_v2_argv(candidate, inventory, receipt, output, target=None),
    )
    paired = runner.invoke(
        app,
        _plan_v2_argv(candidate, inventory, receipt, output, target="ad9361-2r2t"),
    )

    assert missing.exit_code == 4
    assert "requires --runtime-target" in missing.output
    assert paired.exit_code == 4
    assert "requires --runtime-target" in paired.output
    assert not output.exists()


def test_candidate_ram_v2_plan_binds_exact_target_and_confirmation(tmp_path: Path) -> None:
    candidate, inventory, receipt, output = _plan_inputs_v2(tmp_path)

    result = runner.invoke(
        app,
        _plan_v2_argv(candidate, inventory, receipt, output, target="ad9361-1r1t"),
    )

    assert result.exit_code == 0, result.output
    document = json.loads(result.output)
    operation = load_private_contract(output, ReleaseCandidateOperationPlanV2)
    assert operation.runtime_target == "ad9361-1r1t"
    assert operation.preboot_profile == "tx-capable-1r1t-v1"
    assert operation.confirmation_phrase == (
        f"RAM BOOT RX-ONLY RELEASE CANDIDATE {SERIAL} ad9361-1r1t"
    )
    assert operation.confirmation_phrase in document["next_command"]

    qualification = runner.invoke(
        app,
        [
            "firmware",
            "candidate-ram",
            "qualification-plan",
            "--operation-plan",
            str(output),
            "--physical-ip",
            "192.168.1.104",
            "--report",
            str(tmp_path / "legacy-tandem-report.json"),
            "--output",
            str(tmp_path / "legacy-tandem-plan.json"),
        ],
    )
    assert qualification.exit_code == 4
    assert not (tmp_path / "legacy-tandem-plan.json").exists()


def test_legacy_candidate_plan_rejects_v2_runtime_target_option(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    candidate_path = tmp_path / "candidate-plan.json"
    write_private_contract(candidate_path, _candidate(tmp_path))
    inventory_path = tmp_path / "usb-inventory.json"
    write_private_contract(
        inventory_path,
        build_release_usb_inventory((_local(),), created_at=NOW),
    )
    receipt = tmp_path / "receipt.json"
    output = tmp_path / "operation.json"

    result = runner.invoke(
        app,
        _plan_v2_argv(
            candidate_path,
            inventory_path,
            receipt,
            output,
            target="ad9361-1r1t",
        ),
    )

    assert result.exit_code == 4
    assert "candidate-plan.v1 does not accept" in result.output
    assert not output.exists()


def test_candidate_ram_execute_dispatches_v2_only_to_rx_only_backend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate, inventory, receipt, operation_path = _plan_inputs_v2(tmp_path)
    planned = runner.invoke(
        app,
        _plan_v2_argv(
            candidate,
            inventory,
            receipt,
            operation_path,
            target="ad9361-1r1t",
        ),
    )
    assert planned.exit_code == 0, planned.output
    password = tmp_path / "radio.password"
    password.write_text("secret\n")
    password.chmod(0o600)
    calls: list[str] = []

    class Backend:
        def __init__(self, **kwargs: object) -> None:
            calls.append("v2-backend")

    def execute(path: Path, **kwargs: object) -> tuple[SimpleNamespace, str]:
        calls.append("v2-execute")
        return (
            SimpleNamespace(
                outcome="pass",
                model_dump=lambda **options: {"schema": "v2-test", "outcome": "pass"},
            ),
            "d" * 64,
        )

    monkeypatch.setattr(
        "pluto_plus.release_candidate_linux.attest_clean_tool_repository",
        lambda path: SimpleNamespace(
            repository="misko/pluto-plus-utils", commit="c" * 40
        ),
    )
    monkeypatch.setattr(
        "pluto_plus.release_candidate_rx_only_linux.LinuxRxOnlyReleaseCandidateBackend",
        Backend,
    )
    monkeypatch.setattr(
        "pluto_plus.release_candidate_rx_only_lifecycle.execute_rx_only_candidate_ram",
        execute,
    )
    monkeypatch.setattr(
        "pluto_plus.release_candidate_linux.LinuxReleaseCandidateBackend",
        lambda **kwargs: pytest.fail("legacy backend selected for v2"),
    )

    result = runner.invoke(
        app,
        [
            "firmware",
            "candidate-ram",
            "execute",
            "--operation-plan",
            str(operation_path),
            "--ssh-password-file",
            str(password),
            "--confirm",
            f"RAM BOOT RX-ONLY RELEASE CANDIDATE {SERIAL} ad9361-1r1t",
            "--tool-repository",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert calls == ["v2-backend", "v2-execute"]
    assert json.loads(result.output)["receipt"]["schema"] == "v2-test"


def test_candidate_ram_recover_dispatches_v2_pass_to_persistent_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate, inventory, receipt_path, operation_path = _plan_inputs_v2(tmp_path)
    planned = runner.invoke(
        app,
        _plan_v2_argv(
            candidate,
            inventory,
            receipt_path,
            operation_path,
            target="ad9361-1r1t",
        ),
    )
    assert planned.exit_code == 0, planned.output
    password = tmp_path / "radio.password"
    password.write_text("secret\n")
    password.chmod(0o600)
    calls: list[str] = []

    class V2Source:
        operation_plan = SimpleNamespace(path=operation_path)
        outcome = "pass"

    class Backend:
        def __init__(self, **kwargs: object) -> None:
            calls.append("v2-backend")

    def recover(path: Path, **kwargs: object) -> tuple[SimpleNamespace, str]:
        calls.append("v2-recover")
        return (
            SimpleNamespace(
                target=SimpleNamespace(serial=SERIAL),
                source_outcome="pass",
                runtime_target="ad9361-1r1t",
                recovered_runtime=SimpleNamespace(
                    firmware_version="v0.48-plutoplus-spf-iq-direct-async-v3",
                    layout=SimpleNamespace(kind="tx-capable"),
                ),
                qspi_unchanged=True,
                host_route=SimpleNamespace(release_verified=True),
                pre_reset_usb_departure_verified=True,
            ),
            "d" * 64,
        )

    monkeypatch.setattr(
        "pluto_plus.release_candidate_rx_only.ReleaseCandidateRamReceiptV2",
        V2Source,
    )
    monkeypatch.setattr(
        "pluto_plus.release_candidate_rx_only.load_ram_receipt_document",
        lambda path: V2Source(),
    )
    monkeypatch.setattr(
        "pluto_plus.release_candidate_linux.attest_clean_tool_repository",
        lambda path: SimpleNamespace(
            repository="misko/pluto-plus-utils", commit="c" * 40
        ),
    )
    monkeypatch.setattr(
        "pluto_plus.release_candidate_rx_only_linux.LinuxRxOnlyReleaseCandidateBackend",
        Backend,
    )
    monkeypatch.setattr(
        "pluto_plus.release_candidate_rx_only_lifecycle.recover_rx_only_candidate_ram",
        recover,
    )

    result = runner.invoke(
        app,
        [
            "firmware",
            "candidate-ram",
            "recover",
            str(receipt_path),
            "--ssh-password-file",
            str(password),
            "--expected-return-firmware",
            "v0.48-plutoplus-spf-iq-direct-async-v3",
            "--output",
            str(tmp_path / "recovery.json"),
            "--confirm",
            f"RECOVER RX-ONLY RELEASE CANDIDATE {SERIAL} ad9361-1r1t",
            "--tool-repository",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert calls == ["v2-backend", "v2-recover"]
    document = json.loads(result.output)
    assert document["source_outcome"] == "pass"
    assert document["runtime_layout"] == "tx-capable"
    assert document["pre_reset_usb_departure_verified"] is True


def test_candidate_ram_v2_recover_rejects_return_firmware_before_backend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate, inventory, receipt_path, operation_path = _plan_inputs_v2(tmp_path)
    planned = runner.invoke(
        app,
        _plan_v2_argv(
            candidate,
            inventory,
            receipt_path,
            operation_path,
            target="ad9361-1r1t",
        ),
    )
    assert planned.exit_code == 0, planned.output

    class V2Source:
        operation_plan = SimpleNamespace(path=operation_path)
        outcome = "pass"

    monkeypatch.setattr(
        "pluto_plus.release_candidate_rx_only.ReleaseCandidateRamReceiptV2",
        V2Source,
    )
    monkeypatch.setattr(
        "pluto_plus.release_candidate_rx_only.load_ram_receipt_document",
        lambda path: V2Source(),
    )
    monkeypatch.setattr(
        "pluto_plus.release_candidate_rx_only_linux.LinuxRxOnlyReleaseCandidateBackend",
        lambda **kwargs: pytest.fail("backend selected after firmware mismatch"),
    )

    result = runner.invoke(
        app,
        [
            "firmware",
            "candidate-ram",
            "recover",
            str(receipt_path),
            "--ssh-password-file",
            str(tmp_path / "unused.password"),
            "--expected-return-firmware",
            "wrong-persistent-firmware",
            "--output",
            str(tmp_path / "recovery.json"),
            "--confirm",
            f"RECOVER RX-ONLY RELEASE CANDIDATE {SERIAL} ad9361-1r1t",
        ],
    )

    assert result.exit_code == 5
    assert "operation plan's persistent firmware" in result.output
