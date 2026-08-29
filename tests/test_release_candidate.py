from __future__ import annotations

import json
import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from pluto_plus.inventory import HostNetworkInterface, LocalUsbPluto
from pluto_plus.release_candidate import (
    CANDIDATE_PLAN_SCHEMA,
    OPERATION_PLAN_SCHEMA,
    RAM_RECEIPT_SCHEMA,
    USB_INVENTORY_SCHEMA,
    CleanupReceipt,
    ContentIdentity,
    DfuIdentity,
    ExpectedRuntime,
    FileIdentity,
    HostRouteReceipt,
    QspiObservation,
    ReleaseCandidateContractError,
    ReleaseCandidateOperationPlan,
    ReleaseCandidatePlan,
    ReleaseCandidateRamReceipt,
    ReleaseUsbInventory,
    RuntimeObservation,
    SafeState,
    TransitionReceipt,
    UsbInventoryTarget,
    build_operation_plan,
    build_release_usb_inventory,
    canonical_json_bytes,
    load_private_contract,
    model_file_identity,
    validate_contract_bundle,
    write_private_contract,
)

NOW = datetime(2026, 8, 26, 16, 0, tzinfo=UTC)
SERIAL = "winbond-db6968136727402c"
TOPOLOGY = "3-7"


def _file(name: str, fill: str, *, bytes: int = 100) -> FileIdentity:
    return FileIdentity(path=Path("/evidence") / name, bytes=bytes, sha256=fill * 64)


def _candidate() -> ReleaseCandidatePlan:
    return ReleaseCandidatePlan(
        candidate_id="1" * 32,
        created_at=NOW,
        source_repository="misko/plutosdr-fw",
        source_commit="2" * 40,
        device_tool_repository="misko/pluto-plus-utils",
        device_tool_version="0.2.0",
        device_tool_source_commit="b" * 40,
        artifact_index=_file("candidate-index.json", "3", bytes=9_890),
        dfu=_file("candidate.dfu", "4", bytes=12_788_463),
        fit=ContentIdentity(bytes=12_788_447, sha256="5" * 64),
        expected_runtime=ExpectedRuntime(
            firmware_version="v0.41-plutoplus-spf-tandem-agc-v8-rc14",
            hardware_model="Analog Devices PlutoSDR Rev.C (Z7010-AD9361)",
            metadata_abi="frame-metadata-v5",
            capabilities=("tandem-agc",),
        ),
        dfu_identity=DfuIdentity(),
    )


def _target() -> UsbInventoryTarget:
    return UsbInventoryTarget(
        serial=SERIAL,
        topology=TOPOLOGY,
        sysfs_path=Path("/sys/bus/usb/devices/3-7"),
        bus_number=3,
        device_number=29,
        network_interface="enx00e02215c53b",
        source_ipv4="192.168.2.10",
    )


def _local_radio(
    *,
    serial: str = SERIAL,
    topology: str = TOPOLOGY,
    bus_number: int | None = 3,
    device_number: int | None = 29,
    interfaces: tuple[HostNetworkInterface, ...] | None = None,
) -> LocalUsbPluto:
    return LocalUsbPluto(
        usb_path=f"/sys/bus/usb/devices/{topology}",
        bus_number=bus_number,
        device_number=device_number,
        product="PlutoSDR+",
        serial=serial,
        speed_mbps=480.0,
        interface_count=7,
        host_network_interfaces=(
            interfaces
            if interfaces is not None
            else (HostNetworkInterface(name="enx00e02215c53b", ipv4_addresses=("192.168.2.10",)),)
        ),
    )


def _inventory() -> ReleaseUsbInventory:
    return build_release_usb_inventory((_local_radio(),), created_at=NOW)


def _operation(candidate: ReleaseCandidatePlan | None = None) -> ReleaseCandidateOperationPlan:
    selected_candidate = candidate or _candidate()
    return ReleaseCandidateOperationPlan(
        plan_id="6" * 32,
        created_at=NOW,
        candidate_plan=model_file_identity(
            Path("/evidence/candidate-plan.json"), selected_candidate
        ),
        usb_inventory=_file("usb-inventory.json", "8", bytes=1_500),
        target=_target(),
        expected_current_firmware="v0.41-plutoplus-spf-tandem-agc-v8-rc12",
        receipt_path=Path("/evidence/hardware/deploy") / SERIAL / "ram-receipt.json",
        confirmation_phrase=f"RAM BOOT RELEASE CANDIDATE {SERIAL}",
    )


def _safe() -> SafeState:
    return SafeState(
        tx_gain_db=(-80.0, -80.0),
        dds_raw=(0, 0, 0, 0, 0, 0, 0, 0),
        dds_scale=(0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0),
        dac_selectors=(3, 3, 3, 3),
        tandem_state="IDLE",
        fifo_level=0,
        fault_flags=0,
    )


def _runtime(*, firmware: str, boot_id: str) -> RuntimeObservation:
    return RuntimeObservation(
        serial=SERIAL,
        topology=TOPOLOGY,
        usb_uri="usb:3.29.5",
        hardware_model="Analog Devices PlutoSDR Rev.C (Z7010-AD9361)",
        firmware_version=firmware,
        metadata_abi="frame-metadata-v5",
        capabilities=("tandem-agc",),
        boot_id=boot_id,
        qspi=QspiObservation(bytes=31_457_280, sha256="9" * 64),
        safe_state=_safe(),
    )


def _receipt() -> ReleaseCandidateRamReceipt:
    candidate = _candidate()
    operation = _operation(candidate)
    return ReleaseCandidateRamReceipt(
        receipt_id="a" * 32,
        outcome="pass",
        started_at=NOW,
        completed_at=NOW + timedelta(minutes=2),
        tool_repository="misko/pluto-plus-utils",
        tool_version="0.2.0",
        tool_source_commit="b" * 40,
        operation_plan=model_file_identity(Path("/evidence/operation-plan.json"), operation),
        candidate_plan=model_file_identity(Path("/evidence/candidate-plan.json"), candidate),
        candidate_dfu=ContentIdentity(bytes=candidate.dfu.bytes, sha256=candidate.dfu.sha256),
        candidate_fit=candidate.fit,
        target=_target(),
        expected_firmware="v0.41-plutoplus-spf-tandem-agc-v8-rc14",
        expected_hardware_model="Analog Devices PlutoSDR Rev.C (Z7010-AD9361)",
        expected_metadata_abi="frame-metadata-v5",
        required_capabilities=("tandem-agc",),
        pre_runtime=_runtime(
            firmware="v0.41-plutoplus-spf-tandem-agc-v8-rc12",
            boot_id="11111111-1111-4111-8111-111111111111",
        ),
        post_runtime=_runtime(
            firmware="v0.41-plutoplus-spf-tandem-agc-v8-rc14",
            boot_id="22222222-2222-4222-8222-222222222222",
        ),
        host_route=HostRouteReceipt(
            destination="192.168.2.1/32",
            interface="enx00e02215c53b",
            source="192.168.2.10",
            release_verified=True,
        ),
        transition=TransitionReceipt(
            topology=TOPOLOGY,
            sealed_input=True,
            download_completed=True,
            detach_completed=True,
        ),
        cleanup=CleanupReceipt(verified=True),
    )


def _replace(model: object, **changes: object) -> object:
    return model.__class__.model_validate(  # type: ignore[attr-defined]
        model.model_dump(mode="python", by_alias=True) | changes  # type: ignore[attr-defined]
    )


def test_candidate_plan_is_ram_only_exact_and_canonical() -> None:
    candidate = _candidate()

    assert candidate.schema_id == CANDIDATE_PLAN_SCHEMA
    assert candidate.allowed_operation == "ram-only"
    assert candidate.dfu_identity.selector == "0456:b673,0456:b674"
    assert candidate.expected_runtime.capabilities == ("tandem-agc",)
    payload = canonical_json_bytes(candidate)
    assert payload.endswith(b"\n")
    assert json.loads(payload)["fit"]["sha256"] == "5" * 64
    assert canonical_json_bytes(json.loads(payload)) == payload


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"allowed_operation": "persistent"}, "ram-only"),
        ({"schema_version": 2}, "Input should be 1"),
        ({"source_commit": "f" * 39}, "string_pattern_mismatch"),
        ({"fit": {"bytes": 12_788_464, "sha256": "5" * 64}}, "smaller"),
        (
            {
                "expected_runtime": {
                    "firmware_version": "candidate",
                    "hardware_model": "Pluto",
                    "metadata_abi": "frame-metadata-v5",
                    "capabilities": ["zeta", "alpha"],
                }
            },
            "sorted order",
        ),
    ],
)
def test_candidate_plan_rejects_wrong_authority_or_identity(
    changes: dict[str, object], message: str
) -> None:
    with pytest.raises(ValidationError, match=message):
        _replace(_candidate(), **changes)


def test_operation_plan_is_offline_and_binds_one_exact_target() -> None:
    plan = _operation()

    assert plan.schema_id == OPERATION_PLAN_SCHEMA
    assert plan.hardware_accessed is False
    assert plan.target.sysfs_path == Path("/sys/bus/usb/devices/3-7")
    assert plan.confirmation_phrase.endswith(SERIAL)


def test_strict_inventory_is_sorted_unique_and_canonical() -> None:
    second = _local_radio(
        serial="1040007c4a94000211000b009186843ef2",
        topology="3-8",
        bus_number=3,
        device_number=23,
        interfaces=(
            HostNetworkInterface(name="enx00e02297811f", ipv4_addresses=("192.168.2.10",)),
        ),
    )

    inventory = build_release_usb_inventory((_local_radio(), second), created_at=NOW)

    assert inventory.schema_id == USB_INVENTORY_SCHEMA
    assert tuple(device.serial for device in inventory.devices) == tuple(
        sorted((SERIAL, second.serial or ""))
    )
    assert json.loads(canonical_json_bytes(inventory))["schema"] == USB_INVENTORY_SCHEMA


@pytest.mark.parametrize(
    ("radio", "message"),
    [
        (_local_radio(serial=""), "stable serial"),
        (_local_radio(bus_number=None), "bus/device"),
        (_local_radio(interfaces=()), "one network interface"),
        (
            _local_radio(
                interfaces=(
                    HostNetworkInterface(
                        name="enx00e02215c53b",
                        ipv4_addresses=("192.168.2.10", "192.168.3.10"),
                    ),
                )
            ),
            "one host IPv4",
        ),
    ],
)
def test_inventory_builder_rejects_incomplete_target(radio: LocalUsbPluto, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        build_release_usb_inventory((radio,), created_at=NOW)


def test_inventory_schema_rejects_duplicate_serial_or_topology() -> None:
    target = _target()
    with pytest.raises(ValidationError, match="duplicate serials"):
        ReleaseUsbInventory(created_at=NOW, devices=(target, target))
    with pytest.raises(ValidationError, match="duplicate topologies"):
        ReleaseUsbInventory(
            created_at=NOW,
            devices=(
                target,
                target.model_copy(update={"serial": "OTHER"}),
            ),
        )


def test_operation_builder_consumes_retained_files_without_hardware() -> None:
    candidate = _candidate()
    inventory = _inventory()

    plan = build_operation_plan(
        candidate,
        inventory,
        candidate_path=Path("/evidence/candidate-plan.json"),
        inventory_path=Path("/evidence/usb-inventory.json"),
        serial=SERIAL,
        expected_current_firmware="v0.41-plutoplus-spf-tandem-agc-v8-rc12",
        receipt_path=Path("/evidence/hardware/deploy") / SERIAL / "ram-receipt.json",
        plan_id="f" * 32,
        created_at=NOW,
    )

    assert plan.hardware_accessed is False
    assert plan.target == inventory.devices[0]
    assert plan.candidate_plan == model_file_identity(
        Path("/evidence/candidate-plan.json"), candidate
    )
    assert plan.usb_inventory == model_file_identity(
        Path("/evidence/usb-inventory.json"), inventory
    )


def test_operation_builder_requires_one_exact_inventory_serial() -> None:
    with pytest.raises(ValueError, match="expected one"):
        build_operation_plan(
            _candidate(),
            _inventory(),
            candidate_path=Path("/evidence/candidate-plan.json"),
            inventory_path=Path("/evidence/usb-inventory.json"),
            serial="MISSING",
            expected_current_firmware="old",
            receipt_path=Path("/evidence/receipt.json"),
            plan_id="f" * 32,
            created_at=NOW,
        )


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"hardware_accessed": True}, "Input should be False"),
        ({"confirmation_phrase": "RAM BOOT WRONG"}, "confirmation phrase"),
        ({"ssh_host": "8.8.8.8"}, "private IPv4"),
        (
            {
                "target": _target().model_copy(
                    update={"sysfs_path": Path("/sys/bus/usb/devices/3-8")}
                )
            },
            "does not match",
        ),
    ],
)
def test_operation_plan_rejects_live_or_ambiguous_inputs(
    changes: dict[str, object], message: str
) -> None:
    with pytest.raises(ValidationError, match=message):
        _replace(_operation(), **changes)


def test_passing_receipt_proves_new_boot_unchanged_qspi_and_cleanup() -> None:
    receipt = _receipt()

    assert receipt.schema_id == RAM_RECEIPT_SCHEMA
    assert receipt.outcome == "pass"
    assert receipt.pre_runtime is not None
    assert receipt.post_runtime is not None
    assert receipt.pre_runtime.qspi == receipt.post_runtime.qspi
    assert receipt.pre_runtime.boot_id != receipt.post_runtime.boot_id
    assert receipt.transition.persistent_write is False
    assert receipt.host_route.release_verified is True
    assert receipt.cleanup.verified is True
    validate_contract_bundle(
        _candidate(),
        _operation(),
        receipt,
        candidate_path=Path("/evidence/candidate-plan.json"),
        operation_path=Path("/evidence/operation-plan.json"),
    )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("same_boot", "new boot ID"),
        ("changed_qspi", "unchanged qspi-linux"),
        ("wrong_firmware", "postboot firmware"),
        ("wrong_model", "postboot hardware model"),
        ("wrong_abi", "postboot metadata ABI"),
        ("wrong_capabilities", "postboot capabilities"),
        ("unreleased_route", "completed transition or cleanup"),
        ("unsealed", "completed transition or cleanup"),
        ("cleanup_failed", "completed transition or cleanup"),
        ("wrong_serial", "does not match the target"),
    ],
)
def test_passing_receipt_rejects_planted_semantic_failures(mutation: str, message: str) -> None:
    receipt = _receipt()
    payload = receipt.model_dump(mode="python", by_alias=True)
    assert isinstance(payload["pre_runtime"], dict)
    assert isinstance(payload["post_runtime"], dict)
    assert isinstance(payload["host_route"], dict)
    assert isinstance(payload["transition"], dict)
    assert isinstance(payload["cleanup"], dict)
    if mutation == "same_boot":
        payload["post_runtime"]["boot_id"] = payload["pre_runtime"]["boot_id"]
    elif mutation == "changed_qspi":
        payload["post_runtime"]["qspi"]["sha256"] = "d" * 64
    elif mutation == "wrong_firmware":
        payload["post_runtime"]["firmware_version"] = "wrong"
    elif mutation == "wrong_model":
        payload["post_runtime"]["hardware_model"] = "wrong model"
    elif mutation == "wrong_abi":
        payload["post_runtime"]["metadata_abi"] = "frame-metadata-v4"
    elif mutation == "wrong_capabilities":
        payload["post_runtime"]["capabilities"] = ["other"]
    elif mutation == "unreleased_route":
        payload["host_route"]["release_verified"] = False
    elif mutation == "unsealed":
        payload["transition"]["sealed_input"] = False
    elif mutation == "cleanup_failed":
        payload["cleanup"] = {"verified": False, "errors": ["mute readback failed"]}
    elif mutation == "wrong_serial":
        payload["post_runtime"]["serial"] = "OTHER"
    with pytest.raises(ValidationError, match=message):
        ReleaseCandidateRamReceipt.model_validate(payload)


def test_nonpassing_receipt_requires_failure_and_never_fakes_pass() -> None:
    payload = _receipt().model_dump(mode="python", by_alias=True)
    payload.update(outcome="unknown", failure_phase=None, error=None)
    with pytest.raises(ValidationError, match="identify its failure"):
        ReleaseCandidateRamReceipt.model_validate(payload)


def test_contracts_forbid_unknown_fields() -> None:
    payload = _candidate().model_dump(mode="python", by_alias=True) | {
        "github_attestation": "unused"
    }
    with pytest.raises(ValidationError, match="extra_forbidden"):
        ReleaseCandidatePlan.model_validate(payload)


def test_private_contract_roundtrip_is_absent_only_and_canonical(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    path = tmp_path / "candidate-plan.json"
    candidate = _candidate()

    identity = write_private_contract(path, candidate)

    assert identity == model_file_identity(path, candidate)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.read_bytes() == canonical_json_bytes(candidate)
    assert load_private_contract(path, ReleaseCandidatePlan) == candidate
    with pytest.raises(ReleaseCandidateContractError, match="already exists"):
        write_private_contract(path, candidate)


@pytest.mark.parametrize("mutation", ["pretty", "duplicate", "nonfinite"])
def test_contract_loader_rejects_noncanonical_or_ambiguous_json(
    tmp_path: Path, mutation: str
) -> None:
    tmp_path.chmod(0o700)
    path = tmp_path / "contract.json"
    candidate = _candidate()
    if mutation == "pretty":
        data = (
            json.dumps(candidate.model_dump(mode="json", by_alias=True), indent=2) + "\n"
        ).encode()
        message = "not canonical"
    elif mutation == "duplicate":
        data = b'{"schema":"a","schema":"b"}\n'
        message = "duplicate key"
    else:
        data = b'{"value":NaN}\n'
        message = "non-finite"
    path.write_bytes(data)
    path.chmod(0o600)

    with pytest.raises(ReleaseCandidateContractError, match=message):
        load_private_contract(path, ReleaseCandidatePlan)


def test_contract_loader_rejects_public_mode_symlink_and_hardlink(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    source = tmp_path / "source.json"
    source.write_bytes(canonical_json_bytes(_candidate()))
    source.chmod(0o600)
    source.chmod(0o644)
    with pytest.raises(ReleaseCandidateContractError, match="mode-0600"):
        load_private_contract(source, ReleaseCandidatePlan)
    source.chmod(0o600)
    link = tmp_path / "link.json"
    link.symlink_to(source)
    with pytest.raises(ReleaseCandidateContractError, match="mode-0600"):
        load_private_contract(link, ReleaseCandidatePlan)
    link.unlink()
    os.link(source, link)
    with pytest.raises(ReleaseCandidateContractError, match="one link"):
        load_private_contract(source, ReleaseCandidatePlan)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("candidate_identity", "exact candidate plan bytes"),
        ("operation_identity", "exact operation plan bytes"),
        ("pre_firmware", "preboot firmware"),
        ("dfu", "DFU identity"),
        ("fit", "FIT identity"),
        ("expected", "expected runtime"),
        ("device_tool", "device tool identity"),
        ("route", "host route"),
    ],
)
def test_cross_contract_validator_rejects_coherent_looking_substitution(
    mutation: str, message: str
) -> None:
    candidate = _candidate()
    operation = _operation(candidate)
    receipt_payload = _receipt().model_dump(mode="python", by_alias=True)
    if mutation == "candidate_identity":
        receipt_payload["candidate_plan"]["sha256"] = "e" * 64
    elif mutation == "operation_identity":
        receipt_payload["operation_plan"]["sha256"] = "e" * 64
    elif mutation == "pre_firmware":
        receipt_payload["pre_runtime"]["firmware_version"] = "unexpected-current"
    elif mutation == "dfu":
        receipt_payload["candidate_dfu"]["sha256"] = "e" * 64
    elif mutation == "fit":
        receipt_payload["candidate_fit"]["sha256"] = "e" * 64
    elif mutation == "expected":
        receipt_payload["expected_firmware"] = "other-candidate"
        receipt_payload["post_runtime"]["firmware_version"] = "other-candidate"
    elif mutation == "device_tool":
        receipt_payload["tool_source_commit"] = "e" * 40
    elif mutation == "route":
        receipt_payload["host_route"]["destination"] = "192.168.2.2/32"
    receipt = ReleaseCandidateRamReceipt.model_validate(receipt_payload)
    with pytest.raises(ValueError, match=message):
        validate_contract_bundle(
            candidate,
            operation,
            receipt,
            candidate_path=Path("/evidence/candidate-plan.json"),
            operation_path=Path("/evidence/operation-plan.json"),
        )
