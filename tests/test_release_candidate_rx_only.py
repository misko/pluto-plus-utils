from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from pluto_plus.release_candidate import (
    PLUTO_REV_C_AD9361_MODEL,
    PLUTO_REV_C_AD9363A_MODEL,
    CleanupReceipt,
    ContentIdentity,
    FileIdentity,
    HostRouteReceipt,
    QspiObservation,
    ReleaseCandidatePlan,
    ReleaseUsbInventory,
    TransitionReceipt,
    UsbInventoryTarget,
    canonical_json_bytes,
    model_file_identity,
)
from pluto_plus.release_candidate_rx_only import (
    RX_ONLY_CANDIDATE_PLAN_SCHEMA,
    RX_ONLY_OPERATION_PLAN_SCHEMA,
    RX_ONLY_RAM_RECEIPT_SCHEMA,
    RX_ONLY_RECOVERY_RECEIPT_SCHEMA,
    ExpectedRuntimeV2,
    PrebootQuiesceReceiptV2,
    ReleaseCandidateOperationPlanV2,
    ReleaseCandidatePlanV2,
    ReleaseCandidateRamReceiptV2,
    ReleaseCandidateRecoveryReceiptV2,
    RuntimeObservationV2,
    RxOnlyLayoutV2,
    SharedTxLoSafeState,
    SingleRxSafeStateV2,
    SingleRxSetupObservation,
    TxCapableLayoutV2,
    TxCapableSingleRxSafeStateV2,
    build_rx_only_operation_plan,
    load_candidate_plan_document,
    load_ram_receipt_document,
    validate_rx_only_recovery_bundle,
    validate_rx_only_recovery_source,
)

NOW = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
SERIAL = "104000bac4950008230026001b440a003a"
TOPOLOGY = "5-2"
CURRENT = "v0.48-plutoplus-spf-iq-direct-async-v3"
CANDIDATE = "v0.49-plutoplus-rx-only"


def _file(name: str, fill: str, *, size: int) -> FileIdentity:
    return FileIdentity(path=Path("/evidence") / name, bytes=size, sha256=fill * 64)


def _candidate() -> ReleaseCandidatePlanV2:
    return ReleaseCandidatePlanV2(
        candidate_id="1" * 32,
        created_at=NOW,
        source_repository="misko/plutosdr-fw",
        source_commit="2" * 40,
        device_tool_repository="misko/pluto-plus-utils",
        device_tool_version="0.1.0",
        device_tool_source_commit="3" * 40,
        artifact_index=_file("artifact-index.json", "4", size=4096),
        dfu=_file("candidate.dfu", "5", size=100_000),
        fit=ContentIdentity(bytes=99_984, sha256="6" * 64),
        expected_runtime=ExpectedRuntimeV2(
            firmware_version=CANDIDATE,
            hardware_model=PLUTO_REV_C_AD9361_MODEL,
            metadata_abi=None,
            capabilities=(),
        ),
    )


def _target() -> UsbInventoryTarget:
    return UsbInventoryTarget(
        serial=SERIAL,
        topology=TOPOLOGY,
        sysfs_path=Path("/sys/bus/usb/devices/5-2"),
        bus_number=5,
        device_number=62,
        network_interface="enx00e0221686a8",
        source_ipv4="192.168.2.10",
    )


def _operation() -> ReleaseCandidateOperationPlanV2:
    candidate = _candidate()
    return ReleaseCandidateOperationPlanV2(
        plan_id="7" * 32,
        created_at=NOW,
        candidate_plan=model_file_identity(Path("/evidence/candidate-plan-v2.json"), candidate),
        usb_inventory=_file("usb-inventory.json", "8", size=1024),
        target=_target(),
        runtime_target="ad9361-1r1t",
        expected_current_firmware=CURRENT,
        receipt_path=Path("/evidence") / SERIAL / "ram-receipt-v2.json",
        confirmation_phrase=f"RAM BOOT RX-ONLY RELEASE CANDIDATE {SERIAL} ad9361-1r1t",
    )


def _setup() -> SingleRxSetupObservation:
    return SingleRxSetupObservation(
        runtime_target="ad9361-1r1t",
        uboot_attr_name="compatible",
        uboot_attr_val="ad9361",
        uboot_compatible="ad9361",
        uboot_mode="1r1t",
        phy_model="ad9361",
        rx_scan_channels=("voltage0", "voltage1"),
    )


def _tx_safe() -> TxCapableSingleRxSafeStateV2:
    return TxCapableSingleRxSafeStateV2(
        tx_gain_db=(-80.0,),
        dds_raw=(0, 0, 0, 0),
        dds_scale=(0.0, 0.0, 0.0, 0.0),
        dac_selectors=(3, 3),
        tandem_state="IDLE",
        fifo_level=0,
        fault_flags=0,
    )


def _runtime(*, firmware: str, boot: str, layout: str) -> RuntimeObservationV2:
    selected_layout = (
        TxCapableLayoutV2(safe_state=_tx_safe())
        if layout == "tx-capable"
        else RxOnlyLayoutV2(safe_state=SingleRxSafeStateV2(tx_gain_db=(-80.0,)))
    )
    return RuntimeObservationV2(
        serial=SERIAL,
        topology=TOPOLOGY,
        usb_uri="usb:5.62.5",
        hardware_model=PLUTO_REV_C_AD9361_MODEL,
        firmware_version=firmware,
        metadata_abi=None,
        capabilities=("tandem-agc",) if layout == "tx-capable" else (),
        boot_id=boot,
        qspi=QspiObservation(bytes=31_457_280, sha256="9" * 64),
        layout=selected_layout,
        single_rx_setup=_setup(),
    )


def _receipt() -> ReleaseCandidateRamReceiptV2:
    candidate = _candidate()
    operation = _operation()
    return ReleaseCandidateRamReceiptV2(
        receipt_id="a" * 32,
        outcome="pass",
        started_at=NOW,
        completed_at=NOW + timedelta(minutes=1),
        tool_repository="misko/pluto-plus-utils",
        tool_version="0.1.0",
        tool_source_commit="3" * 40,
        operation_plan=model_file_identity(Path("/evidence/operation-plan-v2.json"), operation),
        candidate_plan=model_file_identity(Path("/evidence/candidate-plan-v2.json"), candidate),
        candidate_dfu=ContentIdentity(bytes=candidate.dfu.bytes, sha256=candidate.dfu.sha256),
        candidate_fit=candidate.fit,
        target=_target(),
        runtime_target="ad9361-1r1t",
        expected_firmware=CANDIDATE,
        expected_hardware_model=PLUTO_REV_C_AD9361_MODEL,
        expected_metadata_abi=None,
        required_capabilities=(),
        pre_runtime=_runtime(
            firmware=CURRENT,
            boot="11111111-1111-4111-8111-111111111111",
            layout="tx-capable",
        ),
        post_runtime=_runtime(
            firmware=CANDIDATE,
            boot="22222222-2222-4222-8222-222222222222",
            layout="rx-only",
        ),
        preboot_quiesce=PrebootQuiesceReceiptV2(readback_verified=True),
        host_route=HostRouteReceipt(
            destination="192.168.2.1/32",
            interface="enx00e0221686a8",
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


def _payload(model: object, **changes: object) -> dict[str, object]:
    return model.model_dump(mode="python", by_alias=True) | changes  # type: ignore[attr-defined]


def test_v2_contracts_have_exact_distinct_schema_ids() -> None:
    receipt = _receipt()

    assert _candidate().schema_id == RX_ONLY_CANDIDATE_PLAN_SCHEMA
    assert _operation().schema_id == RX_ONLY_OPERATION_PLAN_SCHEMA
    assert receipt.schema_id == RX_ONLY_RAM_RECEIPT_SCHEMA
    assert canonical_json_bytes(receipt).endswith(b"\n")
    assert receipt.post_runtime is not None
    assert receipt.post_runtime.metadata_abi is None
    assert receipt.post_runtime.capabilities == ()


def test_v1_candidate_cannot_parse_v2_bytes_and_v2_cannot_parse_v1() -> None:
    with pytest.raises(ValidationError):
        ReleaseCandidatePlan.model_validate(
            _candidate().model_dump(mode="python", by_alias=True)
        )
    v1 = _candidate().model_dump(mode="python", by_alias=True)
    v1["schema"] = "pluto-plus-utils.release-candidate-plan.v1"
    v1["schema_version"] = 1
    with pytest.raises(ValidationError):
        ReleaseCandidatePlanV2.model_validate(v1)


def test_exact_schema_dispatch_preserves_v1_and_selects_v2(tmp_path: Path) -> None:
    from pluto_plus.release_candidate import (
        ExpectedRuntime,
        ReleaseCandidateContractError,
        write_private_contract,
    )

    tmp_path.chmod(0o700)
    v2_path = tmp_path / "candidate-v2.json"
    write_private_contract(v2_path, _candidate())
    v1 = ReleaseCandidatePlan(
        candidate_id="b" * 32,
        created_at=NOW,
        source_repository="misko/plutosdr-fw",
        source_commit="c" * 40,
        device_tool_repository="misko/pluto-plus-utils",
        device_tool_version="0.1.0",
        device_tool_source_commit="d" * 40,
        artifact_index=_file("v1-index.json", "1", size=100),
        dfu=_file("v1.dfu", "2", size=101),
        fit=ContentIdentity(bytes=100, sha256="3" * 64),
        expected_runtime=ExpectedRuntime(
            firmware_version="v1",
            hardware_model=PLUTO_REV_C_AD9361_MODEL,
            metadata_abi="frame-metadata-v1",
            capabilities=("tandem-agc",),
        ),
    )
    v1_path = tmp_path / "candidate-v1.json"
    write_private_contract(v1_path, v1)

    assert isinstance(load_candidate_plan_document(v1_path), ReleaseCandidatePlan)
    assert isinstance(load_candidate_plan_document(v2_path), ReleaseCandidatePlanV2)
    unknown_path = tmp_path / "unknown.json"
    payload = _candidate().model_dump(mode="json", by_alias=True)
    payload["schema"] = "pluto-plus-utils.release-candidate-plan.v99"
    unknown_path.write_bytes(canonical_json_bytes(payload))
    unknown_path.chmod(0o600)
    with pytest.raises(ReleaseCandidateContractError, match="exact supported"):
        load_candidate_plan_document(unknown_path)


def test_ram_receipt_dispatch_does_not_translate_v2(tmp_path: Path) -> None:
    from pluto_plus.release_candidate import write_private_contract

    tmp_path.chmod(0o700)
    path = tmp_path / "receipt-v2.json"
    receipt = _receipt()
    write_private_contract(path, receipt)

    loaded = load_ram_receipt_document(path)
    assert isinstance(loaded, ReleaseCandidateRamReceiptV2)
    assert loaded == receipt


@pytest.mark.parametrize("target", ["ad9361-2r2t", "ad9364-1r1t", "ad9363a-2r2t"])
def test_operation_rejects_non_rx_only_runtime_targets(target: str) -> None:
    with pytest.raises(ValidationError):
        ReleaseCandidateOperationPlanV2.model_validate(
            _payload(_operation(), runtime_target=target)
        )


def test_operation_confirmation_binds_serial_and_runtime_target() -> None:
    with pytest.raises(ValidationError, match="confirmation phrase"):
        ReleaseCandidateOperationPlanV2.model_validate(
            _payload(
                _operation(),
                confirmation_phrase=f"RAM BOOT RX-ONLY RELEASE CANDIDATE {SERIAL}",
            )
        )


def test_ad9363a_has_a_positive_candidate_operation_and_setup_path() -> None:
    candidate = ReleaseCandidatePlanV2.model_validate(
        _payload(
            _candidate(),
            expected_runtime=ExpectedRuntimeV2(
                firmware_version=CANDIDATE,
                hardware_model=PLUTO_REV_C_AD9363A_MODEL,
            ),
        )
    )
    operation = build_rx_only_operation_plan(
        candidate,
        ReleaseUsbInventory(created_at=NOW, devices=(_target(),)),
        candidate_path=Path("/evidence/ad9363a-candidate.json"),
        inventory_path=Path("/evidence/usb-inventory.json"),
        serial=SERIAL,
        runtime_target="ad9363a-1r1t",
        expected_current_firmware=CURRENT,
        receipt_path=Path("/evidence") / SERIAL / "ad9363a-receipt.json",
        plan_id="8" * 32,
        created_at=NOW,
    )
    setup = SingleRxSetupObservation(
        runtime_target="ad9363a-1r1t",
        uboot_attr_name="compatible",
        uboot_attr_val="ad9363a",
        uboot_compatible="ad9363a",
        uboot_mode="1r1t",
        phy_model="ad9363a",
        rx_scan_channels=("voltage0", "voltage1"),
    )

    assert operation.runtime_target == "ad9363a-1r1t"
    assert operation.confirmation_phrase.endswith(f"{SERIAL} ad9363a-1r1t")
    assert setup.phy_model == "ad9363a"


def test_setup_rejects_legacy_2r2t_before_any_v2_transition() -> None:
    with pytest.raises(ValidationError):
        SingleRxSetupObservation.model_validate(
            _payload(
                _setup(),
                uboot_mode="2r2t",
                rx_scan_channels=("voltage0", "voltage1", "voltage2", "voltage3"),
            )
        )


def test_setup_rejects_crossed_driver_or_attr_pair() -> None:
    with pytest.raises(ValidationError, match="runtime target"):
        SingleRxSetupObservation.model_validate(
            _payload(_setup(), phy_model="ad9363a")
        )
    with pytest.raises(ValidationError, match="attr_name"):
        SingleRxSetupObservation.model_validate(
            _payload(_setup(), uboot_attr_val="ad9363a")
        )


def test_1r1t_safe_state_has_one_real_gain_and_one_shared_lo() -> None:
    state = SingleRxSafeStateV2(tx_gain_db=(-80.0,))

    assert state.tx_gain_controls == ("out_voltage0_hardwaregain",)
    assert state.shared_tx_lo.controls == ("out_altvoltage1_TX_LO_powerdown",)
    assert state.shared_tx_lo.powerdown == (True,)
    with pytest.raises(ValidationError):
        SingleRxSafeStateV2.model_validate(
            _payload(state, tx_gain_db=(-80.0, -80.0))
        )
    with pytest.raises(ValidationError):
        SharedTxLoSafeState.model_validate(
            {"controls": ("out_altvoltage0_RX_LO_powerdown",), "powerdown": (True,)}
        )
    with pytest.raises(ValidationError):
        SharedTxLoSafeState.model_validate(
            {
                "controls": (
                    "out_altvoltage1_TX_LO_powerdown",
                    "out_altvoltage1_TX_LO_powerdown",
                ),
                "powerdown": (True, True),
            }
        )
    for changes in (
        {"tx_gain_controls": (), "tx_gain_db": (-80.0,)},
        {"tx_gain_controls": ("out_voltage0_hardwaregain",), "tx_gain_db": ()},
    ):
        with pytest.raises(ValidationError):
            SingleRxSafeStateV2.model_validate(changes)
    with pytest.raises(ValidationError):
        SharedTxLoSafeState.model_validate({"controls": (), "powerdown": ()})
    with pytest.raises(ValidationError):
        PrebootQuiesceReceiptV2.model_validate(
            {"tx_gain_controls": (), "readback_verified": True}
        )


def test_tx_capable_1r1t_safe_state_retains_exact_dds_tandem_checks() -> None:
    safe = _tx_safe()

    with pytest.raises(ValidationError):
        TxCapableSingleRxSafeStateV2.model_validate(
            _payload(safe, dds_raw=(0,) * 8)
        )
    with pytest.raises(ValidationError, match="DDS raw"):
        TxCapableSingleRxSafeStateV2.model_validate(
            _payload(safe, dds_raw=(0, 0, 1, 0))
        )
    with pytest.raises(ValidationError, match="DAC selectors"):
        TxCapableSingleRxSafeStateV2.model_validate(
            _payload(safe, dac_selectors=(3, 0))
        )


def test_rx_only_layout_requires_absent_tx_devices_and_exact_marker() -> None:
    layout = RxOnlyLayoutV2(safe_state=SingleRxSafeStateV2(tx_gain_db=(-80.0,)))

    assert layout.dds_device is None
    assert layout.tx_dma_device is None
    assert layout.tandem_device is None
    assert layout.root_device_tree_marker == "misko,rx-only-fpga"
    with pytest.raises(ValidationError):
        RxOnlyLayoutV2.model_validate(_payload(layout, dds_device="disabled"))
    with pytest.raises(ValidationError):
        RxOnlyLayoutV2.model_validate(_payload(layout, root_device_tree_marker=None))


def test_passing_receipt_requires_same_target_uboot_identity_pre_and_post() -> None:
    receipt = _receipt()
    assert receipt.post_runtime is not None
    crossed = receipt.post_runtime.model_copy(
        update={
            "hardware_model": PLUTO_REV_C_AD9363A_MODEL,
            "single_rx_setup": SingleRxSetupObservation(
                runtime_target="ad9363a-1r1t",
                uboot_attr_name="compatible",
                uboot_attr_val="ad9363a",
                uboot_compatible="ad9363a",
                uboot_mode="1r1t",
                phy_model="ad9363a",
                rx_scan_channels=("voltage0", "voltage1"),
            )
        }
    )
    with pytest.raises(ValidationError, match="planned runtime target"):
        ReleaseCandidateRamReceiptV2.model_validate(
            _payload(receipt, post_runtime=crossed)
        )


def test_passing_receipt_requires_quiesce_new_boot_same_qspi_and_cleanup() -> None:
    receipt = _receipt()
    assert receipt.pre_runtime is not None
    assert receipt.post_runtime is not None
    for changes, match in (
        ({"preboot_quiesce": None}, "quiesce"),
        (
            {
                "post_runtime": receipt.post_runtime.model_copy(
                    update={"boot_id": receipt.pre_runtime.boot_id}
                )
            },
            "new boot ID",
        ),
        ({"cleanup": CleanupReceipt(verified=False, errors=("route",))}, "cleanup"),
    ):
        with pytest.raises(ValidationError, match=match):
            ReleaseCandidateRamReceiptV2.model_validate(_payload(receipt, **changes))


def test_unknown_receipt_requires_exact_baseline_and_started_monotonic_transition() -> None:
    receipt = _receipt()
    base = receipt.model_dump(mode="python", by_alias=True)
    base.update(
        outcome="unknown",
        failure_phase="postboot-attestation",
        error="timeout",
    )

    assert ReleaseCandidateRamReceiptV2.model_validate(base).outcome == "unknown"

    crossed = receipt.model_dump(mode="python", by_alias=True)
    crossed.update(
        outcome="unknown",
        failure_phase="postboot-attestation",
        error="timeout",
    )
    crossed_pre = crossed["pre_runtime"]
    assert isinstance(crossed_pre, dict)
    crossed_pre["hardware_model"] = PLUTO_REV_C_AD9363A_MODEL
    crossed_pre["single_rx_setup"] = {
        "runtime_target": "ad9363a-1r1t",
        "uboot_attr_name": "compatible",
        "uboot_attr_val": "ad9363a",
        "uboot_compatible": "ad9363a",
        "uboot_mode": "1r1t",
        "phy_model": "ad9363a",
        "rx_scan_channels": ("voltage0", "voltage1"),
    }
    with pytest.raises(ValidationError, match="TX-capable 1R1T baseline"):
        ReleaseCandidateRamReceiptV2.model_validate(crossed)

    impossible = dict(base)
    impossible["transition"] = receipt.transition.model_copy(
        update={"download_completed": False, "detach_completed": True}
    )
    with pytest.raises(ValidationError, match="detach"):
        ReleaseCandidateRamReceiptV2.model_validate(impossible)

    not_started = dict(base)
    not_started["transition"] = receipt.transition.model_copy(
        update={
            "sealed_input": False,
            "download_completed": False,
            "detach_completed": False,
        }
    )
    with pytest.raises(ValidationError, match="started transition"):
        ReleaseCandidateRamReceiptV2.model_validate(not_started)

    stale_persistent = dict(base)
    stale_persistent["post_runtime"] = receipt.pre_runtime
    with pytest.raises(ValidationError, match="TX-capable runtime"):
        ReleaseCandidateRamReceiptV2.model_validate(stale_persistent)


def test_failed_receipt_cannot_describe_started_transition_or_post_runtime() -> None:
    receipt = _receipt()
    payload = receipt.model_dump(mode="python", by_alias=True)
    payload.update(
        outcome="failed",
        failure_phase="sealed-input",
        error="password changed",
        cleanup=CleanupReceipt(
            verified=False, errors=("transition did not start",)
        ),
    )

    with pytest.raises(ValidationError, match="pre-transition"):
        ReleaseCandidateRamReceiptV2.model_validate(payload)


def test_recovery_v2_is_persistent_tx_capable_rollback_only() -> None:
    source_path = _operation().receipt_path
    source = _receipt().model_copy(
        update={
            "outcome": "unknown",
            "cleanup": CleanupReceipt(verified=False, errors=("unknown",)),
            "failure_phase": "postboot-attestation",
            "error": "timeout",
        }
    )
    recovery = ReleaseCandidateRecoveryReceiptV2(
        recovery_id="b" * 32,
        started_at=NOW,
        completed_at=NOW + timedelta(minutes=1),
        tool_repository="misko/pluto-plus-utils",
        tool_version="0.1.0",
        tool_source_commit="3" * 40,
        source_receipt=model_file_identity(source_path, source),
        source_outcome="unknown",
        operation_plan=source.operation_plan,
        candidate_plan=source.candidate_plan,
        target=source.target,
        runtime_target="ad9361-1r1t",
        pre_runtime=source.pre_runtime,
        recovered_runtime=_runtime(
            firmware=CURRENT,
            boot="33333333-3333-4333-8333-333333333333",
            layout="tx-capable",
        ),
        recovery_quiesce=PrebootQuiesceReceiptV2(readback_verified=True),
        expected_return_firmware=CURRENT,
        host_route=source.host_route,
        recovery_action="persistent-reset",
        dfu_detach_completed=False,
        pre_reset_usb_departure_verified=True,
        cleanup=CleanupReceipt(verified=True),
    )

    assert recovery.schema_id == RX_ONLY_RECOVERY_RECEIPT_SCHEMA
    validate_rx_only_recovery_source(source)
    validate_rx_only_recovery_bundle(
        _candidate(),
        _operation(),
        source,
        recovery,
        candidate_path=Path("/evidence/candidate-plan-v2.json"),
        operation_path=Path("/evidence/operation-plan-v2.json"),
        source_path=source_path,
    )
    with pytest.raises(ValidationError):
        ReleaseCandidateRecoveryReceiptV2.model_validate(
            _payload(recovery, expected_return_layout="rx-only")
        )
    assert source.post_runtime is not None
    reused_runtime = recovery.recovered_runtime.model_copy(
        update={"boot_id": source.post_runtime.boot_id}
    )
    with pytest.raises(ValueError, match="post-runtime boot ID"):
        validate_rx_only_recovery_bundle(
            _candidate(),
            _operation(),
            source,
            recovery.model_copy(update={"recovered_runtime": reused_runtime}),
            candidate_path=Path("/evidence/candidate-plan-v2.json"),
            operation_path=Path("/evidence/operation-plan-v2.json"),
            source_path=source_path,
        )

    wrong_route = recovery.host_route.model_copy(
        update={"destination": "192.168.3.1/32"}
    )
    with pytest.raises(ValueError, match="route destination"):
        validate_rx_only_recovery_bundle(
            _candidate(),
            _operation(),
            source,
            recovery.model_copy(update={"host_route": wrong_route}),
            candidate_path=Path("/evidence/candidate-plan-v2.json"),
            operation_path=Path("/evidence/operation-plan-v2.json"),
            source_path=source_path,
        )

    with pytest.raises(ValueError, match="source path"):
        validate_rx_only_recovery_bundle(
            _candidate(),
            _operation(),
            source,
            recovery,
            candidate_path=Path("/evidence/candidate-plan-v2.json"),
            operation_path=Path("/evidence/operation-plan-v2.json"),
            source_path=Path("/evidence/copied-receipt-v2.json"),
        )

    failed = source.model_copy(
        update={
            "outcome": "failed",
            "post_runtime": None,
            "transition": source.transition.model_copy(
                update={
                    "sealed_input": False,
                    "download_completed": False,
                    "detach_completed": False,
                }
            ),
        }
    )
    with pytest.raises(ValueError, match="PASS|UNKNOWN"):
        validate_rx_only_recovery_source(failed)
