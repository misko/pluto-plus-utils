from __future__ import annotations

from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from pluto_plus.firmware import (
    DFU_PRODUCT_ID,
    DFU_SPECIFICATION,
    DFU_VENDOR_ID,
    FIT_MAGIC,
    PLUTO_FRM_MAGIC,
)
from pluto_plus.release_candidate import (
    PLUTO_REV_C_AD9361_MODEL,
    CleanupReceipt,
    ContentIdentity,
    FileIdentity,
    HostRouteReceipt,
    QspiObservation,
    ReleaseUsbInventory,
    UsbInventoryTarget,
    load_private_contract,
    write_private_contract,
)
from pluto_plus.release_candidate_lifecycle import PasswordFileIdentity, validate_password_file
from pluto_plus.release_candidate_rx_only import (
    ExpectedRuntimeV2,
    PrebootQuiesceReceiptV2,
    ReleaseCandidatePlanV2,
    ReleaseCandidateRamReceiptV2,
    ReleaseCandidateRecoveryReceiptV2,
    RuntimeObservationV2,
    RxOnlyLayoutV2,
    RxOnlyRuntimeTarget,
    SingleRxSafeStateV2,
    SingleRxSetupObservation,
    TxCapableLayoutV2,
    TxCapableSingleRxSafeStateV2,
    build_rx_only_operation_plan,
)
from pluto_plus.release_candidate_rx_only_lifecycle import (
    RxOnlyFailureReconciliation,
    RxOnlyPersistentRecoveryResult,
    RxOnlyReleaseCandidateLifecycleError,
    execute_rx_only_candidate_ram,
    recover_rx_only_candidate_ram,
)

NOW = datetime(2026, 9, 1, 13, 0, tzinfo=UTC)
SERIAL = "104000bac4950008230026001b440a003a"
TOPOLOGY = "5-2"
INTERFACE = "enx00e0221686a8"
CURRENT = "v0.48-plutoplus-spf-iq-direct-async-v3"
CANDIDATE = "v0.49-plutoplus-rx-only"


def _raw_dfu_crc(data: bytes) -> int:
    accumulator = 0xFFFFFFFF
    for byte in data:
        accumulator ^= byte
        for _ in range(8):
            accumulator = (
                (accumulator >> 1) ^ 0xEDB88320
                if accumulator & 1
                else accumulator >> 1
            )
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


def _target() -> UsbInventoryTarget:
    return UsbInventoryTarget(
        serial=SERIAL,
        topology=TOPOLOGY,
        sysfs_path=Path(f"/sys/bus/usb/devices/{TOPOLOGY}"),
        bus_number=5,
        device_number=62,
        network_interface=INTERFACE,
        source_ipv4="192.168.2.10",
    )


def _setup(target: RxOnlyRuntimeTarget = "ad9361-1r1t") -> SingleRxSetupObservation:
    driver = "ad9361" if target == "ad9361-1r1t" else "ad9363a"
    return SingleRxSetupObservation.model_validate(
        {
            "runtime_target": target,
            "uboot_attr_name": "compatible",
            "uboot_attr_val": driver,
            "uboot_compatible": driver,
            "uboot_mode": "1r1t",
            "phy_model": driver,
            "rx_scan_channels": ("voltage0", "voltage1"),
        }
    )


def _tx_safe() -> TxCapableSingleRxSafeStateV2:
    return TxCapableSingleRxSafeStateV2(
        tx_gain_db=(-80.0,),
        dds_raw=(0,) * 4,
        dds_scale=(0.0,) * 4,
        dac_selectors=(3, 3),
        tandem_state="IDLE",
        fifo_level=0,
        fault_flags=0,
    )


def _runtime(*, firmware: str, boot: str, layout: str) -> RuntimeObservationV2:
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
        layout=(
            TxCapableLayoutV2(safe_state=_tx_safe())
            if layout == "tx-capable"
            else RxOnlyLayoutV2(safe_state=SingleRxSafeStateV2(tx_gain_db=(-80.0,)))
        ),
        single_rx_setup=_setup(),
    )


class FakeBackend:
    def __init__(
        self,
        *,
        fail_on: str | None = None,
        reconciliation: RxOnlyFailureReconciliation | None = None,
        recovered_boot: str = "33333333-3333-4333-8333-333333333333",
        departure_verified: bool = True,
        route_destination: str | None = None,
    ) -> None:
        self.fail_on = fail_on
        self.reconciliation = reconciliation
        self.recovered_boot = recovered_boot
        self.departure_verified = departure_verified
        self.route_destination = route_destination
        self.calls: list[str] = []
        self.sealed_payload: bytes | None = None
        self.ssh_argv: tuple[str, ...] | None = None

    def _call(self, name: str) -> None:
        self.calls.append(name)
        if self.fail_on == name:
            raise RuntimeError(f"planted {name} failure")

    @contextmanager
    def transaction_locks(self, target: UsbInventoryTarget, ssh_host: str) -> Iterator[None]:
        assert target == _target()
        assert ssh_host == "192.168.2.1"
        self._call("locks")
        yield

    @contextmanager
    def sealed_dfu(self, payload: bytes) -> Iterator[Path]:
        self._call("seal")
        self.sealed_payload = payload
        yield Path("/proc/self/fd/42")

    def revalidate_target(self, target: UsbInventoryTarget) -> UsbInventoryTarget:
        self._call("target")
        return target

    def acquire_host_route(self, target: UsbInventoryTarget, ssh_host: str) -> HostRouteReceipt:
        self._call("acquire-route")
        return HostRouteReceipt(
            destination=f"{ssh_host}/32",
            interface=target.network_interface,
            source=target.source_ipv4,
            release_verified=False,
        )

    def ensure_host_route(self, route: HostRouteReceipt, target: UsbInventoryTarget) -> None:
        self._call("ensure-route")

    def release_host_route(self, route: HostRouteReceipt) -> None:
        self._call("release-route")

    def quiesce_and_attest_preboot_v2(
        self,
        target: UsbInventoryTarget,
        *,
        runtime_target: RxOnlyRuntimeTarget,
        expected_firmware: str,
        password: PasswordFileIdentity,
        route: HostRouteReceipt,
    ) -> tuple[RuntimeObservationV2, PrebootQuiesceReceiptV2]:
        validate_password_file(password.path, expected=password)
        assert runtime_target == "ad9361-1r1t"
        self._call("quiesce-pre")
        return (
            _runtime(
                firmware=expected_firmware,
                boot="11111111-1111-4111-8111-111111111111",
                layout="tx-capable",
            ),
            PrebootQuiesceReceiptV2(readback_verified=True),
        )

    def attest_rx_only_runtime_v2(
        self,
        target: UsbInventoryTarget,
        *,
        runtime_target: RxOnlyRuntimeTarget,
        expected_firmware: str,
        password: PasswordFileIdentity,
        route: HostRouteReceipt,
    ) -> RuntimeObservationV2:
        validate_password_file(password.path, expected=password)
        assert runtime_target == "ad9361-1r1t"
        self._call("attest-post")
        return _runtime(
            firmware=expected_firmware,
            boot="22222222-2222-4222-8222-222222222222",
            layout="rx-only",
        )

    def request_ram_mode(
        self,
        argv: Sequence[str],
        *,
        password: PasswordFileIdentity,
        route: HostRouteReceipt,
    ) -> None:
        validate_password_file(password.path, expected=password)
        self.ssh_argv = tuple(argv)
        self._call("request")

    def wait_for_dfu(self, target: UsbInventoryTarget, *, timeout_s: float) -> None:
        self._call("wait-dfu")

    def download_dfu(self, argv: Sequence[str], *, sealed_path: Path) -> None:
        assert sealed_path == Path("/proc/self/fd/42")
        self._call("download")

    def detach_dfu(self, argv: Sequence[str]) -> None:
        self._call("detach")

    def wait_for_runtime(
        self, target: UsbInventoryTarget, *, timeout_s: float
    ) -> UsbInventoryTarget:
        self._call("wait-runtime")
        return target

    def reconcile_failure_v2(
        self,
        target: UsbInventoryTarget,
        *,
        candidate: ReleaseCandidatePlanV2,
        runtime_target: RxOnlyRuntimeTarget,
        pre_runtime: RuntimeObservationV2,
        password: PasswordFileIdentity,
        route: HostRouteReceipt,
        timeout_s: float,
    ) -> RxOnlyFailureReconciliation:
        self._call("reconcile")
        return self.reconciliation or RxOnlyFailureReconciliation(
            runtime=None, cleanup=CleanupReceipt(verified=False, errors=("state unknown",))
        )

    def recover_to_persistent_v2(
        self,
        target: UsbInventoryTarget,
        *,
        pre_runtime: RuntimeObservationV2,
        runtime_target: RxOnlyRuntimeTarget,
        expected_firmware: str,
        password: PasswordFileIdentity,
        ssh_host: str,
        timeout_s: float,
    ) -> RxOnlyPersistentRecoveryResult:
        self._call("persistent-reset")
        return RxOnlyPersistentRecoveryResult(
            runtime=_runtime(
                firmware=expected_firmware,
                boot=self.recovered_boot,
                layout="tx-capable",
            ),
            quiesce=PrebootQuiesceReceiptV2(readback_verified=True),
            host_route=HostRouteReceipt(
                destination=self.route_destination or f"{ssh_host}/32",
                interface=target.network_interface,
                source=target.source_ipv4,
                release_verified=True,
            ),
            dfu_detach_completed=False,
            pre_reset_usb_departure_verified=self.departure_verified,
        )


def _private_dir(path: Path) -> Path:
    path.mkdir(mode=0o700)
    return path


def _write_private(path: Path, payload: bytes) -> None:
    path.write_bytes(payload)
    path.chmod(0o600)


def _bundle(tmp_path: Path) -> tuple[Path, Path, str]:
    root = _private_dir(tmp_path / "private")
    archive = _private_dir(root / "archive")
    credentials = _private_dir(root / "credentials")
    deploy = _private_dir(root / SERIAL)
    payload = _dfu()
    dfu_path = archive / "candidate.dfu"
    _write_private(dfu_path, payload)
    import hashlib

    candidate = ReleaseCandidatePlanV2(
        candidate_id="1" * 32,
        created_at=NOW,
        source_repository="misko/plutosdr-fw",
        source_commit="2" * 40,
        device_tool_repository="misko/pluto-plus-utils",
        device_tool_version="0.1.0",
        device_tool_source_commit="3" * 40,
        artifact_index=FileIdentity(
            path=archive / "artifact-index.json", bytes=10, sha256="4" * 64
        ),
        dfu=FileIdentity(
            path=dfu_path, bytes=len(payload), sha256=hashlib.sha256(payload).hexdigest()
        ),
        fit=ContentIdentity(bytes=len(_fit()), sha256=hashlib.sha256(_fit()).hexdigest()),
        expected_runtime=ExpectedRuntimeV2(
            firmware_version=CANDIDATE,
            hardware_model=PLUTO_REV_C_AD9361_MODEL,
        ),
    )
    candidate_path = archive / "candidate-plan.json"
    write_private_contract(candidate_path, candidate)
    inventory = ReleaseUsbInventory(created_at=NOW, devices=(_target(),))
    inventory_path = root / "usb-inventory.json"
    write_private_contract(inventory_path, inventory)
    operation = build_rx_only_operation_plan(
        candidate,
        inventory,
        candidate_path=candidate_path,
        inventory_path=inventory_path,
        serial=SERIAL,
        runtime_target="ad9361-1r1t",
        expected_current_firmware=CURRENT,
        receipt_path=deploy / "ram-receipt.json",
        plan_id="7" * 32,
        created_at=NOW,
    )
    operation_path = root / "operation-plan.json"
    write_private_contract(operation_path, operation)
    password_path = credentials / "radio.password"
    _write_private(password_path, b"secret\n")
    return operation_path, password_path, operation.confirmation_phrase


def test_v2_lifecycle_passes_only_after_quiesce_and_exact_postboot(tmp_path: Path) -> None:
    operation_path, password_path, phrase = _bundle(tmp_path)
    backend = FakeBackend()
    ticks = iter((NOW, NOW + timedelta(minutes=1)))

    receipt, digest = execute_rx_only_candidate_ram(
        operation_path,
        password_path=password_path,
        confirmation=phrase,
        backend=backend,
        tool_repository="misko/pluto-plus-utils",
        tool_version="0.1.0",
        tool_source_commit="3" * 40,
        now=lambda: next(ticks),
        receipt_id_factory=lambda: "a" * 32,
    )

    assert receipt.outcome == "pass"
    assert receipt.preboot_quiesce is not None
    assert receipt.preboot_quiesce.restore_policy == "leave-quiesced-until-reboot"
    assert receipt.pre_runtime is not None and receipt.pre_runtime.layout.kind == "tx-capable"
    assert receipt.post_runtime is not None and receipt.post_runtime.layout.kind == "rx-only"
    assert len(digest) == 64
    assert backend.calls.index("quiesce-pre") < backend.calls.index("request")
    assert backend.calls[-1] == "release-route"
    saved = load_private_contract(
        operation_path.parent / SERIAL / "ram-receipt.json",
        ReleaseCandidateRamReceiptV2,
    )
    assert saved == receipt


def test_v2_lifecycle_wrong_confirmation_never_touches_backend(tmp_path: Path) -> None:
    operation_path, password_path, _ = _bundle(tmp_path)
    backend = FakeBackend()

    with pytest.raises(RxOnlyReleaseCandidateLifecycleError, match="confirmation"):
        execute_rx_only_candidate_ram(
            operation_path,
            password_path=password_path,
            confirmation="RAM BOOT RELEASE CANDIDATE WRONG",
            backend=backend,
            tool_repository="misko/pluto-plus-utils",
            tool_version="0.1.0",
            tool_source_commit="3" * 40,
        )
    assert backend.calls == []


def test_v2_lifecycle_postboot_failure_publishes_unknown_receipt(tmp_path: Path) -> None:
    operation_path, password_path, phrase = _bundle(tmp_path)
    backend = FakeBackend(fail_on="attest-post")
    ticks = iter((NOW, NOW + timedelta(minutes=1)))

    with pytest.raises(RxOnlyReleaseCandidateLifecycleError) as caught:
        execute_rx_only_candidate_ram(
            operation_path,
            password_path=password_path,
            confirmation=phrase,
            backend=backend,
            tool_repository="misko/pluto-plus-utils",
            tool_version="0.1.0",
            tool_source_commit="3" * 40,
            now=lambda: next(ticks),
            receipt_id_factory=lambda: "a" * 32,
        )

    receipt = caught.value.receipt
    assert receipt is not None
    assert receipt.outcome == "unknown"
    assert receipt.preboot_quiesce is not None
    assert receipt.transition.persistent_write is False
    assert receipt.host_route.release_verified
    assert "reconcile" in backend.calls


def test_v2_lifecycle_rejected_reconciliation_still_publishes_unknown_receipt(
    tmp_path: Path,
) -> None:
    operation_path, password_path, phrase = _bundle(tmp_path)
    mismatched = _runtime(
        firmware=CANDIDATE,
        boot="22222222-2222-4222-8222-222222222222",
        layout="rx-only",
    ).model_copy(update={"metadata_abi": "frame-metadata-v3"})
    backend = FakeBackend(
        fail_on="attest-post",
        reconciliation=RxOnlyFailureReconciliation(
            runtime=mismatched,
            cleanup=CleanupReceipt(verified=True),
        ),
    )
    ticks = iter((NOW, NOW + timedelta(minutes=1)))

    with pytest.raises(RxOnlyReleaseCandidateLifecycleError) as caught:
        execute_rx_only_candidate_ram(
            operation_path,
            password_path=password_path,
            confirmation=phrase,
            backend=backend,
            tool_repository="misko/pluto-plus-utils",
            tool_version="0.1.0",
            tool_source_commit="3" * 40,
            now=lambda: next(ticks),
            receipt_id_factory=lambda: "a" * 32,
        )

    receipt = caught.value.receipt
    assert receipt is not None
    assert receipt.outcome == "unknown"
    assert receipt.post_runtime is None
    assert not receipt.cleanup.verified
    assert "reconciled runtime rejected" in receipt.cleanup.errors[-1]
    saved = load_private_contract(
        operation_path.parent / SERIAL / "ram-receipt.json",
        ReleaseCandidateRamReceiptV2,
    )
    assert saved == receipt


def test_v2_lifecycle_preboot_failure_leaves_only_safe_quiesce_and_no_dfu(
    tmp_path: Path,
) -> None:
    operation_path, password_path, phrase = _bundle(tmp_path)
    backend = FakeBackend(fail_on="quiesce-pre")

    with pytest.raises(RuntimeError, match="quiesce-pre"):
        execute_rx_only_candidate_ram(
            operation_path,
            password_path=password_path,
            confirmation=phrase,
            backend=backend,
            tool_repository="misko/pluto-plus-utils",
            tool_version="0.1.0",
            tool_source_commit="3" * 40,
        )

    assert backend.calls == ["locks", "target", "acquire-route", "quiesce-pre", "release-route"]
    assert not (operation_path.parent / SERIAL / "ram-receipt.json").exists()


def test_v2_recovery_always_returns_to_persistent_tx_capable_1r1t(
    tmp_path: Path,
) -> None:
    operation_path, password_path, phrase = _bundle(tmp_path)
    failing = FakeBackend(fail_on="attest-post")
    failure_ticks = iter((NOW, NOW + timedelta(minutes=1)))
    with pytest.raises(RxOnlyReleaseCandidateLifecycleError) as caught:
        execute_rx_only_candidate_ram(
            operation_path,
            password_path=password_path,
            confirmation=phrase,
            backend=failing,
            tool_repository="misko/pluto-plus-utils",
            tool_version="0.1.0",
            tool_source_commit="3" * 40,
            now=lambda: next(failure_ticks),
            receipt_id_factory=lambda: "a" * 32,
        )
    assert caught.value.receipt is not None
    source_path = operation_path.parent / SERIAL / "ram-receipt.json"
    output_parent = _private_dir(operation_path.parent / "recovery")
    output_path = output_parent / "recovery.json"
    recovery_ticks = iter((NOW + timedelta(minutes=2), NOW + timedelta(minutes=3)))
    backend = FakeBackend()

    recovery, digest = recover_rx_only_candidate_ram(
        source_path,
        password_path=password_path,
        confirmation=(
            f"RECOVER RX-ONLY RELEASE CANDIDATE {SERIAL} ad9361-1r1t"
        ),
        output_path=output_path,
        backend=backend,
        tool_repository="misko/pluto-plus-utils",
        tool_version="0.1.0",
        tool_source_commit="3" * 40,
        now=lambda: next(recovery_ticks),
        recovery_id_factory=lambda: "b" * 32,
    )

    assert recovery.expected_return_firmware == CURRENT
    assert recovery.expected_return_layout == "tx-capable"
    assert recovery.recovered_runtime.layout.kind == "tx-capable"
    assert recovery.pre_runtime.single_rx_setup == recovery.recovered_runtime.single_rx_setup
    assert recovery.recovered_runtime.boot_id != recovery.pre_runtime.boot_id
    assert recovery.recovered_runtime.qspi == recovery.pre_runtime.qspi
    assert recovery.recovery_action == "persistent-reset"
    assert backend.calls == ["locks", "persistent-reset"]
    assert load_private_contract(output_path, ReleaseCandidateRecoveryReceiptV2) == recovery
    assert len(digest) == 64


def test_v2_passing_trial_has_an_intentional_persistent_rollback(tmp_path: Path) -> None:
    operation_path, password_path, phrase = _bundle(tmp_path)
    execution_ticks = iter((NOW, NOW + timedelta(minutes=1)))
    execute_rx_only_candidate_ram(
        operation_path,
        password_path=password_path,
        confirmation=phrase,
        backend=FakeBackend(),
        tool_repository="misko/pluto-plus-utils",
        tool_version="0.1.0",
        tool_source_commit="3" * 40,
        now=lambda: next(execution_ticks),
        receipt_id_factory=lambda: "a" * 32,
    )
    source_path = operation_path.parent / SERIAL / "ram-receipt.json"
    output_parent = _private_dir(operation_path.parent / "pass-recovery")
    backend = FakeBackend()
    recovery_ticks = iter((NOW + timedelta(minutes=2), NOW + timedelta(minutes=3)))

    recovery, _ = recover_rx_only_candidate_ram(
        source_path,
        password_path=password_path,
        confirmation=f"RECOVER RX-ONLY RELEASE CANDIDATE {SERIAL} ad9361-1r1t",
        output_path=output_parent / "recovery.json",
        backend=backend,
        tool_repository="misko/pluto-plus-utils",
        tool_version="0.1.0",
        tool_source_commit="3" * 40,
        now=lambda: next(recovery_ticks),
        recovery_id_factory=lambda: "b" * 32,
    )

    assert recovery.source_receipt.path == source_path
    assert recovery.recovered_runtime.layout.kind == "tx-capable"
    assert backend.calls == ["locks", "persistent-reset"]


@pytest.mark.parametrize("reconciled_layout", ["rx-only", "tx-capable"])
def test_v2_recovery_accepts_safely_reconciled_unknown_receipt(
    tmp_path: Path, reconciled_layout: str
) -> None:
    operation_path, password_path, phrase = _bundle(tmp_path)
    reconciled = _runtime(
        firmware=CANDIDATE if reconciled_layout == "rx-only" else CURRENT,
        boot="22222222-2222-4222-8222-222222222222",
        layout=reconciled_layout,
    )
    failing = FakeBackend(
        fail_on="attest-post",
        reconciliation=RxOnlyFailureReconciliation(
            runtime=reconciled, cleanup=CleanupReceipt(verified=True)
        ),
    )
    failure_ticks = iter((NOW, NOW + timedelta(minutes=1)))
    with pytest.raises(RxOnlyReleaseCandidateLifecycleError) as caught:
        execute_rx_only_candidate_ram(
            operation_path,
            password_path=password_path,
            confirmation=phrase,
            backend=failing,
            tool_repository="misko/pluto-plus-utils",
            tool_version="0.1.0",
            tool_source_commit="3" * 40,
            now=lambda: next(failure_ticks),
            receipt_id_factory=lambda: "a" * 32,
        )
    assert caught.value.receipt is not None
    assert caught.value.receipt.cleanup.verified

    output_parent = _private_dir(operation_path.parent / f"{reconciled_layout}-recovery")
    recovery_ticks = iter((NOW + timedelta(minutes=2), NOW + timedelta(minutes=3)))
    recovery, _ = recover_rx_only_candidate_ram(
        operation_path.parent / SERIAL / "ram-receipt.json",
        password_path=password_path,
        confirmation=f"RECOVER RX-ONLY RELEASE CANDIDATE {SERIAL} ad9361-1r1t",
        output_path=output_parent / "recovery.json",
        backend=FakeBackend(),
        tool_repository="misko/pluto-plus-utils",
        tool_version="0.1.0",
        tool_source_commit="3" * 40,
        now=lambda: next(recovery_ticks),
        recovery_id_factory=lambda: "b" * 32,
    )

    assert recovery.recovered_runtime.layout.kind == "tx-capable"


def test_v2_recovery_rejects_failed_pretransition_receipt(tmp_path: Path) -> None:
    operation_path, password_path, phrase = _bundle(tmp_path)
    ticks = iter((NOW, NOW + timedelta(minutes=1)))
    with pytest.raises(RxOnlyReleaseCandidateLifecycleError) as caught:
        execute_rx_only_candidate_ram(
            operation_path,
            password_path=password_path,
            confirmation=phrase,
            backend=FakeBackend(fail_on="seal"),
            tool_repository="misko/pluto-plus-utils",
            tool_version="0.1.0",
            tool_source_commit="3" * 40,
            now=lambda: next(ticks),
            receipt_id_factory=lambda: "a" * 32,
        )
    assert caught.value.receipt is not None
    assert caught.value.receipt.outcome == "failed"
    recovery_backend = FakeBackend()
    output_parent = _private_dir(operation_path.parent / "failed-recovery")

    with pytest.raises(RxOnlyReleaseCandidateLifecycleError, match="PASS|UNKNOWN"):
        recover_rx_only_candidate_ram(
            operation_path.parent / SERIAL / "ram-receipt.json",
            password_path=password_path,
            confirmation=f"RECOVER RX-ONLY RELEASE CANDIDATE {SERIAL} ad9361-1r1t",
            output_path=output_parent / "recovery.json",
            backend=recovery_backend,
            tool_repository="misko/pluto-plus-utils",
            tool_version="0.1.0",
            tool_source_commit="3" * 40,
        )
    assert recovery_backend.calls == []


def test_v2_recovery_rejects_reused_reconciled_boot_id(tmp_path: Path) -> None:
    operation_path, password_path, phrase = _bundle(tmp_path)
    execution_ticks = iter((NOW, NOW + timedelta(minutes=1)))
    execute_rx_only_candidate_ram(
        operation_path,
        password_path=password_path,
        confirmation=phrase,
        backend=FakeBackend(),
        tool_repository="misko/pluto-plus-utils",
        tool_version="0.1.0",
        tool_source_commit="3" * 40,
        now=lambda: next(execution_ticks),
        receipt_id_factory=lambda: "a" * 32,
    )
    output_parent = _private_dir(operation_path.parent / "reused-boot-recovery")

    with pytest.raises(RxOnlyReleaseCandidateLifecycleError, match="recovery proof"):
        recover_rx_only_candidate_ram(
            operation_path.parent / SERIAL / "ram-receipt.json",
            password_path=password_path,
            confirmation=f"RECOVER RX-ONLY RELEASE CANDIDATE {SERIAL} ad9361-1r1t",
            output_path=output_parent / "recovery.json",
            backend=FakeBackend(
                recovered_boot="22222222-2222-4222-8222-222222222222"
            ),
            tool_repository="misko/pluto-plus-utils",
            tool_version="0.1.0",
            tool_source_commit="3" * 40,
            now=lambda: NOW + timedelta(minutes=2),
        )
    assert not (output_parent / "recovery.json").exists()


def test_v2_recovery_rejects_backend_without_usb_departure_proof(tmp_path: Path) -> None:
    operation_path, password_path, phrase = _bundle(tmp_path)
    execution_ticks = iter((NOW, NOW + timedelta(minutes=1)))
    execute_rx_only_candidate_ram(
        operation_path,
        password_path=password_path,
        confirmation=phrase,
        backend=FakeBackend(),
        tool_repository="misko/pluto-plus-utils",
        tool_version="0.1.0",
        tool_source_commit="3" * 40,
        now=lambda: next(execution_ticks),
        receipt_id_factory=lambda: "a" * 32,
    )
    output_parent = _private_dir(operation_path.parent / "missing-departure-proof")
    output_path = output_parent / "recovery.json"

    with pytest.raises(RxOnlyReleaseCandidateLifecycleError, match="USB departure"):
        recover_rx_only_candidate_ram(
            operation_path.parent / SERIAL / "ram-receipt.json",
            password_path=password_path,
            confirmation=f"RECOVER RX-ONLY RELEASE CANDIDATE {SERIAL} ad9361-1r1t",
            output_path=output_path,
            backend=FakeBackend(departure_verified=False),
            tool_repository="misko/pluto-plus-utils",
            tool_version="0.1.0",
            tool_source_commit="3" * 40,
            now=lambda: NOW + timedelta(minutes=2),
        )

    assert not output_path.exists()


def test_v2_recovery_rejects_route_destination_not_bound_to_operation(tmp_path: Path) -> None:
    operation_path, password_path, phrase = _bundle(tmp_path)
    execution_ticks = iter((NOW, NOW + timedelta(minutes=1)))
    execute_rx_only_candidate_ram(
        operation_path,
        password_path=password_path,
        confirmation=phrase,
        backend=FakeBackend(),
        tool_repository="misko/pluto-plus-utils",
        tool_version="0.1.0",
        tool_source_commit="3" * 40,
        now=lambda: next(execution_ticks),
        receipt_id_factory=lambda: "a" * 32,
    )
    output_parent = _private_dir(operation_path.parent / "wrong-recovery-route")
    output_path = output_parent / "recovery.json"

    with pytest.raises(RxOnlyReleaseCandidateLifecycleError, match="recovery proof"):
        recover_rx_only_candidate_ram(
            operation_path.parent / SERIAL / "ram-receipt.json",
            password_path=password_path,
            confirmation=f"RECOVER RX-ONLY RELEASE CANDIDATE {SERIAL} ad9361-1r1t",
            output_path=output_path,
            backend=FakeBackend(route_destination="192.168.3.1/32"),
            tool_repository="misko/pluto-plus-utils",
            tool_version="0.1.0",
            tool_source_commit="3" * 40,
            now=lambda: NOW + timedelta(minutes=2),
        )

    assert not output_path.exists()


def test_v2_recovery_preflights_private_output_before_backend(tmp_path: Path) -> None:
    operation_path, password_path, phrase = _bundle(tmp_path)
    ticks = iter((NOW, NOW + timedelta(minutes=1)))
    execute_rx_only_candidate_ram(
        operation_path,
        password_path=password_path,
        confirmation=phrase,
        backend=FakeBackend(),
        tool_repository="misko/pluto-plus-utils",
        tool_version="0.1.0",
        tool_source_commit="3" * 40,
        now=lambda: next(ticks),
        receipt_id_factory=lambda: "a" * 32,
    )
    backend = FakeBackend()

    with pytest.raises(RxOnlyReleaseCandidateLifecycleError, match="parent"):
        recover_rx_only_candidate_ram(
            operation_path.parent / SERIAL / "ram-receipt.json",
            password_path=password_path,
            confirmation=f"RECOVER RX-ONLY RELEASE CANDIDATE {SERIAL} ad9361-1r1t",
            output_path=operation_path.parent / "missing" / "recovery.json",
            backend=backend,
            tool_repository="misko/pluto-plus-utils",
            tool_version="0.1.0",
            tool_source_commit="3" * 40,
        )
    assert backend.calls == []
