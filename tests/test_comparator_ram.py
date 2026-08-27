from __future__ import annotations

import hashlib
import subprocess
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

import pluto_plus.comparator_ram as comparator
from pluto_plus.comparator_ram import (
    COMPARATOR_PLAN_SCHEMA,
    COMPARATOR_RECEIPT_SCHEMA,
    ComparatorRamError,
    ComparatorRamPlan,
    ComparatorRamReceipt,
    ComparatorToolIdentity,
    attest_comparator_tool_repository,
    comparator_dfu_detach_argv,
    comparator_dfu_download_argv,
    comparator_ssh_argv,
    execute_comparator_ram,
    prepare_comparator_ram_plan,
    validate_comparator_contract_bundle,
    verify_comparator_ram_receipt,
)
from pluto_plus.firmware import (
    DFU_PRODUCT_ID,
    DFU_SPECIFICATION,
    DFU_VENDOR_ID,
    FIT_MAGIC,
    PLUTO_FRM_MAGIC,
)
from pluto_plus.release_candidate import (
    CleanupReceipt,
    ExpectedRuntime,
    FileIdentity,
    HostRouteReceipt,
    QspiObservation,
    ReleaseUsbInventory,
    RuntimeObservation,
    SafeState,
    UsbInventoryTarget,
    canonical_json_bytes,
    load_private_contract,
    model_file_identity,
    write_private_contract,
)
from pluto_plus.release_candidate_lifecycle import (
    FailureReconciliation,
    PasswordFileIdentity,
    validate_password_file,
)

NOW = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)
SERIAL = "winbond-db6968136727402c"
TOPOLOGY = "3-7"
INTERFACE = "enx00e02215c53b"
MODEL = "Analog Devices PlutoSDR Rev.C (Z7010-AD9361)"
OLD_FIRMWARE = "v0.41-plutoplus-spf-tandem-agc-v8-rc20"


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


@pytest.fixture(autouse=True)
def _small_approved_artifacts(monkeypatch: pytest.MonkeyPatch) -> None:
    bundle = b"approved-v7-test-bundle\n"
    monkeypatch.setattr(comparator, "APPROVED_V7_BUNDLE_BYTES", len(bundle))
    monkeypatch.setattr(comparator, "APPROVED_V7_BUNDLE_SHA256", hashlib.sha256(bundle).hexdigest())
    monkeypatch.setattr(comparator, "APPROVED_V7_DFU_BYTES", len(_dfu()))
    monkeypatch.setattr(comparator, "APPROVED_V7_DFU_SHA256", hashlib.sha256(_dfu()).hexdigest())
    monkeypatch.setattr(comparator, "APPROVED_V7_FIT_BYTES", len(_fit()))
    monkeypatch.setattr(comparator, "APPROVED_V7_FIT_SHA256", hashlib.sha256(_fit()).hexdigest())


def _target(*, serial: str = SERIAL) -> UsbInventoryTarget:
    return UsbInventoryTarget(
        serial=serial,
        topology=TOPOLOGY,
        sysfs_path=Path(f"/sys/bus/usb/devices/{TOPOLOGY}"),
        bus_number=3,
        device_number=29,
        network_interface=INTERFACE,
        source_ipv4="192.168.2.10",
    )


def _safe() -> SafeState:
    return SafeState(
        tx_gain_db=(-80.0, -80.0),
        dds_raw=(0,) * 8,
        dds_scale=(0.0,) * 8,
        dac_selectors=(3, 3, 3, 3),
        tandem_state="IDLE",
        fifo_level=0,
        fault_flags=0,
    )


def _runtime(
    *,
    firmware: str,
    boot: str,
    metadata: str,
    qspi_sha256: str = "9" * 64,
    serial: str = SERIAL,
) -> RuntimeObservation:
    return RuntimeObservation(
        serial=serial,
        topology=TOPOLOGY,
        usb_uri="usb:3.29.5",
        hardware_model=MODEL,
        firmware_version=firmware,
        metadata_abi=metadata,
        capabilities=("tandem-agc",),
        boot_id=boot,
        qspi=QspiObservation(bytes=31_457_280, sha256=qspi_sha256),
        safe_state=_safe(),
    )


def _tool(root: Path) -> ComparatorToolIdentity:
    repository = root / "tool"
    wrapper = repository / comparator.COMPARATOR_WRAPPER_RELATIVE
    return ComparatorToolIdentity(
        repository_path=repository,
        version="0.1.0",
        source_commit="5" * 40,
        source_tree_sha256="6" * 64,
        execution_wrapper=FileIdentity(path=wrapper, bytes=101, sha256="7" * 64),
    )


def _current_runtime() -> ExpectedRuntime:
    return ExpectedRuntime(
        firmware_version=OLD_FIRMWARE,
        hardware_model=MODEL,
        metadata_abi="frame-metadata-v5",
        capabilities=("tandem-agc",),
    )


def _materialize(
    tmp_path: Path,
) -> tuple[Path, Path, Path, ComparatorRamPlan, ComparatorToolIdentity]:
    tmp_path.chmod(0o700)
    archive = tmp_path / "archive"
    archive.mkdir(mode=0o700)
    bundle = archive / comparator.APPROVED_V7_BUNDLE_NAME
    bundle.write_bytes(b"approved-v7-test-bundle\n")
    bundle.chmod(0o600)
    dfu = archive / comparator.APPROVED_V7_DFU_NAME
    dfu.write_bytes(_dfu())
    dfu.chmod(0o600)
    inventory = ReleaseUsbInventory(created_at=NOW, devices=(_target(),))
    inventory_path = tmp_path / "usb-inventory.json"
    write_private_contract(inventory_path, inventory)
    receipt_parent = tmp_path / "receipts" / SERIAL
    receipt_parent.mkdir(parents=True, mode=0o700)
    tool = _tool(tmp_path)
    plan = prepare_comparator_ram_plan(
        inventory,
        inventory_path=inventory_path,
        retained_bundle_path=bundle,
        dfu_path=dfu,
        serial=SERIAL,
        expected_current_runtime=_current_runtime(),
        receipt_path=receipt_parent / "comparator-ram-receipt.json",
        tool=tool,
        created_at=NOW,
        expires_at=NOW + timedelta(minutes=15),
        plan_id="1" * 32,
    )
    plan_path = tmp_path / "comparator-ram-plan.json"
    write_private_contract(plan_path, plan)
    credentials = tmp_path / "credentials"
    credentials.mkdir(mode=0o700)
    password = credentials / "password"
    password.write_text("analog\n")
    password.chmod(0o600)
    return plan_path, plan.receipt_path, password, plan, tool


class FakeBackend:
    def __init__(
        self,
        *,
        fail_on: str | None = None,
        changed_qspi: bool = False,
        wrong_revalidated_target: bool = False,
        wrong_returned_target: bool = False,
        unexpected_route: bool = False,
        seal_callback: Callable[[], None] | None = None,
        lock_callback: Callable[[], None] | None = None,
    ) -> None:
        self.fail_on = fail_on
        self.changed_qspi = changed_qspi
        self.wrong_revalidated_target = wrong_revalidated_target
        self.wrong_returned_target = wrong_returned_target
        self.unexpected_route = unexpected_route
        self.seal_callback = seal_callback
        self.lock_callback = lock_callback
        self.calls: list[str] = []
        self.attest_count = 0
        self.ssh_argv: tuple[str, ...] | None = None
        self.download_argv: tuple[str, ...] | None = None
        self.detach_argv: tuple[str, ...] | None = None
        self.sealed_payload: bytes | None = None

    def _call(self, name: str) -> None:
        self.calls.append(name)
        if self.fail_on == name:
            raise RuntimeError(f"planted {name} failure")

    @contextmanager
    def transaction_locks(self, target: UsbInventoryTarget, ssh_host: str) -> Iterator[None]:
        assert target == _target()
        assert ssh_host == "192.168.2.1"
        self._call("locks")
        if self.lock_callback is not None:
            self.lock_callback()
        yield

    @contextmanager
    def sealed_dfu(self, payload: bytes) -> Iterator[Path]:
        self._call("seal")
        self.sealed_payload = payload
        if self.seal_callback is not None:
            self.seal_callback()
        yield Path("/proc/self/fd/42")

    def revalidate_target(self, target: UsbInventoryTarget) -> UsbInventoryTarget:
        self._call("target")
        return _target(serial="another-radio") if self.wrong_revalidated_target else target

    def acquire_host_route(self, target: UsbInventoryTarget, ssh_host: str) -> HostRouteReceipt:
        self._call("acquire-route")
        return HostRouteReceipt(
            destination=f"{ssh_host}/32",
            interface=("wrong0" if self.unexpected_route else target.network_interface),
            source=target.source_ipv4,
            release_verified=False,
        )

    def ensure_host_route(self, route: HostRouteReceipt, target: UsbInventoryTarget) -> None:
        assert route.interface == target.network_interface
        self._call("ensure-route")

    def release_host_route(self, route: HostRouteReceipt) -> None:
        assert route.destination == "192.168.2.1/32"
        self._call("release-route")

    def attest_runtime(
        self,
        target: UsbInventoryTarget,
        *,
        expected_firmware: str,
        password: PasswordFileIdentity,
        route: HostRouteReceipt,
    ) -> RuntimeObservation:
        assert target == _target()
        validate_password_file(password.path, expected=password)
        self.attest_count += 1
        phase = "attest-pre" if self.attest_count == 1 else "attest-post"
        self._call(phase)
        return _runtime(
            firmware=expected_firmware,
            metadata=("frame-metadata-v5" if self.attest_count == 1 else "frame-metadata-v2"),
            boot=(
                "11111111-1111-4111-8111-111111111111"
                if self.attest_count == 1
                else "22222222-2222-4222-8222-222222222222"
            ),
            qspi_sha256=("8" * 64 if self.changed_qspi and self.attest_count > 1 else "9" * 64),
        )

    def request_ram_mode(
        self,
        argv: Sequence[str],
        *,
        password: PasswordFileIdentity,
        route: HostRouteReceipt,
    ) -> None:
        validate_password_file(password.path, expected=password)
        assert route.destination == "192.168.2.1/32"
        self.ssh_argv = tuple(argv)
        self._call("request")

    def wait_for_dfu(self, target: UsbInventoryTarget, *, timeout_s: float) -> None:
        assert target == _target()
        assert timeout_s == 45
        self._call("wait-dfu")

    def download_dfu(self, argv: Sequence[str], *, sealed_path: Path) -> None:
        assert sealed_path == Path("/proc/self/fd/42")
        self.download_argv = tuple(argv)
        self._call("download")

    def detach_dfu(self, argv: Sequence[str]) -> None:
        self.detach_argv = tuple(argv)
        self._call("detach")

    def wait_for_runtime(
        self, target: UsbInventoryTarget, *, timeout_s: float
    ) -> UsbInventoryTarget:
        assert timeout_s == 45
        self._call("wait-runtime")
        return _target(serial="another-radio") if self.wrong_returned_target else target

    def reconcile_failure(
        self,
        target: UsbInventoryTarget,
        *,
        candidate: object,
        pre_runtime: RuntimeObservation,
        password: PasswordFileIdentity,
        route: HostRouteReceipt,
        timeout_s: float,
    ) -> FailureReconciliation:
        del candidate, route
        assert target == _target()
        assert pre_runtime.firmware_version == OLD_FIRMWARE
        assert timeout_s == 45
        validate_password_file(password.path, expected=password)
        self._call("reconcile")
        return FailureReconciliation(
            runtime=_runtime(
                firmware=comparator.APPROVED_V7_FIRMWARE,
                metadata="frame-metadata-v2",
                boot="33333333-3333-4333-8333-333333333333",
            ),
            cleanup=CleanupReceipt(verified=True),
        )


def _execute_success(
    tmp_path: Path, backend: FakeBackend | None = None
) -> tuple[ComparatorRamReceipt, ComparatorRamPlan, Path, ComparatorToolIdentity, FakeBackend]:
    plan_path, receipt_path, password, plan, tool = _materialize(tmp_path)
    selected_backend = backend or FakeBackend()
    clock = iter(
        (
            NOW + timedelta(minutes=1),
            NOW + timedelta(seconds=90),
            NOW + timedelta(minutes=2),
        )
    )
    receipt, digest = execute_comparator_ram(
        plan_path,
        expected_plan_sha256=model_file_identity(plan_path, plan).sha256,
        password_path=password,
        confirmation=plan.confirmation_phrase,
        backend=selected_backend,
        tool=tool,
        timeout_s=45,
        now=clock.__next__,
        receipt_id_factory=lambda: "2" * 32,
    )
    assert digest == model_file_identity(receipt_path, receipt).sha256
    return receipt, plan, plan_path, tool, selected_backend


def test_plan_is_native_expiring_and_binds_exact_v7_provenance(tmp_path: Path) -> None:
    plan_path, _, _, plan, _ = _materialize(tmp_path)

    assert plan.schema_id == COMPARATOR_PLAN_SCHEMA
    assert plan.allowed_operation == "ram-only"
    assert plan.hardware_accessed is False
    assert plan.confirmation_phrase == f"COMPARATOR RAM BOOT {SERIAL}"
    assert plan.artifact.profile_id == "tandem-agc-v7-release-ram"
    assert plan.artifact.source_commit == comparator.APPROVED_V7_SOURCE_COMMIT
    assert plan.harness.source_commit == comparator.APPROVED_V7_HARNESS_COMMIT
    assert plan.harness.frequencies_hz == (915_000_000, 2_450_000_000, 5_800_000_000)
    assert plan.tool.execution_wrapper.path == (
        plan.tool.repository_path / "src/pluto_plus/comparator_ram.py"
    )
    assert load_private_contract(plan_path, ComparatorRamPlan) == plan

    document = plan.model_dump(mode="json", by_alias=True)
    with pytest.raises(ValidationError, match="canonical private IPv4"):
        ComparatorRamPlan.model_validate({**document, "ssh_host": "8.8.8.8"})
    with pytest.raises(ValidationError, match="at most 30 minutes"):
        ComparatorRamPlan.model_validate(
            {**document, "expires_at": (NOW + timedelta(hours=1)).isoformat()}
        )


def test_success_uses_only_sealed_paired_ram_vectors_and_deep_replays(tmp_path: Path) -> None:
    receipt, plan, _, tool, backend = _execute_success(tmp_path)

    assert receipt.schema_id == COMPARATOR_RECEIPT_SCHEMA
    assert receipt.outcome == "pass"
    assert receipt.transition.persistent_write is False
    assert receipt.transition.reset_after_download is False
    assert backend.sealed_payload == _dfu()
    password = tmp_path / "credentials" / "password"
    assert backend.ssh_argv == comparator_ssh_argv(plan, password)
    assert backend.download_argv == comparator_dfu_download_argv(plan, Path("/proc/self/fd/42"))
    assert backend.detach_argv == comparator_dfu_detach_argv(plan)
    assert backend.ssh_argv is not None
    assert backend.download_argv is not None
    assert backend.detach_argv is not None
    flattened = (*backend.ssh_argv, *backend.download_argv, *backend.detach_argv)
    assert "0456:b673,0456:b674" in flattened
    assert "firmware.dfu" in flattened
    assert "-R" not in flattened
    assert "-S" not in flattened
    assert all("mtd" not in token.lower() for token in flattened)
    assert receipt.pre_runtime.boot_id != receipt.post_runtime.boot_id  # type: ignore[union-attr]
    assert receipt.pre_runtime.qspi == receipt.post_runtime.qspi  # type: ignore[union-attr]
    assert verify_comparator_ram_receipt(plan.receipt_path, tool=tool) == receipt


@pytest.mark.parametrize("phase", ["locks", "target", "attest-pre", "seal"])
def test_pre_mutation_failures_leave_no_receipt(tmp_path: Path, phase: str) -> None:
    plan_path, receipt_path, password, plan, tool = _materialize(tmp_path)
    backend = FakeBackend(fail_on=phase)

    with pytest.raises((ComparatorRamError, RuntimeError)):
        execute_comparator_ram(
            plan_path,
            expected_plan_sha256=model_file_identity(plan_path, plan).sha256,
            password_path=password,
            confirmation=plan.confirmation_phrase,
            backend=backend,
            tool=tool,
            now=lambda: NOW + timedelta(minutes=1),
        )

    assert not receipt_path.exists()
    if phase in {"attest-pre", "seal"}:
        assert backend.calls[-1] == "release-route"


def test_wrong_confirmation_and_stale_plan_are_file_only(tmp_path: Path) -> None:
    plan_path, receipt_path, password, plan, tool = _materialize(tmp_path)
    backend = FakeBackend()

    with pytest.raises(ComparatorRamError, match="confirmation"):
        execute_comparator_ram(
            plan_path,
            expected_plan_sha256=model_file_identity(plan_path, plan).sha256,
            password_path=password,
            confirmation="COMPARATOR RAM BOOT another-radio",
            backend=backend,
            tool=tool,
            now=lambda: NOW + timedelta(minutes=1),
        )
    with pytest.raises(ComparatorRamError, match="execution window"):
        execute_comparator_ram(
            plan_path,
            expected_plan_sha256=model_file_identity(plan_path, plan).sha256,
            password_path=password,
            confirmation=plan.confirmation_phrase,
            backend=backend,
            tool=tool,
            now=lambda: NOW + timedelta(hours=1),
        )
    with pytest.raises(ComparatorRamError, match="operator approval"):
        execute_comparator_ram(
            plan_path,
            expected_plan_sha256="0" * 64,
            password_path=password,
            confirmation=plan.confirmation_phrase,
            backend=backend,
            tool=tool,
            now=lambda: NOW + timedelta(minutes=1),
        )
    with pytest.raises(ComparatorRamError, match="utility source"):
        execute_comparator_ram(
            plan_path,
            expected_plan_sha256=model_file_identity(plan_path, plan).sha256,
            password_path=password,
            confirmation=plan.confirmation_phrase,
            backend=backend,
            tool=tool.model_copy(update={"source_tree_sha256": "0" * 64}),
            now=lambda: NOW + timedelta(minutes=1),
        )

    assert backend.calls == []
    assert not receipt_path.exists()


def test_plan_expiring_during_preflight_releases_route_before_mutation(
    tmp_path: Path,
) -> None:
    plan_path, receipt_path, password, plan, tool = _materialize(tmp_path)
    backend = FakeBackend()
    clock = iter((NOW + timedelta(minutes=14), NOW + timedelta(minutes=16)))

    with pytest.raises(ComparatorRamError, match="expired before the RAM mutation boundary"):
        execute_comparator_ram(
            plan_path,
            expected_plan_sha256=model_file_identity(plan_path, plan).sha256,
            password_path=password,
            confirmation=plan.confirmation_phrase,
            backend=backend,
            tool=tool,
            now=clock.__next__,
        )

    assert "request" not in backend.calls
    assert backend.calls[-2:] == ["seal", "release-route"]
    assert not receipt_path.exists()


def test_plan_changed_during_preflight_releases_route_before_mutation(
    tmp_path: Path,
) -> None:
    plan_path, receipt_path, password, plan, tool = _materialize(tmp_path)
    changed_plan = plan.model_copy(update={"expires_at": plan.expires_at - timedelta(seconds=1)})

    def replace_approved_plan() -> None:
        plan_path.write_bytes(canonical_json_bytes(changed_plan))
        plan_path.chmod(0o600)

    backend = FakeBackend(seal_callback=replace_approved_plan)

    with pytest.raises(ComparatorRamError, match="changed after operator approval"):
        execute_comparator_ram(
            plan_path,
            expected_plan_sha256=model_file_identity(plan_path, plan).sha256,
            password_path=password,
            confirmation=plan.confirmation_phrase,
            backend=backend,
            tool=tool,
            now=lambda: NOW + timedelta(minutes=1),
        )

    assert "request" not in backend.calls
    assert backend.calls[-2:] == ["seal", "release-route"]
    assert not receipt_path.exists()


def test_receipt_published_while_waiting_for_lock_prevents_hardware_access(
    tmp_path: Path,
) -> None:
    plan_path, receipt_path, password, plan, tool = _materialize(tmp_path)

    def publish_competing_receipt() -> None:
        receipt_path.write_text("competing executor published this receipt\n")
        receipt_path.chmod(0o600)

    backend = FakeBackend(lock_callback=publish_competing_receipt)

    with pytest.raises(ComparatorRamError, match="destination must be absent"):
        execute_comparator_ram(
            plan_path,
            expected_plan_sha256=model_file_identity(plan_path, plan).sha256,
            password_path=password,
            confirmation=plan.confirmation_phrase,
            backend=backend,
            tool=tool,
            now=lambda: NOW + timedelta(minutes=1),
        )

    assert backend.calls == ["locks"]
    assert receipt_path.read_text() == "competing executor published this receipt\n"


def test_plan_changed_while_waiting_for_lock_prevents_hardware_access(
    tmp_path: Path,
) -> None:
    plan_path, receipt_path, password, plan, tool = _materialize(tmp_path)
    changed_plan = plan.model_copy(update={"expires_at": plan.expires_at - timedelta(seconds=1)})

    def replace_approved_plan() -> None:
        plan_path.write_bytes(canonical_json_bytes(changed_plan))
        plan_path.chmod(0o600)

    backend = FakeBackend(lock_callback=replace_approved_plan)

    with pytest.raises(ComparatorRamError, match="changed after operator approval"):
        execute_comparator_ram(
            plan_path,
            expected_plan_sha256=model_file_identity(plan_path, plan).sha256,
            password_path=password,
            confirmation=plan.confirmation_phrase,
            backend=backend,
            tool=tool,
            now=lambda: NOW + timedelta(minutes=1),
        )

    assert backend.calls == ["locks"]
    assert not receipt_path.exists()


def test_artifact_mutation_is_rejected_before_locks(tmp_path: Path) -> None:
    plan_path, receipt_path, password, plan, tool = _materialize(tmp_path)
    plan.artifact.dfu.path.write_bytes(_dfu()[:-1] + b"x")
    plan.artifact.dfu.path.chmod(0o600)
    backend = FakeBackend()

    with pytest.raises(ComparatorRamError, match="DFU changed"):
        execute_comparator_ram(
            plan_path,
            expected_plan_sha256=model_file_identity(plan_path, plan).sha256,
            password_path=password,
            confirmation=plan.confirmation_phrase,
            backend=backend,
            tool=tool,
            now=lambda: NOW + timedelta(minutes=1),
        )

    assert backend.calls == []
    assert not receipt_path.exists()


def test_wrong_returned_radio_publishes_unknown_receipt(tmp_path: Path) -> None:
    plan_path, receipt_path, password, plan, tool = _materialize(tmp_path)
    backend = FakeBackend(wrong_returned_target=True)
    clock = iter(
        (
            NOW + timedelta(minutes=1),
            NOW + timedelta(seconds=90),
            NOW + timedelta(minutes=2),
        )
    )

    with pytest.raises(ComparatorRamError, match="returned runtime") as caught:
        execute_comparator_ram(
            plan_path,
            expected_plan_sha256=model_file_identity(plan_path, plan).sha256,
            password_path=password,
            confirmation=plan.confirmation_phrase,
            backend=backend,
            tool=tool,
            now=clock.__next__,
            receipt_id_factory=lambda: "3" * 32,
        )

    assert caught.value.receipt is not None
    assert caught.value.receipt.outcome == "unknown"
    assert receipt_path.exists()
    assert backend.calls[-2:] == ["reconcile", "release-route"]


def test_wrong_preflight_radio_is_rejected_without_a_receipt(tmp_path: Path) -> None:
    plan_path, receipt_path, password, plan, tool = _materialize(tmp_path)
    backend = FakeBackend(wrong_revalidated_target=True)

    with pytest.raises(ComparatorRamError, match="live target changed"):
        execute_comparator_ram(
            plan_path,
            expected_plan_sha256=model_file_identity(plan_path, plan).sha256,
            password_path=password,
            confirmation=plan.confirmation_phrase,
            backend=backend,
            tool=tool,
            now=lambda: NOW + timedelta(minutes=1),
        )

    assert backend.calls == ["locks", "target"]
    assert not receipt_path.exists()


def test_qspi_change_cannot_publish_pass(tmp_path: Path) -> None:
    plan_path, receipt_path, password, plan, tool = _materialize(tmp_path)
    backend = FakeBackend(changed_qspi=True)
    clock = iter(
        (
            NOW + timedelta(minutes=1),
            NOW + timedelta(seconds=90),
            NOW + timedelta(minutes=2),
        )
    )

    with pytest.raises(ComparatorRamError, match="qspi-linux") as caught:
        execute_comparator_ram(
            plan_path,
            expected_plan_sha256=model_file_identity(plan_path, plan).sha256,
            password_path=password,
            confirmation=plan.confirmation_phrase,
            backend=backend,
            tool=tool,
            now=clock.__next__,
            receipt_id_factory=lambda: "4" * 32,
        )

    assert caught.value.receipt is not None
    assert caught.value.receipt.outcome == "unknown"
    assert load_private_contract(receipt_path, ComparatorRamReceipt).outcome == "unknown"


@pytest.mark.parametrize(
    ("phase", "download_completed", "detach_completed"),
    [
        ("request", False, False),
        ("download", False, False),
        ("detach", True, False),
        ("attest-post", True, True),
    ],
)
def test_mutation_failure_receipts_are_durable_and_route_released(
    tmp_path: Path, phase: str, download_completed: bool, detach_completed: bool
) -> None:
    plan_path, receipt_path, password, plan, tool = _materialize(tmp_path)
    backend = FakeBackend(fail_on=phase)
    clock = iter(
        (
            NOW + timedelta(minutes=1),
            NOW + timedelta(seconds=90),
            NOW + timedelta(minutes=2),
        )
    )

    with pytest.raises(ComparatorRamError) as caught:
        execute_comparator_ram(
            plan_path,
            expected_plan_sha256=model_file_identity(plan_path, plan).sha256,
            password_path=password,
            confirmation=plan.confirmation_phrase,
            backend=backend,
            tool=tool,
            now=clock.__next__,
            receipt_id_factory=lambda: "5" * 32,
        )

    receipt = caught.value.receipt
    assert receipt is not None
    assert receipt.outcome == "unknown"
    assert receipt.transition.download_completed is download_completed
    assert receipt.transition.detach_completed is detach_completed
    assert receipt.host_route.release_verified is True
    assert receipt.cleanup.verified is True
    assert load_private_contract(receipt_path, ComparatorRamReceipt) == receipt


def test_route_and_cleanup_failures_cannot_publish_success(tmp_path: Path) -> None:
    plan_path, receipt_path, password, plan, tool = _materialize(tmp_path)
    unexpected = FakeBackend(unexpected_route=True)
    with pytest.raises(ComparatorRamError, match="unexpected comparator host route"):
        execute_comparator_ram(
            plan_path,
            expected_plan_sha256=model_file_identity(plan_path, plan).sha256,
            password_path=password,
            confirmation=plan.confirmation_phrase,
            backend=unexpected,
            tool=tool,
            now=lambda: NOW + timedelta(minutes=1),
        )
    assert unexpected.calls[-1] == "release-route"
    assert not receipt_path.exists()

    second_root = tmp_path / "second"
    second_root.mkdir(mode=0o700)
    plan_path, receipt_path, password, plan, tool = _materialize(second_root)
    cleanup_failure = FakeBackend(fail_on="release-route")
    clock = iter(
        (
            NOW + timedelta(minutes=1),
            NOW + timedelta(seconds=90),
            NOW + timedelta(minutes=2),
        )
    )
    with pytest.raises(ComparatorRamError) as caught:
        execute_comparator_ram(
            plan_path,
            expected_plan_sha256=model_file_identity(plan_path, plan).sha256,
            password_path=password,
            confirmation=plan.confirmation_phrase,
            backend=cleanup_failure,
            tool=tool,
            now=clock.__next__,
            receipt_id_factory=lambda: "6" * 32,
        )
    assert caught.value.receipt is not None
    assert caught.value.receipt.outcome == "unknown"
    assert caught.value.receipt.host_route.release_verified is False
    assert caught.value.receipt.cleanup.verified is False
    assert receipt_path.exists()


def test_semantic_replay_rejects_plan_and_receipt_substitution(tmp_path: Path) -> None:
    receipt, plan, plan_path, _, _ = _execute_success(tmp_path)

    wrong_plan_identity = receipt.model_copy(
        update={
            "plan": receipt.plan.model_copy(update={"sha256": "0" * 64}),
        }
    )
    with pytest.raises(ComparatorRamError, match="exact plan bytes"):
        validate_comparator_contract_bundle(plan, wrong_plan_identity, plan_path=plan_path)
    wrong_target = receipt.model_copy(update={"target": _target(serial="other-radio")})
    with pytest.raises(ComparatorRamError, match="semantics differ"):
        validate_comparator_contract_bundle(plan, wrong_target, plan_path=plan_path)
    out_of_window = receipt.model_copy(
        update={
            "started_at": plan.expires_at + timedelta(seconds=1),
            "completed_at": plan.expires_at + timedelta(seconds=2),
        }
    )
    with pytest.raises(ComparatorRamError, match="outside the approved execution window"):
        validate_comparator_contract_bundle(plan, out_of_window, plan_path=plan_path)
    assert receipt.transition.persistent_write is False
    with pytest.raises(ValidationError, match="persistent_write"):
        ComparatorRamReceipt.model_validate(
            {
                **receipt.model_dump(mode="json", by_alias=True),
                "transition": {
                    **receipt.transition.model_dump(mode="json"),
                    "persistent_write": True,
                },
            }
        )


def test_clean_tool_attestation_binds_tree_wrapper_and_rejects_dirty_source(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repo"
    wrapper = repository / comparator.COMPARATOR_WRAPPER_RELATIVE
    wrapper.parent.mkdir(parents=True)
    wrapper.write_text("# reviewed comparator wrapper\n")
    wrapper.chmod(0o644)
    subprocess.run(("git", "-C", str(repository), "init", "-q"), check=True)
    subprocess.run(
        ("git", "-C", str(repository), "config", "user.email", "test@example.invalid"),
        check=True,
    )
    subprocess.run(("git", "-C", str(repository), "config", "user.name", "Test"), check=True)
    subprocess.run(("git", "-C", str(repository), "add", "."), check=True)
    subprocess.run(("git", "-C", str(repository), "commit", "-qm", "initial"), check=True)
    subprocess.run(
        (
            "git",
            "-C",
            str(repository),
            "remote",
            "add",
            "origin",
            "git@github.com:misko/pluto-plus-utils.git",
        ),
        check=True,
    )

    identity = attest_comparator_tool_repository(
        repository.absolute(), version="0.1.0", wrapper_path=wrapper.absolute()
    )

    assert identity.execution_wrapper.sha256 == hashlib.sha256(wrapper.read_bytes()).hexdigest()
    assert len(identity.source_tree_sha256) == 64
    wrapper.chmod(0o664)
    assert (
        attest_comparator_tool_repository(
            repository.absolute(), version="0.1.0", wrapper_path=wrapper.absolute()
        ).execution_wrapper
        == identity.execution_wrapper
    )
    wrapper.chmod(0o666)
    with pytest.raises(ComparatorRamError, match="permitted writable mode"):
        attest_comparator_tool_repository(
            repository.absolute(), version="0.1.0", wrapper_path=wrapper.absolute()
        )
    wrapper.chmod(0o660)
    with pytest.raises(ComparatorRamError, match="permitted writable mode"):
        attest_comparator_tool_repository(
            repository.absolute(), version="0.1.0", wrapper_path=wrapper.absolute()
        )
    wrapper.chmod(0o664)
    wrapper.write_text("# changed\n")
    with pytest.raises(Exception, match="fully clean"):
        attest_comparator_tool_repository(
            repository.absolute(), version="0.1.0", wrapper_path=wrapper.absolute()
        )
