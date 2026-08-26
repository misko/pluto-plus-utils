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
    CleanupReceipt,
    ContentIdentity,
    DfuIdentity,
    ExpectedRuntime,
    FileIdentity,
    HostRouteReceipt,
    QspiObservation,
    ReleaseCandidateOperationPlan,
    ReleaseCandidatePlan,
    ReleaseUsbInventory,
    RuntimeObservation,
    SafeState,
    UsbInventoryTarget,
    build_operation_plan,
    load_private_contract,
    model_file_identity,
    validate_contract_bundle,
    write_private_contract,
)
from pluto_plus.release_candidate_lifecycle import (
    DFU_SELECTOR,
    FailureReconciliation,
    PasswordFileIdentity,
    ReleaseCandidateLifecycleError,
    dfu_detach_argv,
    dfu_download_argv,
    execute_candidate_ram,
    ssh_ram_argv,
    validate_password_file,
)

NOW = datetime(2026, 8, 26, 17, 0, tzinfo=UTC)
SERIAL = "winbond-db6968136727402c"
TOPOLOGY = "3-7"
INTERFACE = "enx00e02215c53b"
MODEL = "Analog Devices PlutoSDR Rev.C (Z7010-AD9361)"
OLD_FIRMWARE = "v0.41-plutoplus-spf-tandem-agc-v8-rc12"
NEW_FIRMWARE = "v0.41-plutoplus-spf-tandem-agc-v8-rc14"


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


def _target() -> UsbInventoryTarget:
    return UsbInventoryTarget(
        serial=SERIAL,
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


def _runtime(*, firmware: str, boot: str) -> RuntimeObservation:
    return RuntimeObservation(
        serial=SERIAL,
        topology=TOPOLOGY,
        usb_uri="usb:3.29.5",
        hardware_model=MODEL,
        firmware_version=firmware,
        metadata_abi="frame-metadata-v5",
        capabilities=("tandem-agc",),
        boot_id=boot,
        qspi=QspiObservation(bytes=31_457_280, sha256="9" * 64),
        safe_state=_safe(),
    )


class FakeBackend:
    def __init__(self, *, fail_on: str | None = None) -> None:
        self.fail_on = fail_on
        self.calls: list[str] = []
        self.ssh_argv: tuple[str, ...] | None = None
        self.download_argv: tuple[str, ...] | None = None
        self.detach_argv: tuple[str, ...] | None = None
        self.sealed_payload: bytes | None = None
        self.attest_count = 0

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
        assert route.interface == INTERFACE
        validate_password_file(password.path, expected=password)
        self.attest_count += 1
        name = "attest-pre" if self.attest_count == 1 else "attest-post"
        self._call(name)
        return _runtime(
            firmware=expected_firmware,
            boot=(
                "11111111-1111-4111-8111-111111111111"
                if self.attest_count == 1
                else "22222222-2222-4222-8222-222222222222"
            ),
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
        return target

    def reconcile_failure(
        self,
        target: UsbInventoryTarget,
        *,
        candidate: ReleaseCandidatePlan,
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
                firmware=NEW_FIRMWARE,
                boot="33333333-3333-4333-8333-333333333333",
            ),
            cleanup=CleanupReceipt(verified=True),
        )


def _materialize_contracts(
    tmp_path: Path,
) -> tuple[Path, Path, Path, ReleaseCandidatePlan, ReleaseCandidateOperationPlan]:
    candidate_root = tmp_path / "candidate"
    candidate_root.mkdir(mode=0o700)
    artifact = candidate_root / "artifact"
    artifact.mkdir(mode=0o700)
    dfu = artifact / "candidate.dfu"
    dfu.write_bytes(_dfu())
    dfu.chmod(0o600)
    candidate = ReleaseCandidatePlan(
        candidate_id="1" * 32,
        created_at=NOW,
        source_repository="misko/plutosdr-fw",
        source_commit="2" * 40,
        device_tool_repository="misko/pluto-plus-utils",
        device_tool_version="0.1.0",
        device_tool_source_commit="5" * 40,
        artifact_index=FileIdentity(
            path=candidate_root / "candidate-index.json", bytes=100, sha256="3" * 64
        ),
        dfu=FileIdentity(
            path=dfu,
            bytes=len(_dfu()),
            sha256=__import__("hashlib").sha256(_dfu()).hexdigest(),
        ),
        fit=ContentIdentity(
            bytes=len(_fit()), sha256=__import__("hashlib").sha256(_fit()).hexdigest()
        ),
        expected_runtime=ExpectedRuntime(
            firmware_version=NEW_FIRMWARE,
            hardware_model=MODEL,
            metadata_abi="frame-metadata-v5",
            capabilities=("tandem-agc",),
        ),
        dfu_identity=DfuIdentity(),
    )
    candidate_path = candidate_root / "candidate-plan.json"
    write_private_contract(candidate_path, candidate)
    inventory = ReleaseUsbInventory(created_at=NOW, devices=(_target(),))
    inventory_path = candidate_root / "usb-inventory.json"
    write_private_contract(inventory_path, inventory)
    receipt_parent = candidate_root / "hardware" / "deploy" / SERIAL
    receipt_parent.mkdir(parents=True, mode=0o700)
    operation = build_operation_plan(
        candidate,
        inventory,
        candidate_path=candidate_path,
        inventory_path=inventory_path,
        serial=SERIAL,
        expected_current_firmware=OLD_FIRMWARE,
        receipt_path=receipt_parent / "ram-receipt.json",
        plan_id="4" * 32,
        created_at=NOW,
    )
    operation_path = candidate_root / "operation-plan.json"
    write_private_contract(operation_path, operation)
    password_parent = tmp_path / "credentials"
    password_parent.mkdir(mode=0o700)
    password = password_parent / "password"
    password.write_text("analog\n")
    password.chmod(0o600)
    return operation_path, candidate_path, password, candidate, operation


def _execute(
    tmp_path: Path, backend: FakeBackend
) -> tuple[ReleaseCandidatePlan, ReleaseCandidateOperationPlan]:
    operation_path, candidate_path, password, candidate, operation = _materialize_contracts(
        tmp_path
    )
    receipt, digest = execute_candidate_ram(
        operation_path,
        password_path=password,
        confirmation=f"RAM BOOT RELEASE CANDIDATE {SERIAL}",
        backend=backend,
        tool_repository="misko/pluto-plus-utils",
        tool_version="0.1.0",
        tool_source_commit="5" * 40,
        timeout_s=45,
        now=iter((NOW, NOW + timedelta(minutes=2))).__next__,
        receipt_id_factory=lambda: "6" * 32,
    )
    assert digest == model_file_identity(operation.receipt_path, receipt).sha256
    assert load_private_contract(operation.receipt_path, type(receipt)) == receipt
    validate_contract_bundle(
        candidate,
        operation,
        receipt,
        candidate_path=candidate_path,
        operation_path=operation_path,
    )
    return candidate, operation


def test_native_candidate_ram_success_uses_only_reviewed_vectors(tmp_path: Path) -> None:
    backend = FakeBackend()

    candidate, operation = _execute(tmp_path, backend)

    assert backend.sealed_payload == _dfu()
    assert backend.ssh_argv == ssh_ram_argv(operation, tmp_path / "credentials" / "password")
    assert backend.download_argv == dfu_download_argv(operation, Path("/proc/self/fd/42"))
    assert backend.detach_argv == dfu_detach_argv(operation)
    flattened = (*backend.ssh_argv, *backend.download_argv, *backend.detach_argv)
    assert "StrictHostKeyChecking=no" in flattened
    assert "UserKnownHostsFile=/dev/null" in flattened
    assert "GlobalKnownHostsFile=/dev/null" in flattened
    assert DFU_SELECTOR in flattened
    assert "-R" not in flattened
    assert "-S" not in flattened
    assert all("known_hosts" not in token for token in flattened)
    assert candidate.allowed_operation == "ram-only"
    assert backend.calls == [
        "locks",
        "target",
        "acquire-route",
        "attest-pre",
        "seal",
        "request",
        "wait-dfu",
        "download",
        "detach",
        "wait-runtime",
        "ensure-route",
        "attest-post",
        "release-route",
    ]


@pytest.mark.parametrize(
    ("phase", "download", "detach"),
    [
        ("request", False, False),
        ("wait-dfu", False, False),
        ("download", False, False),
        ("detach", True, False),
        ("wait-runtime", True, True),
        ("ensure-route", True, True),
        ("attest-post", True, True),
    ],
)
def test_mutation_failures_publish_unknown_receipt_and_release_route(
    tmp_path: Path, phase: str, download: bool, detach: bool
) -> None:
    operation_path, candidate_path, password, candidate, operation = _materialize_contracts(
        tmp_path
    )
    backend = FakeBackend(fail_on=phase)
    clock = iter((NOW, NOW + timedelta(minutes=2)))

    with pytest.raises(ReleaseCandidateLifecycleError) as caught:
        execute_candidate_ram(
            operation_path,
            password_path=password,
            confirmation=operation.confirmation_phrase,
            backend=backend,
            tool_repository="misko/pluto-plus-utils",
            tool_version="0.1.0",
            tool_source_commit="5" * 40,
            now=clock.__next__,
            receipt_id_factory=lambda: "7" * 32,
        )

    receipt = caught.value.receipt
    assert receipt is not None
    assert receipt.outcome == "unknown"
    assert receipt.transition.download_completed is download
    assert receipt.transition.detach_completed is detach
    assert receipt.host_route.release_verified is True
    assert receipt.cleanup.verified is True
    assert receipt.error == f"RuntimeError: planted {phase} failure"
    assert backend.calls[-2:] == ["reconcile", "release-route"]
    assert load_private_contract(operation.receipt_path, type(receipt)) == receipt
    validate_contract_bundle(
        candidate,
        operation,
        receipt,
        candidate_path=candidate_path,
        operation_path=operation_path,
    )


def test_preboot_failure_releases_route_without_publishing_receipt(tmp_path: Path) -> None:
    operation_path, _, password, _, operation = _materialize_contracts(tmp_path)
    backend = FakeBackend(fail_on="attest-pre")

    with pytest.raises(RuntimeError, match="planted attest-pre failure"):
        execute_candidate_ram(
            operation_path,
            password_path=password,
            confirmation=operation.confirmation_phrase,
            backend=backend,
            tool_repository="misko/pluto-plus-utils",
            tool_version="0.1.0",
            tool_source_commit="5" * 40,
        )

    assert backend.calls[-1] == "release-route"
    assert not operation.receipt_path.exists()


def test_route_release_failure_cannot_publish_success(tmp_path: Path) -> None:
    operation_path, _, password, _, operation = _materialize_contracts(tmp_path)
    backend = FakeBackend(fail_on="release-route")
    clock = iter((NOW, NOW + timedelta(minutes=2)))

    with pytest.raises(ReleaseCandidateLifecycleError) as caught:
        execute_candidate_ram(
            operation_path,
            password_path=password,
            confirmation=operation.confirmation_phrase,
            backend=backend,
            tool_repository="misko/pluto-plus-utils",
            tool_version="0.1.0",
            tool_source_commit="5" * 40,
            now=clock.__next__,
            receipt_id_factory=lambda: "8" * 32,
        )

    assert caught.value.receipt is not None
    assert caught.value.receipt.outcome == "unknown"
    assert caught.value.receipt.host_route.release_verified is False
    assert caught.value.receipt.cleanup.verified is False
    assert "host route release" in caught.value.receipt.cleanup.errors[0]


def test_password_identity_rejects_public_multiline_and_changed_file(tmp_path: Path) -> None:
    password = tmp_path / "password"
    password.write_text("analog\n")
    password.chmod(0o600)
    identity = validate_password_file(password)

    password.write_text("changed\n")
    password.chmod(0o600)
    with pytest.raises(ReleaseCandidateLifecycleError, match="changed after preflight"):
        validate_password_file(password, expected=identity)
    password.write_text("one\ntwo\n")
    password.chmod(0o600)
    with pytest.raises(ReleaseCandidateLifecycleError, match="exactly one"):
        validate_password_file(password)
    password.write_text("analog\n")
    password.chmod(0o644)
    with pytest.raises(ReleaseCandidateLifecycleError, match="mode-0600"):
        validate_password_file(password)


def test_candidate_dfu_substitution_is_rejected_before_backend_access(tmp_path: Path) -> None:
    operation_path, _, password, _, operation = _materialize_contracts(tmp_path)
    operation.candidate_plan.path.parent.joinpath("artifact/candidate.dfu").write_bytes(
        _dfu()[:-1] + b"x"
    )
    backend = FakeBackend()

    with pytest.raises(ReleaseCandidateLifecycleError, match="SHA-256"):
        execute_candidate_ram(
            operation_path,
            password_path=password,
            confirmation=operation.confirmation_phrase,
            backend=backend,
            tool_repository="misko/pluto-plus-utils",
            tool_version="0.1.0",
            tool_source_commit="5" * 40,
        )

    assert backend.calls == []


def test_wrong_confirmation_is_file_only_and_leaves_receipt_absent(tmp_path: Path) -> None:
    operation_path, _, password, _, operation = _materialize_contracts(tmp_path)
    backend = FakeBackend()

    with pytest.raises(ReleaseCandidateLifecycleError, match="confirmation"):
        execute_candidate_ram(
            operation_path,
            password_path=password,
            confirmation="RAM BOOT SOMETHING ELSE",
            backend=backend,
            tool_repository="misko/pluto-plus-utils",
            tool_version="0.1.0",
            tool_source_commit="5" * 40,
        )

    assert backend.calls == []
    assert not operation.receipt_path.exists()


@pytest.mark.parametrize(
    ("tool_repository", "tool_version", "tool_source_commit"),
    [
        ("someone-else/pluto-plus-utils", "0.1.0", "5" * 40),
        ("misko/pluto-plus-utils", "0.2.0", "5" * 40),
        ("misko/pluto-plus-utils", "0.1.0", "6" * 40),
    ],
)
def test_unplanned_device_tool_is_rejected_before_backend_access(
    tmp_path: Path,
    tool_repository: str,
    tool_version: str,
    tool_source_commit: str,
) -> None:
    operation_path, _, password, _, operation = _materialize_contracts(tmp_path)
    backend = FakeBackend()

    with pytest.raises(ReleaseCandidateLifecycleError, match="device tool identity"):
        execute_candidate_ram(
            operation_path,
            password_path=password,
            confirmation=operation.confirmation_phrase,
            backend=backend,
            tool_repository=tool_repository,
            tool_version=tool_version,
            tool_source_commit=tool_source_commit,
        )

    assert backend.calls == []
    assert not operation.receipt_path.exists()
