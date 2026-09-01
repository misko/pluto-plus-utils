"""Backend-neutral RX-only release-candidate RAM coordinator."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import uuid
from collections.abc import Callable, Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Protocol

from pluto_plus.firmware import FirmwareImageError, validate_dfu
from pluto_plus.release_candidate import (
    CleanupReceipt,
    ContentIdentity,
    HostRouteReceipt,
    ReleaseUsbInventory,
    TransitionReceipt,
    UsbInventoryTarget,
    load_private_contract,
    model_file_identity,
    write_private_contract,
)
from pluto_plus.release_candidate_lifecycle import (
    DFU_ALTERNATE,
    DFU_SELECTOR,
    REMOTE_RAM_COMMAND,
    PasswordFileIdentity,
    ssh_fixed_argv,
    validate_password_file,
)
from pluto_plus.release_candidate_rx_only import (
    RX_ONLY_RAM_RECEIPT_SCHEMA,
    RX_ONLY_RECOVERY_RECEIPT_SCHEMA,
    PrebootQuiesceReceiptV2,
    ReleaseCandidateOperationPlanV2,
    ReleaseCandidatePlanV2,
    ReleaseCandidateRamReceiptV2,
    ReleaseCandidateRecoveryReceiptV2,
    RuntimeObservationV2,
    RxOnlyRuntimeTarget,
    validate_rx_only_contract_bundle,
    validate_rx_only_recovery_bundle,
    validate_rx_only_recovery_source,
)


class RxOnlyReleaseCandidateLifecycleError(RuntimeError):
    """A v2 transition failed, optionally after publishing its v2 receipt."""

    def __init__(
        self,
        message: str,
        *,
        receipt: ReleaseCandidateRamReceiptV2 | None = None,
        receipt_sha256: str | None = None,
    ) -> None:
        super().__init__(message)
        self.receipt = receipt
        self.receipt_sha256 = receipt_sha256


# Keep the coordinator readable while retaining a distinct exception type at
# its public boundary.  Errors raised by shared v1-safe primitives are allowed
# to propagate unchanged; neither carries a v2 receipt.
ReleaseCandidateLifecycleError = RxOnlyReleaseCandidateLifecycleError


@dataclass(frozen=True, slots=True)
class RxOnlyFailureReconciliation:
    runtime: RuntimeObservationV2 | None
    cleanup: CleanupReceipt


@dataclass(frozen=True, slots=True)
class RxOnlyPersistentRecoveryResult:
    runtime: RuntimeObservationV2
    quiesce: PrebootQuiesceReceiptV2
    host_route: HostRouteReceipt
    dfu_detach_completed: bool
    pre_reset_usb_departure_verified: Literal[True]


class RxOnlyReleaseCandidateRamBackend(Protocol):
    """Physical operations required by the isolated v2 coordinator."""

    def transaction_locks(
        self, target: UsbInventoryTarget, ssh_host: str
    ) -> AbstractContextManager[None]: ...

    def sealed_dfu(self, payload: bytes) -> AbstractContextManager[Path]: ...

    def revalidate_target(self, target: UsbInventoryTarget) -> UsbInventoryTarget: ...

    def acquire_host_route(self, target: UsbInventoryTarget, ssh_host: str) -> HostRouteReceipt: ...

    def ensure_host_route(self, route: HostRouteReceipt, target: UsbInventoryTarget) -> None: ...

    def release_host_route(self, route: HostRouteReceipt) -> None: ...

    def quiesce_and_attest_preboot_v2(
        self,
        target: UsbInventoryTarget,
        *,
        runtime_target: RxOnlyRuntimeTarget,
        expected_firmware: str,
        password: PasswordFileIdentity,
        route: HostRouteReceipt,
    ) -> tuple[RuntimeObservationV2, PrebootQuiesceReceiptV2]: ...

    def attest_rx_only_runtime_v2(
        self,
        target: UsbInventoryTarget,
        *,
        runtime_target: RxOnlyRuntimeTarget,
        expected_firmware: str,
        password: PasswordFileIdentity,
        route: HostRouteReceipt,
    ) -> RuntimeObservationV2: ...

    def request_ram_mode(
        self,
        argv: Sequence[str],
        *,
        password: PasswordFileIdentity,
        route: HostRouteReceipt,
    ) -> None: ...

    def wait_for_dfu(self, target: UsbInventoryTarget, *, timeout_s: float) -> None: ...

    def download_dfu(self, argv: Sequence[str], *, sealed_path: Path) -> None: ...

    def detach_dfu(self, argv: Sequence[str]) -> None: ...

    def wait_for_runtime(
        self, target: UsbInventoryTarget, *, timeout_s: float
    ) -> UsbInventoryTarget: ...

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
    ) -> RxOnlyFailureReconciliation: ...

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
    ) -> RxOnlyPersistentRecoveryResult: ...


def ssh_ram_argv_v2(
    operation: ReleaseCandidateOperationPlanV2, password_path: Path
) -> tuple[str, ...]:
    return ssh_fixed_argv(
        operation.target,
        ssh_host=operation.ssh_host,
        password_path=password_path,
        remote_command=REMOTE_RAM_COMMAND,
    )


def dfu_download_argv_v2(
    operation: ReleaseCandidateOperationPlanV2, sealed_path: Path
) -> tuple[str, ...]:
    return (
        "dfu-util",
        "-d",
        DFU_SELECTOR,
        "-p",
        operation.target.topology,
        "-a",
        DFU_ALTERNATE,
        "-D",
        str(sealed_path),
    )


def dfu_detach_argv_v2(operation: ReleaseCandidateOperationPlanV2) -> tuple[str, ...]:
    return (
        "dfu-util",
        "-d",
        DFU_SELECTOR,
        "-p",
        operation.target.topology,
        "-a",
        DFU_ALTERNATE,
        "-e",
    )


def execute_rx_only_candidate_ram(
    operation_path: Path,
    *,
    password_path: Path,
    confirmation: str,
    backend: RxOnlyReleaseCandidateRamBackend,
    tool_repository: str,
    tool_version: str,
    tool_source_commit: str,
    timeout_s: float = 45.0,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
    receipt_id_factory: Callable[[], str] = lambda: uuid.uuid4().hex,
) -> tuple[ReleaseCandidateRamReceiptV2, str]:
    """Execute one exact v2 plan without entering the legacy v1 attestor."""

    if timeout_s <= 0:
        raise ValueError("candidate RAM timeout must be positive")
    selected_operation = _absolute_path(operation_path, label="operation plan")
    operation = load_private_contract(selected_operation, ReleaseCandidateOperationPlanV2)
    if confirmation != operation.confirmation_phrase:
        raise ReleaseCandidateLifecycleError(
            f"confirmation must be exactly {operation.confirmation_phrase!r}"
        )
    candidate_path = operation.candidate_plan.path
    candidate = load_private_contract(candidate_path, ReleaseCandidatePlanV2)
    if model_file_identity(candidate_path, candidate) != operation.candidate_plan:
        raise ReleaseCandidateLifecycleError("operation does not bind current candidate bytes")
    if (
        tool_repository != candidate.device_tool_repository
        or tool_version != candidate.device_tool_version
        or tool_source_commit != candidate.device_tool_source_commit
    ):
        raise ReleaseCandidateLifecycleError(
            "executing device tool identity does not match the candidate plan"
        )
    inventory = load_private_contract(operation.usb_inventory.path, ReleaseUsbInventory)
    if model_file_identity(operation.usb_inventory.path, inventory) != operation.usb_inventory:
        raise ReleaseCandidateLifecycleError("operation does not bind current inventory bytes")
    matches = tuple(item for item in inventory.devices if item.serial == operation.target.serial)
    if matches != (operation.target,):
        raise ReleaseCandidateLifecycleError("operation target is not exact in the inventory")
    password = validate_password_file(password_path)
    try:
        password.path.relative_to(candidate.artifact_index.path.parent)
    except ValueError:
        pass
    else:
        raise ReleaseCandidateLifecycleError(
            "SSH password file must be outside the candidate archive"
        )
    payload = _read_candidate_dfu(candidate)
    _require_absent_receipt(operation.receipt_path, serial=operation.target.serial)
    started_at = _utc(now(), label="execution start")

    with backend.transaction_locks(operation.target, operation.ssh_host):
        fresh_target = backend.revalidate_target(operation.target)
        if fresh_target != operation.target:
            raise ReleaseCandidateLifecycleError("live target changed from the operation plan")
        route = backend.acquire_host_route(operation.target, operation.ssh_host)
        expected_route = HostRouteReceipt(
            destination=f"{operation.ssh_host}/32",
            interface=operation.target.network_interface,
            source=operation.target.source_ipv4,
            release_verified=False,
        )
        if route != expected_route:
            _release_after_preflight_failure(backend, route)
            raise ReleaseCandidateLifecycleError("backend acquired an unexpected host route")
        try:
            pre, quiesce = backend.quiesce_and_attest_preboot_v2(
                operation.target,
                runtime_target=operation.runtime_target,
                expected_firmware=operation.expected_current_firmware,
                password=password,
                route=route,
            )
            _validate_pre_runtime(pre, operation, candidate)
        except BaseException:
            # Quiesce writes only move TX toward the reviewed safe state.  They
            # are intentionally not reversed when preflight fails.
            _release_after_preflight_failure(backend, route)
            raise

        mutation_started = False
        download_completed = False
        detach_completed = False
        post: RuntimeObservationV2 | None = None
        failure_phase = "request-ram-mode"
        try:
            with backend.sealed_dfu(payload) as sealed_path:
                _validate_sealed_path(sealed_path)
                password = validate_password_file(password.path, expected=password)
                mutation_started = True
                backend.request_ram_mode(
                    ssh_ram_argv_v2(operation, password.path),
                    password=password,
                    route=route,
                )
                failure_phase = "wait-for-dfu"
                backend.wait_for_dfu(operation.target, timeout_s=timeout_s)
                failure_phase = "download-dfu"
                backend.download_dfu(
                    dfu_download_argv_v2(operation, sealed_path), sealed_path=sealed_path
                )
                download_completed = True
                failure_phase = "detach-dfu"
                backend.detach_dfu(dfu_detach_argv_v2(operation))
                detach_completed = True
                failure_phase = "wait-for-runtime"
                returned = backend.wait_for_runtime(operation.target, timeout_s=timeout_s)
                if not _same_physical_target(returned, operation.target):
                    raise ReleaseCandidateLifecycleError(
                        "returned runtime differs from the exact operation target"
                    )
                failure_phase = "postboot-route"
                backend.ensure_host_route(route, returned)
                failure_phase = "postboot-attestation"
                password = validate_password_file(password.path, expected=password)
                post = backend.attest_rx_only_runtime_v2(
                    returned,
                    runtime_target=operation.runtime_target,
                    expected_firmware=candidate.expected_runtime.firmware_version,
                    password=password,
                    route=route,
                )
                _validate_post_runtime(pre, post, operation, candidate)
        except BaseException as error:
            return _publish_uncertain_receipt(
                error,
                backend=backend,
                operation=operation,
                operation_path=selected_operation,
                candidate=candidate,
                candidate_path=candidate_path,
                password=password,
                route=route,
                pre=pre,
                quiesce=quiesce,
                failure_phase=failure_phase,
                mutation_started=mutation_started,
                download_completed=download_completed,
                detach_completed=detach_completed,
                started_at=started_at,
                tool_repository=tool_repository,
                tool_version=tool_version,
                tool_source_commit=tool_source_commit,
                timeout_s=timeout_s,
                now=now,
                receipt_id_factory=receipt_id_factory,
            )

        assert post is not None
        try:
            backend.release_host_route(route)
        except BaseException as error:
            return _publish_uncertain_receipt(
                error,
                backend=backend,
                operation=operation,
                operation_path=selected_operation,
                candidate=candidate,
                candidate_path=candidate_path,
                password=password,
                route=route,
                pre=pre,
                quiesce=quiesce,
                failure_phase="release-host-route",
                mutation_started=True,
                download_completed=True,
                detach_completed=True,
                started_at=started_at,
                tool_repository=tool_repository,
                tool_version=tool_version,
                tool_source_commit=tool_source_commit,
                timeout_s=timeout_s,
                now=now,
                receipt_id_factory=receipt_id_factory,
            )
        receipt = _receipt(
            receipt_id=receipt_id_factory(),
            outcome="pass",
            started_at=started_at,
            completed_at=_utc(now(), label="execution completion"),
            tool_repository=tool_repository,
            tool_version=tool_version,
            tool_source_commit=tool_source_commit,
            operation=operation,
            operation_path=selected_operation,
            candidate=candidate,
            candidate_path=candidate_path,
            pre=pre,
            post=post,
            quiesce=quiesce,
            route=route.model_copy(update={"release_verified": True}),
            transition=TransitionReceipt(
                topology=operation.target.topology,
                sealed_input=True,
                download_completed=True,
                detach_completed=True,
            ),
            cleanup=CleanupReceipt(verified=True),
        )
        validate_rx_only_contract_bundle(
            candidate,
            operation,
            receipt,
            candidate_path=candidate_path,
            operation_path=selected_operation,
        )
        identity = write_private_contract(operation.receipt_path, receipt)
        return receipt, identity.sha256


def recover_rx_only_candidate_ram(
    receipt_path: Path,
    *,
    password_path: Path,
    confirmation: str,
    output_path: Path,
    backend: RxOnlyReleaseCandidateRamBackend,
    tool_repository: str,
    tool_version: str,
    tool_source_commit: str,
    timeout_s: float = 45.0,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
    recovery_id_factory: Callable[[], str] = lambda: uuid.uuid4().hex,
) -> tuple[ReleaseCandidateRecoveryReceiptV2, str]:
    """Roll one PASS or transition-started UNKNOWN back to persistent 1R1T."""

    if timeout_s <= 0:
        raise ValueError("candidate recovery timeout must be positive")
    selected_receipt = _absolute_path(receipt_path, label="source receipt")
    source = load_private_contract(selected_receipt, ReleaseCandidateRamReceiptV2)
    operation = load_private_contract(
        source.operation_plan.path, ReleaseCandidateOperationPlanV2
    )
    candidate = load_private_contract(source.candidate_plan.path, ReleaseCandidatePlanV2)
    validate_rx_only_contract_bundle(
        candidate,
        operation,
        source,
        candidate_path=source.candidate_plan.path,
        operation_path=source.operation_plan.path,
    )
    if selected_receipt != operation.receipt_path:
        raise ReleaseCandidateLifecycleError(
            "source receipt path differs from its operation plan"
        )
    try:
        validate_rx_only_recovery_source(source)
    except ValueError as error:
        raise ReleaseCandidateLifecycleError(str(error)) from error
    assert source.pre_runtime is not None
    expected_confirmation = (
        f"RECOVER RX-ONLY RELEASE CANDIDATE {source.target.serial} "
        f"{source.runtime_target}"
    )
    if confirmation != expected_confirmation:
        raise ReleaseCandidateLifecycleError(
            f"recovery requires exact confirmation {expected_confirmation!r}"
        )
    if (
        tool_repository != candidate.device_tool_repository
        or tool_version != candidate.device_tool_version
        or tool_source_commit != candidate.device_tool_source_commit
    ):
        raise ReleaseCandidateLifecycleError(
            "recovering device tool identity does not match the candidate plan"
        )
    password = validate_password_file(password_path)
    try:
        password.path.relative_to(candidate.artifact_index.path.parent)
    except ValueError:
        pass
    else:
        raise ReleaseCandidateLifecycleError(
            "SSH password file must be outside the candidate archive"
        )
    selected_output = _absolute_path(output_path, label="recovery receipt")
    _require_absent_private_output(selected_output, label="recovery receipt")
    started_at = _utc(now(), label="recovery start")
    with backend.transaction_locks(source.target, operation.ssh_host):
        result = backend.recover_to_persistent_v2(
            source.target,
            pre_runtime=source.pre_runtime,
            runtime_target=source.runtime_target,
            expected_firmware=operation.expected_current_firmware,
            password=password,
            ssh_host=operation.ssh_host,
            timeout_s=timeout_s,
        )
    if not isinstance(result, RxOnlyPersistentRecoveryResult):
        raise ReleaseCandidateLifecycleError(
            "backend returned a malformed persistent-recovery result"
        )
    if result.pre_reset_usb_departure_verified is not True:
        raise ReleaseCandidateLifecycleError(
            "persistent recovery lacks verified pre-reset USB departure"
        )
    recovered = result.runtime
    quiesce = result.quiesce
    route = result.host_route
    if (
        recovered.firmware_version != operation.expected_current_firmware
        or recovered.layout.kind != "tx-capable"
        or recovered.single_rx_setup != source.pre_runtime.single_rx_setup
        or recovered.boot_id == source.pre_runtime.boot_id
        or (
            source.post_runtime is not None
            and recovered.boot_id == source.post_runtime.boot_id
        )
        or recovered.qspi != source.pre_runtime.qspi
        or not route.release_verified
        or route.destination != f"{operation.ssh_host}/32"
        or not quiesce.readback_verified
    ):
        raise ReleaseCandidateLifecycleError(
            "persistent 1R1T recovery proof differs from the operation baseline"
        )
    recovery = ReleaseCandidateRecoveryReceiptV2(
        schema=RX_ONLY_RECOVERY_RECEIPT_SCHEMA,
        recovery_id=recovery_id_factory(),
        started_at=started_at,
        completed_at=_utc(now(), label="recovery completion"),
        tool_repository=tool_repository,
        tool_version=tool_version,
        tool_source_commit=tool_source_commit,
        source_receipt=model_file_identity(selected_receipt, source),
        source_outcome="pass" if source.outcome == "pass" else "unknown",
        operation_plan=source.operation_plan,
        candidate_plan=source.candidate_plan,
        target=source.target,
        runtime_target=source.runtime_target,
        pre_runtime=source.pre_runtime,
        recovered_runtime=recovered,
        recovery_quiesce=quiesce,
        expected_return_firmware=operation.expected_current_firmware,
        host_route=route,
        recovery_action=(
            "dfu-detach-then-persistent-reset"
            if result.dfu_detach_completed
            else "persistent-reset"
        ),
        dfu_detach_completed=result.dfu_detach_completed,
        persistent_reset_completed=True,
        pre_reset_usb_departure_verified=result.pre_reset_usb_departure_verified,
        cleanup=CleanupReceipt(verified=True),
    )
    validate_rx_only_recovery_bundle(
        candidate,
        operation,
        source,
        recovery,
        candidate_path=source.candidate_plan.path,
        operation_path=source.operation_plan.path,
        source_path=selected_receipt,
    )
    identity = write_private_contract(selected_output, recovery)
    return recovery, identity.sha256


def _publish_uncertain_receipt(
    error: BaseException,
    *,
    backend: RxOnlyReleaseCandidateRamBackend,
    operation: ReleaseCandidateOperationPlanV2,
    operation_path: Path,
    candidate: ReleaseCandidatePlanV2,
    candidate_path: Path,
    password: PasswordFileIdentity,
    route: HostRouteReceipt,
    pre: RuntimeObservationV2,
    quiesce: PrebootQuiesceReceiptV2,
    failure_phase: str,
    mutation_started: bool,
    download_completed: bool,
    detach_completed: bool,
    started_at: datetime,
    tool_repository: str,
    tool_version: str,
    tool_source_commit: str,
    timeout_s: float,
    now: Callable[[], datetime],
    receipt_id_factory: Callable[[], str],
) -> tuple[ReleaseCandidateRamReceiptV2, str]:
    cleanup_errors: list[str] = []
    reconciled: RuntimeObservationV2 | None = None
    if mutation_started:
        try:
            result = backend.reconcile_failure_v2(
                operation.target,
                candidate=candidate,
                runtime_target=operation.runtime_target,
                pre_runtime=pre,
                password=password,
                route=route,
                timeout_s=timeout_s,
            )
            reconciled = result.runtime
            cleanup = result.cleanup
        except BaseException as cleanup_error:
            cleanup_errors.append(f"{type(cleanup_error).__name__}: {cleanup_error}")
            cleanup = CleanupReceipt(verified=False, errors=tuple(cleanup_errors))
    else:
        cleanup = CleanupReceipt(
            verified=False, errors=("transition did not start; TX remains quiesced",)
        )
    release_verified = False
    try:
        backend.release_host_route(route)
        release_verified = True
    except BaseException as route_error:
        cleanup_errors = [*cleanup.errors, f"host route release: {route_error}"]
        cleanup = CleanupReceipt(verified=False, errors=tuple(cleanup_errors))
    receipt = _receipt(
        receipt_id=receipt_id_factory(),
        outcome="unknown" if mutation_started else "failed",
        started_at=started_at,
        completed_at=_utc(now(), label="execution failure completion"),
        tool_repository=tool_repository,
        tool_version=tool_version,
        tool_source_commit=tool_source_commit,
        operation=operation,
        operation_path=operation_path,
        candidate=candidate,
        candidate_path=candidate_path,
        pre=pre,
        post=reconciled,
        quiesce=quiesce,
        route=route.model_copy(update={"release_verified": release_verified}),
        transition=TransitionReceipt(
            topology=operation.target.topology,
            sealed_input=mutation_started,
            download_completed=download_completed,
            detach_completed=detach_completed,
        ),
        cleanup=cleanup,
        failure_phase=failure_phase,
        error=f"{type(error).__name__}: {error}",
    )
    validate_rx_only_contract_bundle(
        candidate,
        operation,
        receipt,
        candidate_path=candidate_path,
        operation_path=operation_path,
    )
    identity = write_private_contract(operation.receipt_path, receipt)
    raise ReleaseCandidateLifecycleError(
        str(error), receipt=receipt, receipt_sha256=identity.sha256
    ) from error


def _receipt(
    *,
    receipt_id: str,
    outcome: Literal["pass", "failed", "unknown"],
    started_at: datetime,
    completed_at: datetime,
    tool_repository: str,
    tool_version: str,
    tool_source_commit: str,
    operation: ReleaseCandidateOperationPlanV2,
    operation_path: Path,
    candidate: ReleaseCandidatePlanV2,
    candidate_path: Path,
    pre: RuntimeObservationV2 | None,
    post: RuntimeObservationV2 | None,
    quiesce: PrebootQuiesceReceiptV2 | None,
    route: HostRouteReceipt,
    transition: TransitionReceipt,
    cleanup: CleanupReceipt,
    failure_phase: str | None = None,
    error: str | None = None,
) -> ReleaseCandidateRamReceiptV2:
    return ReleaseCandidateRamReceiptV2(
        schema=RX_ONLY_RAM_RECEIPT_SCHEMA,
        receipt_id=receipt_id,
        outcome=outcome,
        started_at=started_at,
        completed_at=completed_at,
        tool_repository=tool_repository,
        tool_version=tool_version,
        tool_source_commit=tool_source_commit,
        operation_plan=model_file_identity(operation_path, operation),
        candidate_plan=model_file_identity(candidate_path, candidate),
        candidate_dfu=ContentIdentity(bytes=candidate.dfu.bytes, sha256=candidate.dfu.sha256),
        candidate_fit=candidate.fit,
        target=operation.target,
        runtime_target=operation.runtime_target,
        expected_firmware=candidate.expected_runtime.firmware_version,
        expected_hardware_model=candidate.expected_runtime.hardware_model,
        expected_metadata_abi=candidate.expected_runtime.metadata_abi,
        required_capabilities=candidate.expected_runtime.capabilities,
        pre_runtime=pre,
        post_runtime=post,
        preboot_quiesce=quiesce,
        host_route=route,
        transition=transition,
        cleanup=cleanup,
        failure_phase=failure_phase,
        error=error,
    )


def _read_candidate_dfu(candidate: ReleaseCandidatePlanV2) -> bytes:
    path = candidate.dfu.path
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        before = path.lstat()
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ReleaseCandidateLifecycleError(f"candidate DFU is unavailable: {error}") from error
    try:
        opened = os.fstat(descriptor)
        if _stable_identity(before) != _stable_identity(opened):
            raise ReleaseCandidateLifecycleError("candidate DFU changed while opening")
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
            or opened.st_size != candidate.dfu.bytes
        ):
            raise ReleaseCandidateLifecycleError(
                "candidate DFU must be one owned mode-0600 exact-size regular file"
            )
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1 << 20))
            if not chunk:
                raise ReleaseCandidateLifecycleError("candidate DFU was truncated during read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ReleaseCandidateLifecycleError("candidate DFU grew during read")
        if _stable_identity(os.fstat(descriptor)) != _stable_identity(opened):
            raise ReleaseCandidateLifecycleError("candidate DFU changed during read")
    finally:
        os.close(descriptor)
    payload = b"".join(chunks)
    if hashlib.sha256(payload).hexdigest() != candidate.dfu.sha256:
        raise ReleaseCandidateLifecycleError("candidate DFU SHA-256 differs from the plan")
    try:
        fit = validate_dfu(payload)
    except FirmwareImageError as error:
        raise ReleaseCandidateLifecycleError(f"candidate DFU is invalid: {error}") from error
    if len(fit) != candidate.fit.bytes or hashlib.sha256(fit).hexdigest() != candidate.fit.sha256:
        raise ReleaseCandidateLifecycleError("candidate FIT identity differs from the plan")
    return payload


def _validate_pre_runtime(
    runtime: RuntimeObservationV2,
    operation: ReleaseCandidateOperationPlanV2,
    candidate: ReleaseCandidatePlanV2,
) -> None:
    setup = runtime.single_rx_setup
    if (
        runtime.serial != operation.target.serial
        or runtime.topology != operation.target.topology
        or runtime.hardware_model != candidate.expected_runtime.hardware_model
        or runtime.firmware_version != operation.expected_current_firmware
        or runtime.layout.kind != "tx-capable"
        or setup.runtime_target != operation.runtime_target
    ):
        raise ReleaseCandidateLifecycleError(
            "preboot runtime is not the exact target-aware TX-capable 1R1T prerequisite"
        )


def _validate_post_runtime(
    pre: RuntimeObservationV2,
    post: RuntimeObservationV2,
    operation: ReleaseCandidateOperationPlanV2,
    candidate: ReleaseCandidatePlanV2,
) -> None:
    expected = candidate.expected_runtime
    if (
        post.serial != operation.target.serial
        or post.topology != operation.target.topology
        or post.hardware_model != expected.hardware_model
        or post.firmware_version != expected.firmware_version
        or post.metadata_abi != expected.metadata_abi
        or post.capabilities != expected.capabilities
        or post.layout.kind != "rx-only"
        or pre.single_rx_setup != post.single_rx_setup
        or post.single_rx_setup.runtime_target != operation.runtime_target
        or post.boot_id == pre.boot_id
        or post.qspi != pre.qspi
    ):
        raise ReleaseCandidateLifecycleError(
            "postboot runtime, 1R1T target, boot epoch, or QSPI identity differs from the candidate"
        )


def _same_physical_target(returned: UsbInventoryTarget, planned: UsbInventoryTarget) -> bool:
    return bool(
        returned.serial == planned.serial
        and returned.topology == planned.topology
        and returned.sysfs_path == planned.sysfs_path
        and returned.vendor_id == planned.vendor_id
        and returned.product_id == planned.product_id
        and returned.network_interface == planned.network_interface
        and returned.source_ipv4 == planned.source_ipv4
    )


def _release_after_preflight_failure(
    backend: RxOnlyReleaseCandidateRamBackend, route: HostRouteReceipt
) -> None:
    try:
        backend.release_host_route(route)
    except BaseException as error:
        raise ReleaseCandidateLifecycleError(
            f"preflight failed and host-route cleanup also failed: {error}"
        ) from error


def _require_absent_receipt(path: Path, *, serial: str) -> None:
    selected = _absolute_path(path, label="receipt path")
    if serial not in selected.parts:
        raise ReleaseCandidateLifecycleError("receipt path must be scoped to the exact serial")
    _require_absent_private_output(selected, label="receipt")


def _require_absent_private_output(path: Path, *, label: str) -> None:
    """Preflight a durable private destination before any hardware mutation."""

    selected = _absolute_path(path, label=f"{label} path")
    if selected.exists() or selected.is_symlink():
        raise ReleaseCandidateLifecycleError(f"{label} destination must be absent")
    try:
        parent = selected.parent.lstat()
    except OSError as error:
        raise ReleaseCandidateLifecycleError(f"{label} parent is unavailable: {error}") from error
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.getuid()
        or stat.S_IMODE(parent.st_mode) != 0o700
    ):
        raise ReleaseCandidateLifecycleError(
            f"{label} parent must be an owned mode-0700 directory"
        )


def _validate_sealed_path(path: Path) -> None:
    if re.fullmatch(r"/proc/self/fd/[0-9]+", str(path)) is None:
        raise ReleaseCandidateLifecycleError(
            "backend DFU input must be one sealed /proc/self/fd descriptor"
        )


def _absolute_path(path: Path, *, label: str) -> Path:
    if not path.is_absolute() or ".." in path.parts:
        raise ReleaseCandidateLifecycleError(f"{label} must be an absolute normalized path")
    return path


def _stable_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
        raise ReleaseCandidateLifecycleError(f"{label} must be expressed in UTC")
    return value
