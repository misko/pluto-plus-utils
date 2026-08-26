"""Backend-neutral release-candidate RAM transition coordinator.

The coordinator owns the semantic state machine and durable receipt.  A
platform backend owns Linux routing, USB/IIO discovery, SSH, and dfu-util.  This
split lets the complete mutation sequence be tested without attached hardware
and gives the standalone CLI and a future daemon one shared implementation.
"""

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
    ReleaseCandidateOperationPlan,
    ReleaseCandidatePlan,
    ReleaseCandidateRamReceipt,
    ReleaseUsbInventory,
    RuntimeObservation,
    TransitionReceipt,
    UsbInventoryTarget,
    load_private_contract,
    model_file_identity,
    validate_contract_bundle,
    write_private_contract,
)

DFU_SELECTOR = "0456:b673,0456:b674"
DFU_ALTERNATE = "firmware.dfu"
REMOTE_RAM_COMMAND = "/usr/sbin/device_reboot ram"
MAX_PASSWORD_BYTES = 4096


class ReleaseCandidateLifecycleError(RuntimeError):
    """The candidate lifecycle was rejected or could not finish safely."""

    def __init__(
        self,
        message: str,
        *,
        receipt: ReleaseCandidateRamReceipt | None = None,
        receipt_sha256: str | None = None,
    ) -> None:
        super().__init__(message)
        self.receipt = receipt
        self.receipt_sha256 = receipt_sha256


@dataclass(frozen=True, slots=True)
class PasswordFileIdentity:
    """Stable metadata for a private password file; never contains the secret."""

    path: Path
    device: int
    inode: int
    bytes: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True, slots=True)
class FailureReconciliation:
    """Best-effort state found after an uncertain transition."""

    runtime: RuntimeObservation | None
    cleanup: CleanupReceipt


class ReleaseCandidateRamBackend(Protocol):
    """Physical operations required by the backend-neutral coordinator."""

    def transaction_locks(
        self, target: UsbInventoryTarget, ssh_host: str
    ) -> AbstractContextManager[None]: ...

    def sealed_dfu(self, payload: bytes) -> AbstractContextManager[Path]: ...

    def revalidate_target(self, target: UsbInventoryTarget) -> UsbInventoryTarget: ...

    def acquire_host_route(self, target: UsbInventoryTarget, ssh_host: str) -> HostRouteReceipt: ...

    def ensure_host_route(self, route: HostRouteReceipt, target: UsbInventoryTarget) -> None: ...

    def release_host_route(self, route: HostRouteReceipt) -> None: ...

    def attest_runtime(
        self,
        target: UsbInventoryTarget,
        *,
        expected_firmware: str,
        password: PasswordFileIdentity,
        route: HostRouteReceipt,
    ) -> RuntimeObservation: ...

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

    def reconcile_failure(
        self,
        target: UsbInventoryTarget,
        *,
        candidate: ReleaseCandidatePlan,
        pre_runtime: RuntimeObservation,
        password: PasswordFileIdentity,
        route: HostRouteReceipt,
        timeout_s: float,
    ) -> FailureReconciliation: ...


def ssh_ram_argv(operation: ReleaseCandidateOperationPlan, password_path: Path) -> tuple[str, ...]:
    """Return the only owner-operated SSH command accepted by this lifecycle."""

    return ssh_fixed_argv(
        operation.target,
        ssh_host=operation.ssh_host,
        password_path=password_path,
        remote_command=REMOTE_RAM_COMMAND,
    )


def ssh_fixed_argv(
    target: UsbInventoryTarget,
    *,
    ssh_host: str,
    password_path: Path,
    remote_command: str,
) -> tuple[str, ...]:
    """Build one password-only USB-bound SSH invocation for a fixed command."""

    password = _absolute_path(password_path, label="SSH password file")
    if not remote_command or "\x00" in remote_command:
        raise ReleaseCandidateLifecycleError("fixed SSH command is malformed")
    return (
        "sshpass",
        "-f",
        str(password),
        "ssh",
        "-F",
        "/dev/null",
        "-B",
        target.network_interface,
        "-o",
        "BatchMode=no",
        "-o",
        "NumberOfPasswordPrompts=1",
        "-o",
        "PreferredAuthentications=password",
        "-o",
        "PasswordAuthentication=yes",
        "-o",
        "PubkeyAuthentication=no",
        "-o",
        "KbdInteractiveAuthentication=no",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        "CheckHostIP=no",
        "-o",
        "UpdateHostKeys=no",
        f"root@{ssh_host}",
        remote_command,
    )


def dfu_download_argv(
    operation: ReleaseCandidateOperationPlan, sealed_path: Path
) -> tuple[str, ...]:
    """Return the sole DFU download vector: paired IDs, topology, RAM alternate."""

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


def dfu_detach_argv(operation: ReleaseCandidateOperationPlan) -> tuple[str, ...]:
    """Return the sole detach vector after the volatile download."""

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


def validate_password_file(
    path: Path, *, expected: PasswordFileIdentity | None = None
) -> PasswordFileIdentity:
    """Validate a one-line owned 0600 password file without retaining its bytes."""

    selected = _absolute_path(path, label="SSH password file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        before = selected.lstat()
        descriptor = os.open(selected, flags)
    except OSError as error:
        raise ReleaseCandidateLifecycleError(
            f"SSH password file cannot be opened safely: {error}"
        ) from error
    try:
        opened = os.fstat(descriptor)
        if _stable_identity(before) != _stable_identity(opened):
            raise ReleaseCandidateLifecycleError("SSH password file changed while opening")
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
            or opened.st_size <= 1
            or opened.st_size > MAX_PASSWORD_BYTES
        ):
            raise ReleaseCandidateLifecycleError(
                "SSH password must be one owned mode-0600 regular file with one link"
            )
        payload = os.read(descriptor, opened.st_size + 1)
        if len(payload) != opened.st_size or os.read(descriptor, 1):
            raise ReleaseCandidateLifecycleError("SSH password file changed during read")
        if _stable_identity(os.fstat(descriptor)) != _stable_identity(opened):
            raise ReleaseCandidateLifecycleError("SSH password file changed during read")
    finally:
        os.close(descriptor)
    if (
        not payload.endswith(b"\n")
        or payload.count(b"\n") != 1
        or b"\x00" in payload
        or b"\r" in payload
        or not payload[:-1]
    ):
        raise ReleaseCandidateLifecycleError(
            "SSH password file must contain exactly one nonempty newline-terminated line"
        )
    identity = PasswordFileIdentity(
        path=selected,
        device=opened.st_dev,
        inode=opened.st_ino,
        bytes=opened.st_size,
        modified_ns=opened.st_mtime_ns,
        changed_ns=opened.st_ctime_ns,
    )
    if expected is not None and identity != expected:
        raise ReleaseCandidateLifecycleError("SSH password file changed after preflight")
    return identity


def execute_candidate_ram(
    operation_path: Path,
    *,
    password_path: Path,
    confirmation: str,
    backend: ReleaseCandidateRamBackend,
    tool_repository: str,
    tool_version: str,
    tool_source_commit: str,
    timeout_s: float = 45.0,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
    receipt_id_factory: Callable[[], str] = lambda: uuid.uuid4().hex,
) -> tuple[ReleaseCandidateRamReceipt, str]:
    """Execute one saved operation plan and publish its canonical receipt."""

    if timeout_s <= 0:
        raise ValueError("candidate RAM timeout must be positive")
    selected_operation = _absolute_path(operation_path, label="operation plan")
    operation = load_private_contract(selected_operation, ReleaseCandidateOperationPlan)
    if confirmation != operation.confirmation_phrase:
        raise ReleaseCandidateLifecycleError(
            f"confirmation must be exactly {operation.confirmation_phrase!r}"
        )
    candidate_path = operation.candidate_plan.path
    candidate = load_private_contract(candidate_path, ReleaseCandidatePlan)
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
    receipt_path = operation.receipt_path
    _require_absent_receipt(receipt_path, serial=operation.target.serial)
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
            pre = backend.attest_runtime(
                operation.target,
                expected_firmware=operation.expected_current_firmware,
                password=password,
                route=route,
            )
            _validate_pre_runtime(pre, operation, candidate)
        except BaseException:
            _release_after_preflight_failure(backend, route)
            raise

        mutation_started = False
        download_completed = False
        detach_completed = False
        post: RuntimeObservation | None = None
        failure_phase = "request-ram-mode"
        try:
            with backend.sealed_dfu(payload) as sealed_path:
                _validate_sealed_path(sealed_path)
                password = validate_password_file(password.path, expected=password)
                mutation_started = True
                backend.request_ram_mode(
                    ssh_ram_argv(operation, password.path),
                    password=password,
                    route=route,
                )
                failure_phase = "wait-for-dfu"
                backend.wait_for_dfu(operation.target, timeout_s=timeout_s)
                failure_phase = "download-dfu"
                backend.download_dfu(
                    dfu_download_argv(operation, sealed_path), sealed_path=sealed_path
                )
                download_completed = True
                failure_phase = "detach-dfu"
                backend.detach_dfu(dfu_detach_argv(operation))
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
                post = backend.attest_runtime(
                    returned,
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
            route=route.model_copy(update={"release_verified": True}),
            transition=TransitionReceipt(
                topology=operation.target.topology,
                sealed_input=True,
                download_completed=True,
                detach_completed=True,
            ),
            cleanup=CleanupReceipt(verified=True),
        )
        validate_contract_bundle(
            candidate,
            operation,
            receipt,
            candidate_path=candidate_path,
            operation_path=selected_operation,
        )
        identity = write_private_contract(receipt_path, receipt)
        return receipt, identity.sha256


def _publish_uncertain_receipt(
    error: BaseException,
    *,
    backend: ReleaseCandidateRamBackend,
    operation: ReleaseCandidateOperationPlan,
    operation_path: Path,
    candidate: ReleaseCandidatePlan,
    candidate_path: Path,
    password: PasswordFileIdentity,
    route: HostRouteReceipt,
    pre: RuntimeObservation,
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
) -> tuple[ReleaseCandidateRamReceipt, str]:
    cleanup_errors: list[str] = []
    reconciled: RuntimeObservation | None = None
    if mutation_started:
        try:
            result = backend.reconcile_failure(
                operation.target,
                candidate=candidate,
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
            verified=False, errors=("transition did not start; no runtime cleanup attempted",)
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
    validate_contract_bundle(
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
    operation: ReleaseCandidateOperationPlan,
    operation_path: Path,
    candidate: ReleaseCandidatePlan,
    candidate_path: Path,
    pre: RuntimeObservation | None,
    post: RuntimeObservation | None,
    route: HostRouteReceipt,
    transition: TransitionReceipt,
    cleanup: CleanupReceipt,
    failure_phase: str | None = None,
    error: str | None = None,
) -> ReleaseCandidateRamReceipt:
    return ReleaseCandidateRamReceipt(
        schema="pluto-plus-utils.release-candidate-ram-receipt.v1",
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
        expected_firmware=candidate.expected_runtime.firmware_version,
        expected_hardware_model=candidate.expected_runtime.hardware_model,
        expected_metadata_abi=candidate.expected_runtime.metadata_abi,
        required_capabilities=candidate.expected_runtime.capabilities,
        pre_runtime=pre,
        post_runtime=post,
        host_route=route,
        transition=transition,
        cleanup=cleanup,
        failure_phase=failure_phase,
        error=error,
    )


def _read_candidate_dfu(candidate: ReleaseCandidatePlan) -> bytes:
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
    runtime: RuntimeObservation,
    operation: ReleaseCandidateOperationPlan,
    candidate: ReleaseCandidatePlan,
) -> None:
    if (
        runtime.serial != operation.target.serial
        or runtime.topology != operation.target.topology
        or runtime.hardware_model != candidate.expected_runtime.hardware_model
        or runtime.firmware_version != operation.expected_current_firmware
    ):
        raise ReleaseCandidateLifecycleError("preboot runtime identity differs from the plan")


def _same_physical_target(returned: UsbInventoryTarget, planned: UsbInventoryTarget) -> bool:
    """Allow a new USB address only after the exact serial/topology returns."""

    return bool(
        returned.serial == planned.serial
        and returned.topology == planned.topology
        and returned.sysfs_path == planned.sysfs_path
        and returned.vendor_id == planned.vendor_id
        and returned.product_id == planned.product_id
        and returned.network_interface == planned.network_interface
        and returned.source_ipv4 == planned.source_ipv4
    )


def _validate_post_runtime(
    pre: RuntimeObservation,
    post: RuntimeObservation,
    operation: ReleaseCandidateOperationPlan,
    candidate: ReleaseCandidatePlan,
) -> None:
    expected = candidate.expected_runtime
    if (
        post.serial != operation.target.serial
        or post.topology != operation.target.topology
        or post.hardware_model != expected.hardware_model
        or post.firmware_version != expected.firmware_version
        or post.metadata_abi != expected.metadata_abi
        or post.capabilities != expected.capabilities
        or post.boot_id == pre.boot_id
        or post.qspi != pre.qspi
    ):
        raise ReleaseCandidateLifecycleError(
            "postboot runtime, boot epoch, or QSPI identity differs from the candidate"
        )


def _release_after_preflight_failure(
    backend: ReleaseCandidateRamBackend, route: HostRouteReceipt
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
    if selected.exists() or selected.is_symlink():
        raise ReleaseCandidateLifecycleError("receipt destination must be absent")
    try:
        parent = selected.parent.lstat()
    except OSError as error:
        raise ReleaseCandidateLifecycleError(f"receipt parent is unavailable: {error}") from error
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.getuid()
        or stat.S_IMODE(parent.st_mode) != 0o700
    ):
        raise ReleaseCandidateLifecycleError("receipt parent must be an owned mode-0700 directory")


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
