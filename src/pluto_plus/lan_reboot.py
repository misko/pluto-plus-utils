"""Guarded LAN reboot for an exact radio whose USB gadget is detached."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import tempfile
import time
import uuid
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pluto_plus.inventory import LocalUsbPluto, scan_local_usb_plutos
from pluto_plus.local_reboot import LocalRebootAttestation, LocalRebootTransport

_SERIAL_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


class LanRebootError(RuntimeError):
    """A detached-USB LAN reboot precondition or invariant failed."""


class LanRebootExecutionError(LanRebootError):
    """A LAN reboot failed or became uncertain after a durable checkpoint."""

    def __init__(self, message: str, receipt: LanRebootReceipt) -> None:
        super().__init__(message)
        self.receipt = receipt


@dataclass(frozen=True, slots=True)
class LanRebootPlan:
    schema_version: int
    plan_id: str
    created_at: str
    serial: str
    ssh_host: str
    known_hosts_sha256: str
    before: LocalRebootAttestation
    confirmation_phrase: str


@dataclass(frozen=True, slots=True)
class LanRebootReceipt:
    schema_version: int
    receipt_id: str
    plan: LanRebootPlan
    started_at: str
    finished_at: str | None
    outcome: Literal["started", "success", "failed_before_mutation", "unknown"]
    completed_phases: tuple[str, ...]
    returned_usb_path: str | None
    returned_usb_interfaces: tuple[str, ...]
    dispatch_error: str | None
    error: str | None
    receipt_path: str


def prepare_lan_reboot(
    serial: str,
    *,
    ssh_host: str,
    known_hosts_file: Path,
    transport: LocalRebootTransport,
    scanner: Callable[[], Sequence[LocalUsbPluto]] = scan_local_usb_plutos,
) -> LanRebootPlan:
    """Attest one LAN radio and require its local USB gadget to be absent."""

    _validate_identity(serial, ssh_host)
    _require_usb_absent(serial, scanner())
    known_hosts_sha256 = _private_file_sha256(known_hosts_file, "SSH known-hosts")
    before = transport.attest(serial)
    if before.serial != serial:
        raise LanRebootError("remote attestation returned a different radio serial")
    return LanRebootPlan(
        schema_version=1,
        plan_id=uuid.uuid4().hex,
        created_at=_now(),
        serial=serial,
        ssh_host=ssh_host,
        known_hosts_sha256=known_hosts_sha256,
        before=before,
        confirmation_phrase=f"REBOOT LAN {serial}",
    )


def execute_lan_reboot(
    plan: LanRebootPlan,
    *,
    confirmation: str,
    transport: LocalRebootTransport,
    known_hosts_file: Path,
    receipt_directory: Path,
    scanner: Callable[[], Sequence[LocalUsbPluto]] = scan_local_usb_plutos,
    timeout_s: float = 60,
    poll_interval_s: float = 0.25,
) -> LanRebootReceipt:
    """Reboot an exact LAN radio and verify its exact serial returns over USB."""

    if confirmation != plan.confirmation_phrase:
        raise LanRebootError(f"confirmation must be exactly {plan.confirmation_phrase!r}")
    if timeout_s <= 0 or poll_interval_s <= 0:
        raise ValueError("reboot timeouts must be positive")
    _validate_identity(plan.serial, plan.ssh_host)

    receipt_id = uuid.uuid4().hex
    destination = receipt_directory / f"lan-{receipt_id}.json"
    started_at = _now()
    completed: list[str] = []
    returned: LocalUsbPluto | None = None
    dispatch_error: str | None = None
    mutation_attempted = False

    def checkpoint(
        outcome: Literal[
            "started", "success", "failed_before_mutation", "unknown"
        ] = "started",
        *,
        finished_at: str | None = None,
        error: str | None = None,
    ) -> LanRebootReceipt:
        receipt = LanRebootReceipt(
            schema_version=1,
            receipt_id=receipt_id,
            plan=plan,
            started_at=started_at,
            finished_at=finished_at,
            outcome=outcome,
            completed_phases=tuple(completed),
            returned_usb_path=None if returned is None else returned.usb_path,
            returned_usb_interfaces=(
                ()
                if returned is None
                else tuple(item.name for item in returned.host_network_interfaces)
            ),
            dispatch_error=dispatch_error,
            error=error,
            receipt_path=str(destination),
        )
        _write_receipt(destination, receipt)
        return receipt

    checkpoint()
    try:
        if _private_file_sha256(known_hosts_file, "SSH known-hosts") != plan.known_hosts_sha256:
            raise LanRebootError("SSH trust changed after LAN reboot planning")
        _require_usb_absent(plan.serial, scanner())
        completed.append("usb_absence_reattested")
        checkpoint()
        fresh = transport.attest(plan.serial)
        if fresh != plan.before:
            raise LanRebootError("remote identity or runtime changed after LAN reboot planning")
        completed.append("remote_identity_reattested")
        checkpoint()
        transport.ensure_tx_safe(plan.serial)
        completed.append("tx_safe_before_reboot")
        checkpoint()
        mutation_attempted = True
        completed.append("reboot_dispatch_attempted")
        checkpoint()
        try:
            transport.reboot(plan.serial)
            completed.append("reboot_dispatched")
            checkpoint()
        except BaseException as error:
            dispatch_error = f"{type(error).__name__}: {error}"
            checkpoint()
        returned = _wait_for_exact_usb_return(
            plan.serial,
            scanner=scanner,
            timeout_s=timeout_s,
            poll_interval_s=poll_interval_s,
        )
        completed.append("exact_usb_serial_returned")
        return checkpoint("success", finished_at=_now())
    except BaseException as error:
        error_text = f"{type(error).__name__}: {error}"
        outcome: Literal["failed_before_mutation", "unknown"] = (
            "unknown" if mutation_attempted else "failed_before_mutation"
        )
        receipt = checkpoint(outcome, finished_at=_now(), error=error_text)
        raise LanRebootExecutionError(error_text, receipt) from error


def _wait_for_exact_usb_return(
    serial: str,
    *,
    scanner: Callable[[], Sequence[LocalUsbPluto]],
    timeout_s: float,
    poll_interval_s: float,
) -> LocalUsbPluto:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        matches = [item for item in scanner() if item.serial == serial]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise LanRebootError("multiple local USB radios returned with the selected serial")
        time.sleep(poll_interval_s)
    raise LanRebootError("exact radio serial did not return over local USB")


def _require_usb_absent(serial: str, devices: Sequence[LocalUsbPluto]) -> None:
    if any(item.serial == serial for item in devices):
        raise LanRebootError(
            "selected serial is already attached over USB; use radio reboot-local instead"
        )


def _validate_identity(serial: str, ssh_host: str) -> None:
    if not _SERIAL_RE.fullmatch(serial):
        raise LanRebootError("invalid radio serial")
    try:
        address = ipaddress.ip_address(ssh_host)
    except ValueError as error:
        raise LanRebootError("SSH host must be a canonical private IPv4 address") from error
    if address.version != 4 or not address.is_private or str(address) != ssh_host:
        raise LanRebootError("SSH host must be a canonical private IPv4 address")
    if ssh_host == "192.168.2.1":
        raise LanRebootError("detached-USB reboot requires a unique LAN address")


def _private_file_sha256(path: Path, label: str) -> str:
    try:
        stat_result = path.lstat()
        data = path.read_bytes()
    except OSError as error:
        raise LanRebootError(f"{label} file is not readable") from error
    if path.is_symlink() or not path.is_file() or stat_result.st_mode & 0o077:
        raise LanRebootError(f"{label} must be a private regular non-symlink file")
    if not data or len(data) > 1024 * 1024:
        raise LanRebootError(f"{label} file is empty or too large")
    return hashlib.sha256(data).hexdigest()


def _write_receipt(path: Path, receipt: LanRebootReceipt) -> None:
    directory = path.parent
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)
    payload = (json.dumps(asdict(receipt), sort_keys=True, separators=(",", ":")) + "\n").encode()
    descriptor, temporary_name = tempfile.mkstemp(prefix=".lan-reboot-", dir=directory)
    temporary = Path(temporary_name)
    stream_opened = False
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream_opened = True
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        if not stream_opened:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise


def _now() -> str:
    return datetime.now(UTC).isoformat()
