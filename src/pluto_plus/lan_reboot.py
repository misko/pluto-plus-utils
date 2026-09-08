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
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pluto_plus.hardware.discovery import _inspect_iio_context
from pluto_plus.hardware.iio_metadata import require_metadata_abi_capability
from pluto_plus.inventory import LocalUsbPluto, scan_local_usb_plutos
from pluto_plus.local_reboot import (
    LocalRebootAttestation,
    LocalRebootCapabilities,
    LocalRebootTransport,
)

_SERIAL_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


class LanRebootError(RuntimeError):
    """A detached-USB LAN reboot precondition or invariant failed."""


class LanRebootExecutionError(LanRebootError):
    """A LAN reboot failed or became uncertain after a durable checkpoint."""

    def __init__(
        self,
        message: str,
        receipt: LanRebootReceipt | LanNetworkRebootReceipt,
    ) -> None:
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


@dataclass(frozen=True, slots=True)
class LanNetworkRebootPlan:
    """Exact network-return reboot plan for a physically remote LAN radio."""

    schema_version: int
    plan_id: str
    created_at: str
    serial: str
    ssh_host: str
    known_hosts_sha256: str
    expected_metadata_abi: int
    before: LocalRebootAttestation
    confirmation_phrase: str


@dataclass(frozen=True, slots=True)
class LanNetworkRebootReceipt:
    """Durable network-return reboot and rotated-key evidence."""

    schema_version: int
    receipt_id: str
    plan: LanNetworkRebootPlan
    started_at: str
    finished_at: str | None
    outcome: Literal["started", "success", "failed_before_mutation", "unknown"]
    completed_phases: tuple[str, ...]
    before: LocalRebootAttestation | None
    after: LocalRebootAttestation | None
    host_key_rotation: dict[str, str] | None
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


def prepare_lan_network_reboot(
    serial: str,
    *,
    ssh_host: str,
    known_hosts_file: Path,
    transport: LocalRebootTransport,
    scanner: Callable[[], Sequence[LocalUsbPluto]] = scan_local_usb_plutos,
    iio_inspector: Callable[[str], Mapping[str, object]] = _inspect_iio_context,
) -> LanNetworkRebootPlan:
    """Attest one detached LAN radio and its exact IIOD return contract."""

    _validate_identity(serial, ssh_host)
    _require_usb_absent(serial, scanner())
    known_hosts_sha256 = _private_file_sha256(known_hosts_file, "SSH known-hosts")
    before = transport.attest(serial)
    if before.serial != serial or not before.boot_id:
        raise LanRebootError("remote attestation lacks the exact serial or boot identity")
    facts = _inspect_network_iio(ssh_host, iio_inspector)
    expected_metadata_abi = _metadata_abi(facts)
    _require_network_iio_matches(
        facts,
        serial=serial,
        before=before,
        expected_metadata_abi=expected_metadata_abi,
    )
    return LanNetworkRebootPlan(
        schema_version=2,
        plan_id=uuid.uuid4().hex,
        created_at=_now(),
        serial=serial,
        ssh_host=ssh_host,
        known_hosts_sha256=known_hosts_sha256,
        expected_metadata_abi=expected_metadata_abi,
        before=before,
        confirmation_phrase=f"REBOOT LAN {serial}",
    )


def execute_lan_network_reboot(
    plan: LanNetworkRebootPlan,
    *,
    confirmation: str,
    transport: LocalRebootTransport,
    returned_transport_factory: Callable[[], LocalRebootTransport],
    host_key_rotator: Callable[[], dict[str, str]],
    known_hosts_file: Path,
    receipt_directory: Path,
    scanner: Callable[[], Sequence[LocalUsbPluto]] = scan_local_usb_plutos,
    iio_inspector: Callable[[str], Mapping[str, object]] = _inspect_iio_context,
    timeout_s: float = 60,
    poll_interval_s: float = 0.25,
) -> LanNetworkRebootReceipt:
    """Reboot one remote LAN radio and prove its network-only return."""

    if confirmation != plan.confirmation_phrase:
        raise LanRebootError(f"confirmation must be exactly {plan.confirmation_phrase!r}")
    if timeout_s <= 0 or poll_interval_s <= 0:
        raise ValueError("reboot timeouts must be positive")
    _validate_identity(plan.serial, plan.ssh_host)

    receipt_id = uuid.uuid4().hex
    destination = receipt_directory / f"lan-network-{receipt_id}.json"
    started_at = _now()
    completed: list[str] = []
    before: LocalRebootAttestation | None = None
    after: LocalRebootAttestation | None = None
    rotation: dict[str, str] | None = None
    dispatch_error: str | None = None
    mutation_attempted = False

    def checkpoint(
        outcome: Literal[
            "started", "success", "failed_before_mutation", "unknown"
        ] = "started",
        *,
        finished_at: str | None = None,
        error: str | None = None,
    ) -> LanNetworkRebootReceipt:
        receipt = LanNetworkRebootReceipt(
            schema_version=2,
            receipt_id=receipt_id,
            plan=plan,
            started_at=started_at,
            finished_at=finished_at,
            outcome=outcome,
            completed_phases=tuple(completed),
            before=before,
            after=after,
            host_key_rotation=rotation,
            dispatch_error=dispatch_error,
            error=error,
            receipt_path=str(destination),
        )
        _write_receipt(destination, receipt)
        return receipt

    checkpoint()
    try:
        if _private_file_sha256(known_hosts_file, "SSH known-hosts") != (
            plan.known_hosts_sha256
        ):
            raise LanRebootError("SSH trust changed after LAN reboot planning")
        _require_usb_absent(plan.serial, scanner())
        completed.append("usb_absence_reattested")
        checkpoint()
        before = transport.attest(plan.serial)
        if before != plan.before:
            raise LanRebootError("remote identity or runtime changed after LAN reboot planning")
        completed.append("remote_identity_reattested")
        checkpoint()
        facts = _inspect_network_iio(plan.ssh_host, iio_inspector)
        _require_network_iio_matches(
            facts,
            serial=plan.serial,
            before=before,
            expected_metadata_abi=plan.expected_metadata_abi,
        )
        completed.append("lan_iiod_identity_reattested")
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
        _wait_for_network_iio_state(
            plan,
            available=False,
            iio_inspector=iio_inspector,
            timeout_s=timeout_s,
            poll_interval_s=poll_interval_s,
        )
        completed.append("lan_iio_disappeared")
        checkpoint()
        _wait_for_network_iio_state(
            plan,
            available=True,
            iio_inspector=iio_inspector,
            timeout_s=timeout_s,
            poll_interval_s=poll_interval_s,
        )
        completed.append("lan_iio_reappeared")
        checkpoint()
        rotation = host_key_rotator()
        _require_host_key_rotation(
            rotation,
            known_hosts_file=known_hosts_file,
            expected_previous_sha256=plan.known_hosts_sha256,
        )
        completed.append("lan_ssh_host_key_rotated")
        checkpoint()
        returned_transport = returned_transport_factory()
        after = returned_transport.attest(plan.serial)
        if (
            after.serial != before.serial
            or after.firmware != before.firmware
            or after.capabilities != before.capabilities
            or not after.boot_id
            or after.boot_id == before.boot_id
        ):
            raise LanRebootError("network-return identity differs across LAN reboot")
        completed.append("post_reboot_identity_attested")
        checkpoint()
        returned_transport.ensure_tx_safe(plan.serial)
        completed.append("tx_safe_after_reboot")
        return checkpoint("success", finished_at=_now())
    except BaseException as error:
        error_text = f"{type(error).__name__}: {error}"
        outcome: Literal["failed_before_mutation", "unknown"] = (
            "unknown" if mutation_attempted else "failed_before_mutation"
        )
        receipt = checkpoint(outcome, finished_at=_now(), error=error_text)
        raise LanRebootExecutionError(error_text, receipt) from error


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


def _inspect_network_iio(
    host: str,
    inspector: Callable[[str], Mapping[str, object]],
) -> Mapping[str, object]:
    try:
        facts = inspector(host)
    except (OSError, RuntimeError, ValueError) as error:
        raise LanRebootError(f"cannot inspect LAN IIOD at {host}: {error}") from error
    return facts


def _metadata_abi(facts: Mapping[str, object]) -> int:
    try:
        value = int(str(facts.get("iio,buffer-metadata") or ""))
    except ValueError as error:
        raise LanRebootError("LAN IIOD metadata ABI is missing or malformed") from error
    if value <= 0:
        raise LanRebootError("LAN IIOD metadata ABI must be positive")
    return value


def _require_network_iio_matches(
    facts: Mapping[str, object],
    *,
    serial: str,
    before: LocalRebootAttestation,
    expected_metadata_abi: int,
) -> None:
    if str(facts.get("hw_serial") or "").strip() != serial:
        raise LanRebootError("LAN IIOD serial differs from the reboot plan")
    if str(facts.get("fw_version") or "").strip() != before.firmware:
        raise LanRebootError("LAN IIOD firmware differs from the SSH attestation")
    try:
        require_metadata_abi_capability(facts, expected_metadata_abi)
    except ValueError as error:
        raise LanRebootError("LAN IIOD metadata ABI differs from the reboot plan") from error
    raw_names = facts.get("device_names", ())
    names = (
        {str(value) for value in raw_names}
        if isinstance(raw_names, (tuple, list, set, frozenset))
        else set()
    )
    raw_scan = facts.get("cf-ad9361-lpc,scan_channels", ())
    scan = (
        tuple(sorted(str(value) for value in raw_scan))
        if isinstance(raw_scan, (tuple, list, set, frozenset))
        else ()
    )
    observed = LocalRebootCapabilities(
        board_model=str(facts.get("hw_model") or "").strip(),
        phy_model=str(facts.get("ad9361-phy,model") or "").strip(),
        rx_scan_channels=scan,
        tandem_agc="tandem-agc" in names,
    )
    if observed != before.capabilities:
        raise LanRebootError("LAN IIOD capabilities differ from the SSH attestation")


def _wait_for_network_iio_state(
    plan: LanNetworkRebootPlan,
    *,
    available: bool,
    iio_inspector: Callable[[str], Mapping[str, object]],
    timeout_s: float,
    poll_interval_s: float,
) -> None:
    deadline = time.monotonic() + timeout_s
    last_error: BaseException | None = None
    while time.monotonic() < deadline:
        try:
            facts = iio_inspector(plan.ssh_host)
            observed_serial = str(facts.get("hw_serial") or "").strip()
            if observed_serial and observed_serial != plan.serial:
                raise LanRebootError("a different serial appeared at the LAN endpoint")
        except (OSError, RuntimeError, ValueError) as error:
            last_error = error
            present = False
        else:
            try:
                _require_network_iio_matches(
                    facts,
                    serial=plan.serial,
                    before=plan.before,
                    expected_metadata_abi=plan.expected_metadata_abi,
                )
            except LanRebootError as error:
                # During boot, IIOD may answer before all context attributes and
                # devices have appeared. Treat that as unavailable, but never
                # tolerate a non-empty serial belonging to another radio.
                last_error = error
                present = False
            else:
                present = True
        if present is available:
            return
        time.sleep(poll_interval_s)
    state = "return" if available else "disappear"
    detail = f": {last_error}" if last_error is not None else ""
    raise LanRebootError(f"LAN IIOD did not {state} within {timeout_s:g}s{detail}")


def _require_host_key_rotation(
    evidence: Mapping[str, str],
    *,
    known_hosts_file: Path,
    expected_previous_sha256: str,
) -> None:
    previous = evidence.get("previous_known_hosts_sha256")
    replacement = evidence.get("replacement_known_hosts_sha256")
    if previous != expected_previous_sha256:
        raise LanRebootError("SSH key rotation does not bind the planned trust anchor")
    if not replacement or replacement == previous:
        raise LanRebootError("SSH key rotation did not provide a distinct replacement key")
    if _private_file_sha256(known_hosts_file, "replacement SSH known-hosts") != replacement:
        raise LanRebootError("SSH key rotation evidence differs from the installed trust anchor")


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


def _write_receipt(
    path: Path,
    receipt: LanRebootReceipt | LanNetworkRebootReceipt,
) -> None:
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
