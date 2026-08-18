"""Exceptional physical-path bootstrap for Pluto radios without a serial.

This module deliberately does not provide a generic safety bypass.  It accepts
only the hardware-qualified canonical DFU, one direct runtime USB sysfs node,
and a radio whose USB and IIOD serials are both blank.  Normal serial-attested
radios must use the plan/token firmware manager instead.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import socket
import subprocess
import tempfile
import time
import uuid
from collections.abc import Callable
from contextlib import suppress
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal, Protocol, cast

from pluto_plus.doctor import CANONICAL_POLICY, TANDEM_V6_DEVELOPMENT_POLICY
from pluto_plus.firmware import FirmwareImageError, generate_frm, validate_frm
from pluto_plus.hardware.discovery import _facts_from_context_xml
from pluto_plus.inventory import LocalUsbPluto, scan_local_usb_plutos
from pluto_plus.ip_firmware import (
    UsbSshRouteAmbiguous,
    require_unambiguous_usb_ssh_route,
)
from pluto_plus.setup_helper import BoundSshTransport, SetupTransport

_USB_ROOT = Path("/sys/bus/usb/devices")
_BLOCK_ROOT = Path("/sys/class/block")
_IIOD_PORT = 30_431
BOOTSTRAP_POLICY = CANONICAL_POLICY


@dataclass(frozen=True, slots=True)
class StandaloneFlashProfile:
    """Exact mutation policy plus required post-boot capabilities."""

    policy: Any
    metadata_abi: int
    tandem_agc: bool


STANDALONE_FLASH_PROFILES = {
    CANONICAL_POLICY.profile_id: StandaloneFlashProfile(CANONICAL_POLICY, 1, False),
    TANDEM_V6_DEVELOPMENT_POLICY.profile_id: StandaloneFlashProfile(
        TANDEM_V6_DEVELOPMENT_POLICY, 2, True
    ),
}


class BootstrapFirmwareError(RuntimeError):
    """A bootstrap precondition or execution failed."""


UdisksFailureKind = Literal[
    "daemon_unavailable",
    "daemon_timeout",
    "authorization_denied",
    "already_mounted",
    "device_disappeared",
    "operation_failed",
]


class UdisksFailure(BootstrapFirmwareError):
    """A classified, fail-closed udisks operation failure."""

    def __init__(
        self,
        classification: UdisksFailureKind,
        message: str,
        remediation: str,
    ) -> None:
        super().__init__(f"udisks {classification}: {message} Remediation: {remediation}")
        self.classification = classification
        self.remediation = remediation


class BootstrapSshTransport(SetupTransport, Protocol):
    """Fixed remote commands plus an exact binary FRM upload operation."""

    def upload_frm(self, data: bytes, *, timeout_s: float = 120) -> None: ...


class BoundSshBootstrapTransport:
    """Password SSH/SCP pinned to one known host and one USB network interface."""

    def __init__(
        self,
        *,
        interface: str | None,
        password: str,
        known_hosts_file: Path,
        host: str = "192.168.2.1",
        username: str = "root",
        scp_binary: str = "scp",
        route_preflight: Callable[[], None] | None = None,
    ) -> None:
        selected_route_preflight = route_preflight or (
            (lambda: _require_usb_ssh_route(interface, host))
            if interface is not None
            else (lambda: None)
        )
        selected_route_preflight()
        self._commands = BoundSshTransport(
            host=host,
            interface=interface,
            password=password,
            known_hosts_file=known_hosts_file,
            username=username,
            route_preflight=lambda: None,
        )
        self._interface = interface
        self._password = password
        self._known_hosts_file = known_hosts_file
        self._host = host
        self._username = username
        self._scp_binary = scp_binary
        self._route_preflight = selected_route_preflight

    def run(
        self,
        command: str,
        *,
        stdin: bytes | None = None,
        timeout_s: float = 15,
    ) -> str:
        self._route_preflight()
        return self._commands.run(command, stdin=stdin, timeout_s=timeout_s)

    def upload_frm(self, data: bytes, *, timeout_s: float = 120) -> None:
        """Upload binary bytes with SCP; the PTY carries only the password prompt."""

        self._route_preflight()
        try:
            import pexpect
        except ImportError as error:  # pragma: no cover - composition guard
            raise BootstrapFirmwareError("bound SSH flashing requires pexpect") from error
        local_path: Path | None = None
        try:
            descriptor, name = tempfile.mkstemp(prefix="pluto-plus-", suffix=".frm")
            local_path = Path(name)
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            arguments = [
                "-O",
                "-o",
                "BatchMode=no",
                "-o",
                "ConnectTimeout=5",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                f"UserKnownHostsFile={self._known_hosts_file}",
                str(local_path),
                f"{self._username}@{self._host}:/tmp/pluto-plus-utils/pluto.frm",
            ]
            if self._interface is not None:
                arguments[1:1] = ["-o", f"BindInterface={self._interface}"]
            child = pexpect.spawn(
                self._scp_binary,
                arguments,
                encoding=None,
                timeout=timeout_s,
            )
            transcript = bytearray()
            password_sent = False
            try:
                while True:
                    matched = child.expect(
                        [b"[Pp]assword:", pexpect.EOF, pexpect.TIMEOUT],
                        timeout=timeout_s,
                    )
                    transcript.extend(cast(bytes, child.before or b""))
                    if matched == 0:
                        if password_sent:
                            raise BootstrapFirmwareError("radio SCP authentication failed")
                        child.sendline(self._password.encode())
                        password_sent = True
                        continue
                    if matched == 1:
                        break
                    raise BootstrapFirmwareError("radio SCP upload timed out")
            finally:
                child.close(force=True)
            if child.exitstatus != 0 or child.signalstatus is not None:
                output = bytes(transcript).decode(errors="replace").replace("\r", "")
                raise BootstrapFirmwareError(
                    "radio SCP upload failed "
                    f"({child.exitstatus=}, {child.signalstatus=}): {output[-500:]}"
                )
        except OSError as error:
            raise BootstrapFirmwareError(f"cannot stage FRM for SCP: {error}") from error
        finally:
            if local_path is not None:
                local_path.unlink(missing_ok=True)


def enroll_bound_usb_ssh_host_key(
    *,
    serial: str,
    usb_sysfs_path: Path,
    known_hosts_file: Path,
    password: str,
    host: str = "192.168.2.1",
    timeout_s: float = 15,
) -> dict[str, str]:
    """Pin one host key only after a USB-selected serial attestation."""

    target = _direct_usb_path(usb_sysfs_path)
    local = _one_local_target(target)
    if local.serial != serial or not serial.strip():
        raise BootstrapFirmwareError("USB path does not match the requested stable serial")
    if len(local.host_network_interfaces) != 1:
        raise BootstrapFirmwareError("SSH enrollment requires one exact USB network interface")
    try:
        address = ipaddress.ip_address(host)
    except ValueError as error:
        raise BootstrapFirmwareError("SSH host must be a literal IP address") from error
    if address.version != 4 or not address.is_private:
        raise BootstrapFirmwareError("SSH host must be a private IPv4 address")
    interface = (
        local.host_network_interfaces[0].name if host == "192.168.2.1" else None
    )
    if interface is not None:
        _require_usb_ssh_route(interface, host)
    destination = known_hosts_file.expanduser().resolve()
    if destination.exists():
        raise BootstrapFirmwareError("known-hosts destination already exists; refusing overwrite")
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=destination.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    temporary.chmod(0o600)
    command = (
        "printf 'serial='; cat /sys/kernel/config/usb_gadget/composite_gadget/"
        "strings/0x409/serialnumber"
    )
    try:
        import pexpect

        arguments = [
                "-o",
                "BatchMode=no",
                "-o",
                "ConnectTimeout=5",
                "-o",
                "StrictHostKeyChecking=accept-new",
                "-o",
                f"UserKnownHostsFile={temporary}",
                f"root@{host}",
                command,
            ]
        if interface is not None:
            arguments[0:0] = ["-o", f"BindInterface={interface}"]
        child = pexpect.spawn(
            "ssh",
            arguments,
            encoding=None,
            timeout=timeout_s,
        )
        transcript = bytearray()
        password_sent = False
        try:
            while True:
                matched = child.expect([b"[Pp]assword:", pexpect.EOF, pexpect.TIMEOUT])
                transcript.extend(cast(bytes, child.before or b""))
                if matched == 0:
                    if password_sent:
                        raise BootstrapFirmwareError("USB-bound SSH authentication failed")
                    child.sendline(password.encode())
                    password_sent = True
                    continue
                if matched == 1:
                    break
                raise BootstrapFirmwareError("USB-bound SSH enrollment timed out")
        finally:
            child.close(force=True)
        output = bytes(transcript).decode(errors="replace").replace("\r", "")
        serial_lines = [
            line.removeprefix("serial=").strip()
            for line in output.splitlines()
            if line.startswith("serial=")
        ]
        if child.exitstatus != 0:
            raise BootstrapFirmwareError(
                f"USB-bound SSH serial attestation exited with status {child.exitstatus}"
            )
        if serial_lines != [serial]:
            observed = serial_lines[0] if len(serial_lines) == 1 else None
            raise BootstrapFirmwareError(
                f"USB-bound SSH endpoint attested serial {observed!r}, expected {serial!r}"
            )
        if not temporary.is_file() or temporary.stat().st_size == 0:
            raise BootstrapFirmwareError("SSH did not record a host key")
        temporary.replace(destination)
        directory = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        fingerprint = _run_output(
            ("ssh-keygen", "-lf", str(destination), "-E", "sha256"), timeout_s=10
        ).strip()
        return {
            "serial": serial,
            "usb_sysfs_path": str(target),
            "usb_interface": local.host_network_interfaces[0].name,
            "ssh_host": host,
            "known_hosts_file": str(destination),
            "fingerprint": fingerprint,
        }
    except ImportError as error:
        raise BootstrapFirmwareError("USB-bound SSH enrollment requires pexpect") from error
    finally:
        temporary.unlink(missing_ok=True)


def _require_usb_ssh_route(interface: str, host: str) -> None:
    try:
        require_unambiguous_usb_ssh_route(interface, host)
    except UsbSshRouteAmbiguous as error:
        raise BootstrapFirmwareError(str(error)) from error


@dataclass(frozen=True, slots=True)
class BootstrapPlan:
    plan_id: str
    usb_sysfs_path: str
    usb_port: str
    usb_interface: str
    block_device: str
    partition: str
    before_firmware: str
    before_model: str
    before_phy: str
    image_path: str
    image_sha256: str
    fit_sha256: str
    fit_size: int
    frm_sha256: str
    expected_firmware: str
    confirmation_phrase: str
    mutation_profile_id: str = CANONICAL_POLICY.profile_id
    expected_metadata_abi: int = 1
    expected_tandem_agc: bool = False
    operation: Literal["flash", "force_flash"] = "force_flash"
    target_serial: str | None = None


@dataclass(frozen=True, slots=True)
class BootstrapResult:
    receipt_id: str
    outcome: Literal["success", "failed", "unknown"]
    phases: tuple[str, ...]
    receipt_path: str
    returned_serial: str | None = None
    returned_firmware: str | None = None
    returned_phy: str | None = None
    error: str | None = None
    failure_phase: str | None = None
    failure_classification: str | None = None
    retryable: bool | None = None
    remediation: str | None = None


def prepare_bootstrap_plan(
    image: Path,
    usb_sysfs_path: Path,
) -> tuple[BootstrapPlan, bytes]:
    """Create a non-mutating plan for one blank-serial runtime Pluto."""

    return prepare_usb_flash_plan(image, usb_sysfs_path, force_blank_serial=True)


def prepare_usb_flash_plan(
    image: Path,
    usb_sysfs_path: Path,
    *,
    force_blank_serial: bool = False,
    mutation_profile_id: str = CANONICAL_POLICY.profile_id,
) -> tuple[BootstrapPlan, bytes]:
    """Create an exact-profile path-bound USB flash plan without mutation."""

    target = _direct_usb_path(usb_sysfs_path)
    profile = STANDALONE_FLASH_PROFILES.get(mutation_profile_id)
    if profile is None:
        raise BootstrapFirmwareError(
            f"unknown standalone mutation profile {mutation_profile_id!r}; expected one of "
            f"{sorted(STANDALONE_FLASH_PROFILES)}"
        )
    if force_blank_serial and mutation_profile_id != CANONICAL_POLICY.profile_id:
        raise BootstrapFirmwareError("blank-serial recovery accepts only the canonical policy")
    policy = (
        BOOTSTRAP_POLICY if mutation_profile_id == CANONICAL_POLICY.profile_id else profile.policy
    )
    try:
        image_data = image.read_bytes()
    except OSError as error:
        raise BootstrapFirmwareError(f"cannot read firmware image: {error}") from error
    image_sha256 = hashlib.sha256(image_data).hexdigest()
    if image_sha256 != policy.asset_sha256:
        raise BootstrapFirmwareError(
            f"profile {mutation_profile_id!r} accepts only its exact qualified DFU: "
            f"expected SHA-256 {policy.asset_sha256}, got {image_sha256}"
        )
    try:
        frm = generate_frm(image_data)
        fit = validate_frm(frm)
    except FirmwareImageError as error:
        raise BootstrapFirmwareError(f"invalid canonical DFU: {error}") from error

    local = _one_local_target(target)
    if force_blank_serial and local.serial is not None:
        raise BootstrapFirmwareError(
            "force-flash is only for a blank-serial target; use firmware flash"
        )
    if not force_blank_serial and local.serial is None:
        raise BootstrapFirmwareError(
            "target has no stable serial; use firmware force-flash with exact physical path"
        )
    if len(local.host_network_interfaces) != 1:
        raise BootstrapFirmwareError(
            "bootstrap target must expose exactly one USB network interface"
        )
    if len(local.storage_devices) != 1:
        raise BootstrapFirmwareError(
            "bootstrap target must expose exactly one mass-storage partition"
        )
    interface = local.host_network_interfaces[0].name
    facts = inspect_bound_iiod(interface)
    live_serial = str(facts.get("hw_serial") or "").strip() or None
    if force_blank_serial and live_serial is not None:
        raise BootstrapFirmwareError(
            "force-flash is only for a target whose USB and IIOD serials are both blank"
        )
    if not force_blank_serial and live_serial != local.serial:
        raise BootstrapFirmwareError("USB and IIOD serials do not match the selected target")
    model = str(facts.get("hw_model") or "").strip()
    if "plutosdr rev.c" not in model.lower():
        raise BootstrapFirmwareError(
            f"bootstrap requires a live PlutoSDR Rev.C model, got {model!r}"
        )
    before_firmware = str(facts.get("fw_version") or "").strip()
    before_phy = str(facts.get("ad9361-phy,model") or "").strip()
    if not before_firmware or before_phy not in {"ad9361", "ad9363a", "ad9364"}:
        raise BootstrapFirmwareError("target did not expose complete firmware/PHY facts")

    partition = Path(local.storage_devices[0])
    block_device = _attest_partition(target, partition)
    port = target.name
    operation: Literal["flash", "force_flash"] = "force_flash" if force_blank_serial else "flash"
    confirmation = f"BOOTSTRAP {port}" if force_blank_serial else f"FLASH {local.serial}"
    return (
        BootstrapPlan(
            plan_id=str(uuid.uuid4()),
            usb_sysfs_path=str(target),
            usb_port=port,
            usb_interface=interface,
            block_device=str(block_device),
            partition=str(partition),
            before_firmware=before_firmware,
            before_model=model,
            before_phy=before_phy,
            image_path=str(image.resolve()),
            image_sha256=image_sha256,
            fit_sha256=hashlib.sha256(fit).hexdigest(),
            fit_size=len(fit),
            frm_sha256=hashlib.sha256(frm).hexdigest(),
            expected_firmware=policy.device_firmware,
            mutation_profile_id=mutation_profile_id,
            expected_metadata_abi=profile.metadata_abi,
            expected_tandem_agc=profile.tandem_agc,
            confirmation_phrase=confirmation,
            operation=operation,
            target_serial=local.serial,
        ),
        frm,
    )


def execute_bootstrap_plan(
    plan: BootstrapPlan,
    frm: bytes,
    *,
    confirmation: str,
    receipt_directory: Path,
    return_timeout_s: float = 180,
) -> BootstrapResult:
    """Write only ``pluto.frm`` and attest the same physical port after reboot."""

    if confirmation != plan.confirmation_phrase:
        raise BootstrapFirmwareError(f"confirmation must be exactly {plan.confirmation_phrase!r}")
    if hashlib.sha256(frm).hexdigest() != plan.frm_sha256:
        raise BootstrapFirmwareError("generated FRM changed after planning")
    try:
        fit = validate_frm(frm)
    except FirmwareImageError as error:
        raise BootstrapFirmwareError(f"generated FRM is invalid: {error}") from error
    if hashlib.sha256(fit).hexdigest() != plan.fit_sha256 or len(fit) != plan.fit_size:
        raise BootstrapFirmwareError("generated FIT no longer matches the plan")

    # Re-run every identity and topology check immediately before mutation.
    fresh_plan, fresh_frm = prepare_usb_flash_plan(
        Path(plan.image_path),
        Path(plan.usb_sysfs_path),
        force_blank_serial=plan.operation == "force_flash",
        mutation_profile_id=plan.mutation_profile_id,
    )
    for field in (
        "usb_sysfs_path",
        "usb_interface",
        "block_device",
        "partition",
        "before_firmware",
        "before_model",
        "before_phy",
        "image_sha256",
        "fit_sha256",
        "fit_size",
        "frm_sha256",
        "expected_firmware",
        "mutation_profile_id",
        "expected_metadata_abi",
        "expected_tandem_agc",
        "operation",
        "target_serial",
    ):
        if getattr(fresh_plan, field) != getattr(plan, field):
            raise BootstrapFirmwareError(f"bootstrap precondition changed: {field}")
    if fresh_frm != frm:
        raise BootstrapFirmwareError("deterministic FRM changed during revalidation")

    # Prove the daemon and exact device nodes are ready before an execution
    # attempt or durable receipt is created. A failed readiness check is not a
    # consumed mutation attempt because no updater volume was mounted or written.
    _preflight_udisks(
        partition=Path(plan.partition),
        block_device=Path(plan.block_device),
    )

    receipt_id = str(uuid.uuid4())
    receipt_path = receipt_directory / f"{receipt_id}.json"
    phases: list[str] = ["preflight_revalidated"]
    receipt = {
        "schema_version": 1,
        "receipt_id": receipt_id,
        "outcome": "started",
        "plan": asdict(plan),
        "phases": phases,
        "error": None,
    }
    _write_receipt(receipt_path, receipt)
    wrote_image = False
    try:
        mountpoint = _mount_partition(Path(plan.partition))
        phases.append("mounted")
        _update_receipt(receipt_path, receipt, phases)
        if not (mountpoint / "info.html").is_file():
            raise BootstrapFirmwareError("selected updater volume has no info.html")
        destination = mountpoint / "pluto.frm"
        if destination.exists():
            raise BootstrapFirmwareError(
                "selected updater already contains pluto.frm; reconcile it before retrying"
            )
        _write_fat_atomic(destination, frm)
        wrote_image = True
        phases.append("pluto_frm_written")
        _update_receipt(receipt_path, receipt, phases)
        _run(("sync", "-f", str(destination)), timeout_s=30)
        phases.append("synced")
        _update_receipt(receipt_path, receipt, phases)
        _run_udisks("unmount", Path(plan.partition), timeout_s=30)
        phases.append("unmounted")
        _update_receipt(receipt_path, receipt, phases)
        _run_udisks("power-off", Path(plan.block_device), timeout_s=30)
        phases.append("ejected")
        _update_receipt(receipt_path, receipt, phases)
        _wait_for_path(Path(plan.usb_sysfs_path), present=False, timeout_s=30)
        phases.append("disappeared")
        _update_receipt(receipt_path, receipt, phases)
        _wait_for_path(Path(plan.usb_sysfs_path), present=True, timeout_s=return_timeout_s)
        phases.append("reappeared")
        _update_receipt(receipt_path, receipt, phases)
        returned_serial, returned_firmware, returned_phy = _attest_return_when_ready(
            plan, timeout_s=return_timeout_s
        )
        phases.append("return_attested")
        if plan.target_serial is not None:
            phases.append("tx_safe_attested")
        result = BootstrapResult(
            receipt_id=receipt_id,
            outcome="success",
            phases=tuple(phases),
            receipt_path=str(receipt_path),
            returned_serial=returned_serial,
            returned_firmware=returned_firmware,
            returned_phy=returned_phy,
        )
    except Exception as error:
        outcome: Literal["failed", "unknown"] = "unknown" if wrote_image else "failed"
        # If mounting succeeded but writing did not, make a bounded cleanup attempt.
        if "mounted" in phases and "unmounted" not in phases:
            try:
                _run_udisks("unmount", Path(plan.partition), timeout_s=30)
                phases.append("cleanup_unmounted")
            except Exception:
                phases.append("cleanup_unmount_failed")
        classification = (
            error.classification
            if isinstance(error, UdisksFailure)
            else ("post_write_uncertain" if wrote_image else "pre_write_failure")
        )
        remediation = (
            error.remediation
            if isinstance(error, UdisksFailure)
            else (
                "Do not retry automatically; reconcile the radio and this receipt first."
                if wrote_image
                else "This receipt proves no pluto.frm write began; correct the error and re-plan."
            )
        )
        result = BootstrapResult(
            receipt_id=receipt_id,
            outcome=outcome,
            phases=tuple(phases),
            receipt_path=str(receipt_path),
            error=f"{type(error).__name__}: {error}",
            failure_phase=_bootstrap_failure_phase(phases),
            failure_classification=classification,
            retryable=not wrote_image,
            remediation=remediation,
        )
    receipt.update(asdict(result))
    _write_receipt(receipt_path, receipt)
    return result


def execute_usb_flash_plan(
    plan: BootstrapPlan,
    frm: bytes,
    *,
    confirmation: str,
    receipt_directory: Path,
    return_timeout_s: float = 180,
) -> BootstrapResult:
    """Execute either a normal or force path-bound canonical USB flash plan."""

    return execute_bootstrap_plan(
        plan,
        frm,
        confirmation=confirmation,
        receipt_directory=receipt_directory,
        return_timeout_s=return_timeout_s,
    )


def execute_usb_flash_plan_ssh(
    plan: BootstrapPlan,
    frm: bytes,
    *,
    confirmation: str,
    receipt_directory: Path,
    transport: BootstrapSshTransport,
    return_timeout_s: float = 180,
) -> BootstrapResult:
    """Flash canonical FRM through fixed, interface-bound authenticated SSH operations."""

    _validate_plan_payload(plan, frm, confirmation)
    fresh_plan, fresh_frm = prepare_usb_flash_plan(
        Path(plan.image_path),
        Path(plan.usb_sysfs_path),
        force_blank_serial=plan.operation == "force_flash",
        mutation_profile_id=plan.mutation_profile_id,
    )
    _require_same_plan(plan, fresh_plan, fresh_frm, frm)
    receipt_id = str(uuid.uuid4())
    receipt_path = receipt_directory / f"{receipt_id}.json"
    phases: list[str] = ["preflight_revalidated"]
    receipt: dict[str, Any] = {
        "schema_version": 1,
        "receipt_id": receipt_id,
        "transport": "bound_ssh_frm",
        "outcome": "started",
        "plan": asdict(plan),
        "phases": phases,
        "error": None,
    }
    _write_receipt(receipt_path, receipt)
    updater_dispatched = False
    try:
        before = transport.run(_REMOTE_ATTEST_COMMAND, timeout_s=15)
        remote = _remote_attestation(before)
        expected_serial = plan.target_serial or ""
        if remote["serial"] != expected_serial:
            raise BootstrapFirmwareError("remote serial changed before SSH firmware staging")
        if "plutosdr rev.c" not in remote["model"].lower():
            raise BootstrapFirmwareError("remote board is not an attested PlutoSDR Rev.C")
        if remote["firmware"] != plan.before_firmware:
            raise BootstrapFirmwareError("remote firmware changed before SSH firmware staging")
        if remote["updater"] != "/sbin/update_frm.sh":
            raise BootstrapFirmwareError("fixed radio updater is unavailable")
        phases.append("remote_preflight_attested")
        _update_receipt(receipt_path, receipt, phases)

        transport.run(_REMOTE_STAGE_COMMAND, timeout_s=15)
        transport.upload_frm(frm, timeout_s=120)
        phases.append("pluto_frm_staged")
        _update_receipt(receipt_path, receipt, phases)
        remote_hash = _one_sha256(transport.run(_REMOTE_STAGE_HASH_COMMAND, timeout_s=30))
        if remote_hash != plan.frm_sha256:
            raise BootstrapFirmwareError("remote staged FRM hash does not match the plan")
        phases.append("staged_hash_verified")
        _update_receipt(receipt_path, receipt, phases)

        updater_dispatched = True
        update_output = transport.run(_REMOTE_UPDATE_COMMAND, timeout_s=120)
        if "Failed" in update_output or not re.search(r"(?m)^Done\s*$", update_output):
            raise BootstrapFirmwareError("radio updater did not report an unambiguous Done")
        phases.append("updater_reported_done")
        _update_receipt(receipt_path, receipt, phases)
        flashed_hash = _one_sha256(
            transport.run(
                f"head -c {plan.fit_size} /dev/mtdblock3 | sha256sum",
                timeout_s=120,
            )
        )
        if flashed_hash != plan.fit_sha256:
            raise BootstrapFirmwareError("flashed mtd3 FIT hash does not match the plan")
        phases.append("mtd3_fit_verified")
        _update_receipt(receipt_path, receipt, phases)
        transport.run(_REMOTE_CLEANUP_COMMAND, timeout_s=30)
        phases.append("remote_stage_removed")
        _update_receipt(receipt_path, receipt, phases)
        transport.run(_REMOTE_REBOOT_COMMAND, timeout_s=15)
        phases.append("reboot_dispatched")
        _update_receipt(receipt_path, receipt, phases)

        _wait_for_path(Path(plan.usb_sysfs_path), present=False, timeout_s=30)
        phases.append("disappeared")
        _update_receipt(receipt_path, receipt, phases)
        _wait_for_path(Path(plan.usb_sysfs_path), present=True, timeout_s=return_timeout_s)
        phases.append("reappeared")
        _update_receipt(receipt_path, receipt, phases)
        returned_serial, returned_firmware, returned_phy = _attest_return_when_ready(
            plan, timeout_s=return_timeout_s
        )
        phases.append("return_attested")
        if plan.target_serial is not None:
            phases.append("tx_safe_attested")
        result = BootstrapResult(
            receipt_id=receipt_id,
            outcome="success",
            phases=tuple(phases),
            receipt_path=str(receipt_path),
            returned_serial=returned_serial,
            returned_firmware=returned_firmware,
            returned_phy=returned_phy,
        )
    except Exception as error:
        outcome: Literal["failed", "unknown"] = "unknown" if updater_dispatched else "failed"
        result = BootstrapResult(
            receipt_id=receipt_id,
            outcome=outcome,
            phases=tuple(phases),
            receipt_path=str(receipt_path),
            error=f"{type(error).__name__}: {error}",
        )
    receipt.update(asdict(result))
    _write_receipt(receipt_path, receipt)
    return result


_REMOTE_ATTEST_COMMAND = (
    "printf 'serial='; cat /sys/kernel/config/usb_gadget/composite_gadget/strings/0x409/"
    "serialnumber 2>/dev/null || true; printf '\\nmodel='; tr -d '\\000' </proc/device-tree/"
    "model; printf '\\nfirmware='; sed -n 's/^device-fw //p' /opt/VERSIONS | head -n1; "
    "printf 'updater='; command -v /sbin/update_frm.sh"
)
_REMOTE_STAGE_COMMAND = (
    "umask 077; mkdir -p /tmp/pluto-plus-utils && rm -f /tmp/pluto-plus-utils/pluto.frm"
)
_REMOTE_STAGE_HASH_COMMAND = "sha256sum /tmp/pluto-plus-utils/pluto.frm"
_REMOTE_UPDATE_COMMAND = "/sbin/update_frm.sh /tmp/pluto-plus-utils/pluto.frm"
_REMOTE_CLEANUP_COMMAND = "rm -f /tmp/pluto-plus-utils/pluto.frm && sync"
_REMOTE_REBOOT_COMMAND = "/usr/sbin/device_reboot reset"


def _remote_attestation(output: str) -> dict[str, str]:
    facts: dict[str, str] = {}
    for key in ("serial", "model", "firmware", "updater"):
        match = re.search(rf"(?m)^{key}=(.*)$", output)
        if match is None:
            raise BootstrapFirmwareError(f"remote attestation omitted {key}")
        facts[key] = match.group(1).strip()
    return facts


def _one_sha256(output: str) -> str:
    matches = re.findall(r"(?m)\b[0-9a-f]{64}\b", output)
    if len(matches) != 1:
        raise BootstrapFirmwareError("remote hash command did not return exactly one SHA-256")
    return str(matches[0])


def _validate_plan_payload(plan: BootstrapPlan, frm: bytes, confirmation: str) -> None:
    if confirmation != plan.confirmation_phrase:
        raise BootstrapFirmwareError(f"confirmation must be exactly {plan.confirmation_phrase!r}")
    if hashlib.sha256(frm).hexdigest() != plan.frm_sha256:
        raise BootstrapFirmwareError("generated FRM changed after planning")
    try:
        fit = validate_frm(frm)
    except FirmwareImageError as error:
        raise BootstrapFirmwareError(f"generated FRM is invalid: {error}") from error
    if hashlib.sha256(fit).hexdigest() != plan.fit_sha256 or len(fit) != plan.fit_size:
        raise BootstrapFirmwareError("generated FIT no longer matches the plan")


def _require_same_plan(
    plan: BootstrapPlan,
    fresh_plan: BootstrapPlan,
    fresh_frm: bytes,
    frm: bytes,
) -> None:
    for field in (
        "usb_sysfs_path",
        "usb_interface",
        "block_device",
        "partition",
        "before_firmware",
        "before_model",
        "before_phy",
        "image_sha256",
        "fit_sha256",
        "fit_size",
        "frm_sha256",
        "expected_firmware",
        "mutation_profile_id",
        "expected_metadata_abi",
        "expected_tandem_agc",
        "operation",
        "target_serial",
    ):
        if getattr(fresh_plan, field) != getattr(plan, field):
            raise BootstrapFirmwareError(f"bootstrap precondition changed: {field}")
    if fresh_frm != frm:
        raise BootstrapFirmwareError("deterministic FRM changed during revalidation")


def _attest_return(plan: BootstrapPlan) -> tuple[str | None, str, str]:
    returned = _one_local_target(Path(plan.usb_sysfs_path))
    if plan.operation == "flash" and returned.serial is None:
        raise BootstrapFirmwareError("returned radio has no stable USB serial")
    if plan.target_serial is not None and returned.serial != plan.target_serial:
        raise BootstrapFirmwareError("a different USB serial returned at the selected path")
    if len(returned.host_network_interfaces) != 1:
        raise BootstrapFirmwareError("returned radio lacks one USB network interface")
    facts = inspect_bound_iiod(returned.host_network_interfaces[0].name)
    returned_serial = str(facts.get("hw_serial") or "").strip() or None
    returned_firmware = str(facts.get("fw_version") or "").strip()
    returned_phy = str(facts.get("ad9361-phy,model") or "").strip()
    if returned_serial != returned.serial:
        raise BootstrapFirmwareError("returned USB and IIOD serials do not match")
    if returned_firmware != plan.expected_firmware:
        raise BootstrapFirmwareError(
            f"returned firmware is {returned_firmware!r}, expected {plan.expected_firmware!r}"
        )
    observed_metadata = str(facts.get("iio,buffer-metadata") or "").strip()
    if observed_metadata != str(plan.expected_metadata_abi):
        raise BootstrapFirmwareError(
            f"returned metadata ABI is {observed_metadata!r}, expected {plan.expected_metadata_abi}"
        )
    raw_device_names = facts.get("device_names", ())
    device_names = (
        {str(value) for value in raw_device_names}
        if isinstance(raw_device_names, (tuple, list, set, frozenset))
        else set()
    )
    observed_tandem = "tandem-agc" in device_names
    if observed_tandem is not plan.expected_tandem_agc:
        raise BootstrapFirmwareError(
            f"returned tandem capability is {observed_tandem}, expected {plan.expected_tandem_agc}"
        )
    if plan.target_serial is not None:
        _mute_returned_radio(plan.target_serial)
    return returned_serial, returned_firmware, returned_phy


def _mute_returned_radio(serial: str) -> None:
    """Mute and read back one exact returned USB-IIO radio."""

    try:
        import adi
        import iio

        from pluto_plus.hardware.iio import _mute_transmit

        matches = [
            uri
            for uri, description in iio.scan_contexts().items()
            if uri.startswith("usb:") and f"serial={serial}" in description
        ]
        if len(matches) != 1:
            raise BootstrapFirmwareError(
                f"expected one returned USB-IIO context for TX safety, got {matches}"
            )
        device = adi.ad9361(uri=matches[0])
        try:
            if device._ctx.attrs.get("hw_serial") != serial:
                raise BootstrapFirmwareError("TX safety context has the wrong serial")
            _mute_transmit(device)
        finally:
            device.rx_destroy_buffer()
            device._ctx.close()
    except (ImportError, OSError, RuntimeError, ValueError) as error:
        if isinstance(error, BootstrapFirmwareError):
            raise
        raise BootstrapFirmwareError(f"cannot attest returned TX-safe state: {error}") from error


def _attest_return_when_ready(
    plan: BootstrapPlan,
    *,
    timeout_s: float,
) -> tuple[str | None, str, str]:
    deadline = time.monotonic() + timeout_s
    last_error: BootstrapFirmwareError | None = None
    while time.monotonic() < deadline:
        try:
            return _attest_return(plan)
        except BootstrapFirmwareError as error:
            last_error = error
            time.sleep(0.5)
    if last_error is not None:
        raise BootstrapFirmwareError(
            f"returned radio did not become attestable within {timeout_s:g}s: {last_error}"
        ) from last_error
    raise BootstrapFirmwareError("returned radio attestation timeout must be positive")


def inspect_bound_iiod(interface: str) -> dict[str, object]:
    """Read IIOD metadata through one exact USB network interface."""

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as channel:
            channel.settimeout(3)
            channel.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_BINDTODEVICE,
                interface.encode() + b"\0",
            )
            channel.connect(("192.168.2.1", _IIOD_PORT))
            stream = channel.makefile("rb")
            channel.sendall(b"PRINT\r\n")
            size = int(stream.readline(32).strip())
            if size < 1 or size > 2 * 1024 * 1024:
                raise ValueError("invalid IIOD context size")
            payload = stream.read(size)
            if len(payload) != size:
                raise OSError("truncated IIOD context")
        return dict(_facts_from_context_xml(payload))
    except (OSError, ValueError) as error:
        raise BootstrapFirmwareError(
            f"cannot attest IIOD through interface {interface}: {error}"
        ) from error


def _direct_usb_path(path: Path) -> Path:
    if not path.is_absolute() or path.parent != _USB_ROOT:
        raise BootstrapFirmwareError(
            "--usb-sysfs-path must name one direct device below /sys/bus/usb/devices"
        )
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise BootstrapFirmwareError(f"USB sysfs target is unavailable: {error}") from error
    if resolved.name != path.name or ":" in path.name:
        raise BootstrapFirmwareError("USB sysfs target must be one direct device, not an interface")
    return path


def _one_local_target(path: Path) -> LocalUsbPluto:
    matches = [device for device in scan_local_usb_plutos() if device.usb_path == str(path)]
    if len(matches) != 1:
        raise BootstrapFirmwareError(
            f"expected exactly one runtime Pluto at {path}, found {len(matches)}"
        )
    return matches[0]


def _attest_partition(target: Path, partition: Path) -> Path:
    if not partition.is_absolute() or partition.parent != Path("/dev"):
        raise BootstrapFirmwareError("updater partition must be one absolute /dev node")
    sysfs_partition = _BLOCK_ROOT / partition.name
    try:
        resolved_partition = sysfs_partition.resolve(strict=True)
        resolved_partition.relative_to(target.resolve(strict=True))
    except (OSError, ValueError) as error:
        raise BootstrapFirmwareError(
            f"partition {partition} is not physically below {target}"
        ) from error
    block_name = resolved_partition.parent.name
    if block_name == partition.name or not partition.name.startswith(block_name):
        raise BootstrapFirmwareError("could not derive the updater block device")
    block_device = Path("/dev") / block_name
    if not block_device.exists() or not partition.exists():
        raise BootstrapFirmwareError("updater block device is unavailable")
    return block_device


def _mount_partition(partition: Path) -> Path:
    _require_udisks_device(partition)
    if _mountpoint_for(partition) is not None:
        raise _udisks_already_mounted(partition)
    try:
        _run_udisks("mount", partition, timeout_s=30)
    except UdisksFailure:
        # A timed-out daemon call can have completed the mount without returning
        # a response. Never write in that ambiguous state; make one exact-device
        # cleanup attempt and preserve the original classification.
        if _mountpoint_for(partition) is not None:
            with suppress(UdisksFailure):
                _run_udisks("unmount", partition, timeout_s=30)
        raise
    mountpoint = _mountpoint_for(partition)
    if mountpoint is None or mountpoint.is_symlink() or not mountpoint.is_dir():
        with suppress(UdisksFailure):
            _run_udisks("unmount", partition, timeout_s=30)
        raise BootstrapFirmwareError("udisks did not create a verifiable mountpoint")
    missing_options = {"nodev", "nosuid", "noexec"} - _mount_options_for(partition)
    if missing_options:
        with suppress(UdisksFailure):
            _run_udisks("unmount", partition, timeout_s=30)
        raise BootstrapFirmwareError(
            "updater mount omitted required safety options: "
            + ", ".join(sorted(missing_options))
        )
    return mountpoint


def _preflight_udisks(*, partition: Path, block_device: Path) -> None:
    """Require a responsive daemon and unchanged, unmounted exact target."""

    _require_udisks_device(partition)
    _require_udisks_device(block_device)
    if _mountpoint_for(partition) is not None:
        raise _udisks_already_mounted(partition)
    _run_udisks("status", None, timeout_s=5)
    _require_udisks_device(partition)
    _require_udisks_device(block_device)
    if _mountpoint_for(partition) is not None:
        raise _udisks_already_mounted(partition)


def _run_udisks(operation: str, device: Path | None, *, timeout_s: float) -> None:
    argv: tuple[str, ...]
    if operation == "status":
        argv = ("udisksctl", "status")
    elif operation == "mount" and device is not None:
        argv = (
            "udisksctl",
            "mount",
            "--block-device",
            str(device),
            "--options",
            "rw,nodev,nosuid,noexec",
        )
    elif operation in {"unmount", "power-off"} and device is not None:
        argv = ("udisksctl", operation, "--block-device", str(device))
    else:  # pragma: no cover - internal programming guard
        raise ValueError(f"invalid udisks operation: {operation}")
    try:
        _run(argv, timeout_s=timeout_s)
    except BootstrapFirmwareError as error:
        if device is not None and not device.exists():
            raise UdisksFailure(
                "device_disappeared",
                f"exact device {device} disappeared during {operation}",
                "Reconnect the radio and create a fresh path-bound flash plan.",
            ) from error
        raise _classify_udisks_failure(error, operation=operation, device=device) from error


def _require_udisks_device(device: Path) -> None:
    if not device.exists():
        raise UdisksFailure(
            "device_disappeared",
            f"exact device {device} is unavailable",
            "Reconnect the radio and create a fresh path-bound flash plan.",
        )


def _udisks_already_mounted(partition: Path) -> UdisksFailure:
    return UdisksFailure(
        "already_mounted",
        f"exact updater partition {partition} is already mounted",
        "Inspect the exact updater volume, remove or reconcile any existing pluto.frm, "
        f"then unmount it with `udisksctl unmount --block-device {partition}` and re-plan.",
    )


def _classify_udisks_failure(
    error: BootstrapFirmwareError,
    *,
    operation: str,
    device: Path | None,
) -> UdisksFailure:
    detail = str(error)
    lowered = detail.lower()
    target = "udisks daemon" if device is None else f"exact device {device}"
    if "timeout" in lowered or "timed out" in lowered:
        return UdisksFailure(
            "daemon_timeout",
            f"{operation} timed out for {target}",
            "Restore or restart udisks2.service, verify `udisksctl status`, then retry.",
        )
    if any(
        marker in lowered
        for marker in (
            "not authorized",
            "authorization",
            "authentication",
            "access denied",
            "permission denied",
            "not permitted",
            "polkit",
        )
    ):
        return UdisksFailure(
            "authorization_denied",
            f"{operation} was denied for {target}",
            "Use an authorized local session or correct the host udisks/polkit policy; "
            "no privileged mount fallback is used.",
        )
    if "already mounted" in lowered:
        assert device is not None
        return _udisks_already_mounted(device)
    if any(
        marker in lowered
        for marker in (
            "error connecting to the udisks daemon",
            "udisks daemon",
            "serviceunknown",
            "service unknown",
            "connection refused",
            "no such file or directory",
            "not found",
        )
    ):
        return UdisksFailure(
            "daemon_unavailable",
            f"{operation} could not reach the udisks daemon",
            "Start or restore udisks2.service, verify `udisksctl status`, then retry.",
        )
    return UdisksFailure(
        "operation_failed",
        f"{operation} failed for {target}: {detail}",
        "Inspect the host udisks2 service and logs, verify the exact device, then re-plan.",
    )


def _bootstrap_failure_phase(phases: list[str]) -> str:
    if "mounted" not in phases:
        return "mount"
    if "pluto_frm_written" not in phases:
        return "pre_write_validation"
    if "synced" not in phases:
        return "sync"
    if "unmounted" not in phases:
        return "unmount"
    if "ejected" not in phases:
        return "power_off"
    return "return_attestation"


def _mountpoint_for(partition: Path) -> Path | None:
    try:
        device = partition.stat().st_rdev
    except OSError:
        return None
    needle = f"{os.major(device)}:{os.minor(device)}"
    try:
        lines = Path("/proc/self/mountinfo").read_text().splitlines()
    except OSError:
        return None
    for line in lines:
        fields = line.split()
        if len(fields) > 4 and fields[2] == needle:
            value = fields[4]
            for encoded, decoded in (("\\040", " "), ("\\011", "\t"), ("\\134", "\\")):
                value = value.replace(encoded, decoded)
            return Path(value)
    return None


def _mount_options_for(partition: Path) -> set[str]:
    try:
        device = partition.stat().st_rdev
        lines = Path("/proc/self/mountinfo").read_text().splitlines()
    except OSError:
        return set()
    needle = f"{os.major(device)}:{os.minor(device)}"
    for line in lines:
        fields = line.split()
        if len(fields) <= 6 or fields[2] != needle or "-" not in fields:
            continue
        separator = fields.index("-")
        options = set(fields[5].split(","))
        if len(fields) > separator + 3:
            options.update(fields[separator + 3].split(","))
        return options
    return set()


def _write_fat_atomic(destination: Path, data: bytes) -> None:
    temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise


def _run(argv: tuple[str, ...], *, timeout_s: float) -> None:
    try:
        subprocess.run(
            argv,
            check=True,
            timeout=timeout_s,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as error:
        detail = str(error.stderr or error.stdout or "").strip()
        suffix = f": {detail[-500:]}" if detail else ""
        raise BootstrapFirmwareError(
            f"command {argv[0]!r} exited {error.returncode}{suffix}"
        ) from error
    except (OSError, subprocess.SubprocessError) as error:
        raise BootstrapFirmwareError(f"command {argv[0]!r} failed: {error}") from error


def _run_output(argv: tuple[str, ...], *, timeout_s: float) -> str:
    try:
        completed = subprocess.run(
            argv,
            check=True,
            timeout=timeout_s,
            capture_output=True,
            text=True,
        )
        return completed.stdout
    except (OSError, subprocess.SubprocessError) as error:
        raise BootstrapFirmwareError(f"command {argv[0]!r} failed: {error}") from error


def _wait_for_path(path: Path, *, present: bool, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if path.exists() is present:
            return
        time.sleep(0.5)
    state = "appear" if present else "disappear"
    raise BootstrapFirmwareError(f"USB path {path} did not {state} within {timeout_s:g}s")


def _write_receipt(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _update_receipt(
    path: Path,
    receipt: dict[str, Any],
    phases: list[str],
) -> None:
    receipt["phases"] = list(phases)
    _write_receipt(path, receipt)
