"""Guarded daemon-independent RAM-only DFU boot for one exact USB Pluto."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import subprocess
import tempfile
import time
import uuid
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Protocol

from pluto_plus.bootstrap_firmware import (
    STANDALONE_FLASH_PROFILES,
    BoundSshBootstrapTransport,
    inspect_bound_iiod,
    mute_returned_radio_at_path,
)
from pluto_plus.firmware import FirmwareImageError, validate_dfu
from pluto_plus.inventory import LocalUsbPluto, scan_local_usb_plutos
from pluto_plus.local_reboot import FixedSshLocalRebootTransport

_USB_ROOT = Path("/sys/bus/usb/devices")
_SERIAL = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


class VolatileFirmwareError(RuntimeError):
    """RAM-boot precondition or execution failure."""


@dataclass(frozen=True, slots=True)
class VolatileFirmwarePlan:
    schema_version: int
    plan_id: str
    created_at: str
    serial: str
    usb_sysfs_path: str
    usb_port: str
    runtime_usb_device_node: str
    raw_usb_write_access: bool
    usb_interface: str
    transition_host: str
    transition_route_mode: Literal["usb_gadget", "lan"]
    known_hosts_sha256: str
    before_firmware: str
    before_model: str
    before_phy: str
    image_path: str
    image_sha256: str
    fit_sha256: str
    fit_size: int
    profile_id: str
    expected_firmware: str
    expected_metadata_abi: int
    expected_tandem_agc: bool
    confirmation_phrase: str
    expected_ddr_burst_max_iq_bytes: int | None = None
    expected_ddr_burst_reserve_bytes: int | None = None
    expected_ddr_ring_max_iq_bytes: int | None = None
    expected_ddr_ring_modes: str | None = None
    expected_buffer_metadata_status: bool = False
    expected_buffer_metadata_timing_log: bool = False
    expected_iiod_cpu_affinity: int | None = None
    expected_iiod_rw_cpu_affinity: int | None = None


@dataclass(frozen=True, slots=True)
class VolatileFirmwareResult:
    schema_version: int
    receipt_id: str
    outcome: Literal["success", "failed_before_mutation", "unknown"]
    phases: tuple[str, ...]
    receipt_path: str
    returned_serial: str | None = None
    returned_firmware: str | None = None
    returned_phy: str | None = None
    error: str | None = None
    retryable: bool = False
    remediation: str | None = None
    source_receipt_id: str | None = None


class RamBootTransition(Protocol):
    def enter_ram(self, plan: VolatileFirmwarePlan) -> None: ...


class DfuCommandRunner(Protocol):
    def run(self, argv: Sequence[str], *, timeout_s: float) -> str: ...


class SubprocessDfuRunner:
    def run(self, argv: Sequence[str], *, timeout_s: float) -> str:
        try:
            completed = subprocess.run(
                tuple(argv),
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout_s,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise VolatileFirmwareError(f"DFU command failed to run: {error}") from error
        output = (completed.stdout + completed.stderr)[-4000:]
        if completed.returncode != 0:
            raise VolatileFirmwareError(
                f"DFU command exited {completed.returncode}: {output.strip()}"
            )
        return output


class SshRamBootTransition:
    """Narrow SSH adapter: attest, mute/read back, then enter RAM DFU."""

    def __init__(self, transport: BoundSshBootstrapTransport) -> None:
        self._transport = transport
        self._radio = FixedSshLocalRebootTransport(transport)

    def enter_ram(self, plan: VolatileFirmwarePlan) -> None:
        before = self._radio.attest(plan.serial)
        if (
            before.firmware != plan.before_firmware
            or not _is_plutosdr_rev_c(plan.before_model)
            or not _is_plutosdr_rev_c(before.capabilities.board_model)
            or before.capabilities.phy_model != plan.before_phy
        ):
            raise VolatileFirmwareError("remote SSH facts changed from the USB-bound plan")
        self._radio.ensure_tx_safe(plan.serial)
        self._transport.run(
            "set -eu; "
            f'test "$(cat /sys/kernel/config/usb_gadget/composite_gadget/strings/0x409/'
            f'serialnumber)" = "{plan.serial}"; '
            "/bin/sync; /usr/sbin/device_reboot ram",
            timeout_s=15,
        )


def _is_plutosdr_rev_c(model: str) -> bool:
    """Match the stable board identity across IIOD and device-tree spellings."""

    return "plutosdr rev.c" in model.casefold().replace("+", "")


def prepare_ram_boot_plan(
    image: Path,
    usb_sysfs_path: Path,
    *,
    profile_id: str,
    transition_host: str,
    known_hosts_file: Path,
    scanner: Callable[[], Sequence[LocalUsbPluto]] = scan_local_usb_plutos,
    iiod_inspector: Callable[[str], dict[str, object]] = inspect_bound_iiod,
    usb_access_checker: Callable[[Path], bool] = lambda path: os.access(path, os.R_OK | os.W_OK),
) -> VolatileFirmwarePlan:
    """Build a read-only exact-profile plan; never infer a candidate from bytes."""

    profile = STANDALONE_FLASH_PROFILES.get(profile_id)
    if profile is None:
        raise VolatileFirmwareError(
            f"unknown RAM-boot profile {profile_id!r}; expected one of "
            f"{sorted(STANDALONE_FLASH_PROFILES)}"
        )
    policy = profile.policy
    path = usb_sysfs_path.expanduser().absolute()
    if path.parent != _USB_ROOT or ":" in path.name:
        raise VolatileFirmwareError(
            "--usb-sysfs-path must name one direct /sys/bus/usb/devices runtime device"
        )
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise VolatileFirmwareError(f"USB target is unavailable: {error}") from error
    if resolved.name != path.name:
        raise VolatileFirmwareError("USB target is not one direct runtime device")
    matches = [device for device in scanner() if device.usb_path == str(path)]
    if len(matches) != 1:
        raise VolatileFirmwareError(f"expected exactly one runtime Pluto at {path}")
    local = matches[0]
    if local.serial is None or not _SERIAL.fullmatch(local.serial):
        raise VolatileFirmwareError("RAM boot requires one stable non-blank USB serial")
    if len(local.host_network_interfaces) != 1:
        raise VolatileFirmwareError("RAM boot requires one exact USB network interface")
    if local.bus_number is None or local.device_number is None:
        raise VolatileFirmwareError("RAM boot requires a current USB bus/device address")
    usb_device_node = Path(f"/dev/bus/usb/{local.bus_number:03d}/{local.device_number:03d}")
    interface = local.host_network_interfaces[0].name
    facts = iiod_inspector(interface)
    live_serial = str(facts.get("hw_serial") or "").strip()
    model = str(facts.get("hw_model") or "").strip()
    firmware = str(facts.get("fw_version") or "").strip()
    phy = str(facts.get("ad9361-phy,model") or "").strip()
    if live_serial != local.serial:
        raise VolatileFirmwareError("USB and USB-bound IIOD serials do not match")
    if "plutosdr rev.c" not in model.lower():
        raise VolatileFirmwareError("RAM boot requires an attested PlutoSDR Rev.C")
    if not firmware or phy not in {"ad9361", "ad9363a", "ad9364"}:
        raise VolatileFirmwareError("USB-bound IIOD firmware/PHY facts are incomplete")
    try:
        image_data = image.read_bytes()
    except OSError as error:
        raise VolatileFirmwareError(f"cannot read firmware image: {error}") from error
    image_sha = hashlib.sha256(image_data).hexdigest()
    if image_sha != policy.asset_sha256:
        raise VolatileFirmwareError(
            f"profile {profile_id!r} accepts only SHA-256 {policy.asset_sha256}; got {image_sha}"
        )
    try:
        fit = validate_dfu(image_data)
    except FirmwareImageError as error:
        raise VolatileFirmwareError(f"invalid profile DFU: {error}") from error
    fit_sha = hashlib.sha256(fit).hexdigest()
    if fit_sha != policy.fit_body_sha256 or len(fit) != policy.fit_body_size:
        raise VolatileFirmwareError("DFU FIT body does not match the immutable profile")
    try:
        host = ipaddress.ip_address(transition_host)
    except ValueError as error:
        raise VolatileFirmwareError("transition host must be a literal private IPv4") from error
    if host.version != 4 or not host.is_private:
        raise VolatileFirmwareError("transition host must be a literal private IPv4")
    return VolatileFirmwarePlan(
        schema_version=1,
        plan_id=uuid.uuid4().hex,
        created_at=datetime.now(UTC).isoformat(),
        serial=local.serial,
        usb_sysfs_path=str(path),
        usb_port=path.name,
        runtime_usb_device_node=str(usb_device_node),
        raw_usb_write_access=usb_access_checker(usb_device_node),
        usb_interface=interface,
        transition_host=transition_host,
        transition_route_mode=("usb_gadget" if transition_host == "192.168.2.1" else "lan"),
        known_hosts_sha256=_private_file_sha256(known_hosts_file),
        before_firmware=firmware,
        before_model=model,
        before_phy=phy,
        image_path=str(image.resolve()),
        image_sha256=image_sha,
        fit_sha256=fit_sha,
        fit_size=len(fit),
        profile_id=profile_id,
        expected_firmware=policy.device_firmware,
        expected_metadata_abi=profile.metadata_abi,
        expected_tandem_agc=profile.tandem_agc,
        confirmation_phrase=f"RAM BOOT {local.serial}",
        expected_ddr_burst_max_iq_bytes=profile.ddr_burst_max_iq_bytes,
        expected_ddr_burst_reserve_bytes=profile.ddr_burst_reserve_bytes,
        expected_ddr_ring_max_iq_bytes=profile.ddr_ring_max_iq_bytes,
        expected_ddr_ring_modes=profile.ddr_ring_modes,
        expected_buffer_metadata_status=profile.buffer_metadata_status,
        expected_buffer_metadata_timing_log=profile.buffer_metadata_timing_log,
        expected_iiod_cpu_affinity=profile.iiod_cpu_affinity,
        expected_iiod_rw_cpu_affinity=profile.iiod_rw_cpu_affinity,
    )


def execute_ram_boot_plan(
    plan: VolatileFirmwarePlan,
    *,
    confirmation: str,
    known_hosts_file: Path,
    transition: RamBootTransition,
    receipt_directory: Path,
    command_runner: DfuCommandRunner | None = None,
    scanner: Callable[[], Sequence[LocalUsbPluto]] = scan_local_usb_plutos,
    iiod_inspector: Callable[[str], dict[str, object]] = inspect_bound_iiod,
    usb_access_checker: Callable[[Path], bool] = lambda path: os.access(path, os.R_OK | os.W_OK),
    usb_product_reader: Callable[[Path], str | None] = lambda path: _usb_product(path),
    timeout_s: float = 120,
    poll_interval_s: float = 0.25,
) -> VolatileFirmwareResult:
    """Enter DFU and load only the selected profile into RAM."""

    if confirmation != plan.confirmation_phrase:
        raise VolatileFirmwareError(f"confirmation must be exactly {plan.confirmation_phrase!r}")
    if timeout_s <= 0 or poll_interval_s <= 0:
        raise ValueError("RAM-boot timeouts must be positive")
    fresh = prepare_ram_boot_plan(
        Path(plan.image_path),
        Path(plan.usb_sysfs_path),
        profile_id=plan.profile_id,
        transition_host=plan.transition_host,
        known_hosts_file=known_hosts_file,
        scanner=scanner,
        iiod_inspector=iiod_inspector,
        usb_access_checker=usb_access_checker,
    )
    for field in (
        "serial",
        "usb_sysfs_path",
        "usb_port",
        "runtime_usb_device_node",
        "raw_usb_write_access",
        "usb_interface",
        "transition_host",
        "transition_route_mode",
        "known_hosts_sha256",
        "before_firmware",
        "before_model",
        "before_phy",
        "image_path",
        "image_sha256",
        "fit_sha256",
        "fit_size",
        "profile_id",
        "expected_firmware",
        "expected_metadata_abi",
        "expected_tandem_agc",
        "expected_ddr_burst_max_iq_bytes",
        "expected_ddr_burst_reserve_bytes",
        "expected_ddr_ring_max_iq_bytes",
        "expected_ddr_ring_modes",
        "expected_buffer_metadata_status",
        "expected_buffer_metadata_timing_log",
        "expected_iiod_cpu_affinity",
        "expected_iiod_rw_cpu_affinity",
    ):
        if getattr(fresh, field) != getattr(plan, field):
            raise VolatileFirmwareError(f"RAM-boot precondition changed: {field}")
    if not fresh.raw_usb_write_access:
        raise VolatileFirmwareError(
            f"raw USB node {fresh.runtime_usb_device_node} is not writable; install a "
            "serial-preserving 0456:b673/b674 udev permission rule before RAM boot"
        )
    runner = command_runner or SubprocessDfuRunner()
    runner.run(("dfu-util", "--version"), timeout_s=5)

    receipt_id = uuid.uuid4().hex
    receipt_path = receipt_directory / f"{receipt_id}.json"
    phases = ["preflight_revalidated", "dfu_util_ready"]
    started = {
        "schema_version": 1,
        "receipt_id": receipt_id,
        "outcome": "started",
        "plan": asdict(plan),
        "phases": phases,
        "error": None,
    }
    _write_receipt(receipt_path, started)
    mutation_started = False
    try:
        phases.append("ram_transition_dispatch_attempted")
        _write_receipt(receipt_path, started | {"phases": phases})
        mutation_started = True
        transition.enter_ram(plan)
        phases.append("ram_transition_dispatched")
        _write_receipt(receipt_path, started | {"phases": phases})
        _wait_for_product(
            Path(plan.usb_sysfs_path),
            "b674",
            reader=usb_product_reader,
            timeout_s=30,
            poll_interval_s=poll_interval_s,
        )
        phases.append("exact_path_entered_dfu")
        _write_receipt(receipt_path, started | {"phases": phases})
        common = (
            "dfu-util",
            "-p",
            plan.usb_port,
            "-d",
            "0456:b673,0456:b674",
            "-a",
            "firmware.dfu",
        )
        runner.run((*common, "-D", plan.image_path), timeout_s=120)
        phases.append("volatile_dfu_downloaded")
        _write_receipt(receipt_path, started | {"phases": phases})
        runner.run((*common, "-e"), timeout_s=30)
        phases.append("dfu_detach_dispatched")
        _write_receipt(receipt_path, started | {"phases": phases})
        _wait_for_product(
            Path(plan.usb_sysfs_path),
            "b673",
            reader=usb_product_reader,
            timeout_s=timeout_s,
            poll_interval_s=poll_interval_s,
        )
        phases.append("exact_path_returned_runtime")
        serial, firmware, phy = _attest_ram_return(
            plan,
            scanner=scanner,
            iiod_inspector=iiod_inspector,
            timeout_s=timeout_s,
            poll_interval_s=poll_interval_s,
        )
        phases.extend(("return_attested", "tx_safe_attested"))
        result = VolatileFirmwareResult(
            schema_version=1,
            receipt_id=receipt_id,
            outcome="success",
            phases=tuple(phases),
            receipt_path=str(receipt_path),
            returned_serial=serial,
            returned_firmware=firmware,
            returned_phy=phy,
            retryable=False,
            remediation=(
                "RAM-only image is active. Power cycle to return to the unchanged QSPI image; "
                "persistent promotion requires a separate qualified flash plan."
            ),
        )
    except BaseException as error:
        result = VolatileFirmwareResult(
            schema_version=1,
            receipt_id=receipt_id,
            outcome="unknown" if mutation_started else "failed_before_mutation",
            phases=tuple(phases),
            receipt_path=str(receipt_path),
            error=f"{type(error).__name__}: {error}",
            retryable=not mutation_started,
            remediation=(
                "Do not retry. Reconcile the exact serial/path and determine whether it is "
                "runtime, DFU, or running the candidate."
                if mutation_started
                else "Correct the preflight failure and create a fresh plan."
            ),
        )
    _write_receipt(receipt_path, started | asdict(result))
    return result


def resume_ram_boot_receipt(
    source_receipt: Path,
    *,
    confirmation: str,
    receipt_directory: Path,
    command_runner: DfuCommandRunner | None = None,
    scanner: Callable[[], Sequence[LocalUsbPluto]] = scan_local_usb_plutos,
    iiod_inspector: Callable[[str], dict[str, object]] = inspect_bound_iiod,
    usb_access_checker: Callable[[Path], bool] = lambda path: os.access(path, os.R_OK | os.W_OK),
    usb_product_reader: Callable[[Path], str | None] = lambda path: _usb_product(path),
    timeout_s: float = 120,
    poll_interval_s: float = 0.25,
) -> VolatileFirmwareResult:
    """Resume only a receipt proven to have stopped at the exact DFU boundary."""

    source_id, plan = _load_dfu_boundary_receipt(source_receipt)
    expected_confirmation = f"RESUME RAM BOOT {source_id}"
    if confirmation != expected_confirmation:
        raise VolatileFirmwareError(f"confirmation must be exactly {expected_confirmation!r}")
    if timeout_s <= 0 or poll_interval_s <= 0:
        raise ValueError("RAM-boot timeouts must be positive")
    path = Path(plan.usb_sysfs_path)
    if usb_product_reader(path) != "b674":
        raise VolatileFirmwareError("receipt USB path is not currently the Pluto DFU device")
    raw_node = _current_usb_device_node(path)
    if not usb_access_checker(raw_node):
        raise VolatileFirmwareError(f"current raw USB node {raw_node} is not writable")
    _revalidate_plan_image(plan)
    runner = command_runner or SubprocessDfuRunner()
    runner.run(("dfu-util", "--version"), timeout_s=5)

    receipt_id = uuid.uuid4().hex
    receipt_path = receipt_directory / f"{receipt_id}.json"
    phases = ["resume_preflight_revalidated", "dfu_util_ready", "exact_path_attested_dfu"]
    started: dict[str, object] = {
        "schema_version": 1,
        "receipt_id": receipt_id,
        "source_receipt_id": source_id,
        "outcome": "started",
        "plan": asdict(plan),
        "phases": phases,
        "error": None,
    }
    _write_receipt(receipt_path, started)
    try:
        common = (
            "dfu-util",
            "-p",
            plan.usb_port,
            "-d",
            "0456:b673,0456:b674",
            "-a",
            "firmware.dfu",
        )
        runner.run((*common, "-D", plan.image_path), timeout_s=120)
        phases.append("volatile_dfu_downloaded")
        _write_receipt(receipt_path, started | {"phases": phases})
        runner.run((*common, "-e"), timeout_s=30)
        phases.append("dfu_detach_dispatched")
        _write_receipt(receipt_path, started | {"phases": phases})
        _wait_for_product(
            path,
            "b673",
            reader=usb_product_reader,
            timeout_s=timeout_s,
            poll_interval_s=poll_interval_s,
        )
        phases.append("exact_path_returned_runtime")
        serial, firmware, phy = _attest_ram_return(
            plan,
            scanner=scanner,
            iiod_inspector=iiod_inspector,
            timeout_s=timeout_s,
            poll_interval_s=poll_interval_s,
        )
        phases.extend(("return_attested", "tx_safe_attested"))
        result = VolatileFirmwareResult(
            schema_version=1,
            receipt_id=receipt_id,
            outcome="success",
            phases=tuple(phases),
            receipt_path=str(receipt_path),
            returned_serial=serial,
            returned_firmware=firmware,
            returned_phy=phy,
            remediation="RAM-only image is active; QSPI remains unchanged.",
            source_receipt_id=source_id,
        )
    except BaseException as error:
        result = VolatileFirmwareResult(
            schema_version=1,
            receipt_id=receipt_id,
            outcome="unknown",
            phases=tuple(phases),
            receipt_path=str(receipt_path),
            error=f"{type(error).__name__}: {error}",
            remediation="Do not retry; reconcile the exact USB path and receipt.",
            source_receipt_id=source_id,
        )
    _write_receipt(receipt_path, started | asdict(result))
    return result


def reconcile_ram_boot_receipt(
    source_receipt: Path,
    *,
    confirmation: str,
    receipt_directory: Path,
    scanner: Callable[[], Sequence[LocalUsbPluto]] = scan_local_usb_plutos,
    iiod_inspector: Callable[[str], dict[str, object]] = inspect_bound_iiod,
    usb_product_reader: Callable[[Path], str | None] = lambda path: _usb_product(path),
    timeout_s: float = 30,
    poll_interval_s: float = 0.25,
) -> VolatileFirmwareResult:
    """Close an uncertain post-detach receipt without another DFU operation.

    Reconciliation accepts only a receipt whose exact phase history proves that
    the candidate was downloaded, detached, and returned at the recorded
    runtime topology.  It revalidates the immutable image/profile and performs
    only identity/capability and TX-safe attestation; it has no command runner
    and cannot download, detach, reboot, or write QSPI.
    """

    source_id, plan = _load_returned_runtime_receipt(source_receipt)
    expected_confirmation = f"RECONCILE RAM BOOT {source_id}"
    if confirmation != expected_confirmation:
        raise VolatileFirmwareError(f"confirmation must be exactly {expected_confirmation!r}")
    if timeout_s <= 0 or poll_interval_s <= 0:
        raise ValueError("RAM-boot timeouts must be positive")
    _revalidate_plan_image(plan)
    path = Path(plan.usb_sysfs_path)
    if usb_product_reader(path) != "b673":
        raise VolatileFirmwareError("receipt USB path is not currently the Pluto runtime device")

    receipt_id = uuid.uuid4().hex
    receipt_path = receipt_directory / f"{receipt_id}.json"
    phases = ["reconcile_preflight_revalidated", "exact_path_attested_runtime"]
    started: dict[str, object] = {
        "schema_version": 1,
        "receipt_id": receipt_id,
        "source_receipt_id": source_id,
        "outcome": "started",
        "plan": asdict(plan),
        "phases": phases,
        "error": None,
    }
    _write_receipt(receipt_path, started)
    try:
        serial, firmware, phy = _attest_ram_return(
            plan,
            scanner=scanner,
            iiod_inspector=iiod_inspector,
            timeout_s=timeout_s,
            poll_interval_s=poll_interval_s,
        )
        phases.extend(("return_attested", "tx_safe_attested", "source_receipt_reconciled"))
        result = VolatileFirmwareResult(
            schema_version=1,
            receipt_id=receipt_id,
            outcome="success",
            phases=tuple(phases),
            receipt_path=str(receipt_path),
            returned_serial=serial,
            returned_firmware=firmware,
            returned_phy=phy,
            retryable=False,
            remediation="RAM-only image is attested; QSPI remains unchanged.",
            source_receipt_id=source_id,
        )
    except BaseException as error:
        result = VolatileFirmwareResult(
            schema_version=1,
            receipt_id=receipt_id,
            outcome="failed_before_mutation",
            phases=tuple(phases),
            receipt_path=str(receipt_path),
            error=f"{type(error).__name__}: {error}",
            retryable=True,
            remediation=(
                "No firmware operation was attempted; correct the attestation failure and "
                "reconcile this same source receipt again."
            ),
            source_receipt_id=source_id,
        )
    _write_receipt(receipt_path, started | asdict(result))
    return result


def _load_dfu_boundary_receipt(path: Path) -> tuple[str, VolatileFirmwarePlan]:
    try:
        stat_result = path.lstat()
        data = path.read_bytes()
    except OSError as error:
        raise VolatileFirmwareError(f"RAM-boot receipt is not readable: {error}") from error
    if path.is_symlink() or not path.is_file() or stat_result.st_mode & 0o077:
        raise VolatileFirmwareError("RAM-boot receipt must be a private regular file")
    try:
        payload = json.loads(data)
        receipt_id = str(payload["receipt_id"])
        phases = tuple(str(value) for value in payload["phases"])
        plan = VolatileFirmwarePlan(**payload["plan"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise VolatileFirmwareError("RAM-boot receipt is malformed") from error
    expected_phases = (
        "preflight_revalidated",
        "dfu_util_ready",
        "ram_transition_dispatch_attempted",
        "ram_transition_dispatched",
        "exact_path_entered_dfu",
    )
    if payload.get("outcome") != "unknown" or phases != expected_phases:
        raise VolatileFirmwareError("receipt did not stop at the resumable DFU boundary")
    if path.stem != receipt_id or not re.fullmatch(r"[0-9a-f]{32}", receipt_id):
        raise VolatileFirmwareError("receipt identity does not match its filename")
    _validate_receipt_plan_identity(plan)
    return receipt_id, plan


def _load_returned_runtime_receipt(path: Path) -> tuple[str, VolatileFirmwarePlan]:
    try:
        stat_result = path.lstat()
        data = path.read_bytes()
    except OSError as error:
        raise VolatileFirmwareError(f"RAM-boot receipt is not readable: {error}") from error
    if path.is_symlink() or not path.is_file() or stat_result.st_mode & 0o077:
        raise VolatileFirmwareError("RAM-boot receipt must be a private regular file")
    try:
        payload = json.loads(data)
        receipt_id = str(payload["receipt_id"])
        phases = tuple(str(value) for value in payload["phases"])
        plan = VolatileFirmwarePlan(**payload["plan"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise VolatileFirmwareError("RAM-boot receipt is malformed") from error
    original_return = (
        "preflight_revalidated",
        "dfu_util_ready",
        "ram_transition_dispatch_attempted",
        "ram_transition_dispatched",
        "exact_path_entered_dfu",
        "volatile_dfu_downloaded",
        "dfu_detach_dispatched",
        "exact_path_returned_runtime",
    )
    resumed_return = (
        "resume_preflight_revalidated",
        "dfu_util_ready",
        "exact_path_attested_dfu",
        "volatile_dfu_downloaded",
        "dfu_detach_dispatched",
        "exact_path_returned_runtime",
    )
    if payload.get("outcome") != "unknown" or phases not in {
        original_return,
        resumed_return,
    }:
        raise VolatileFirmwareError("receipt did not stop after exact-path runtime return")
    if path.stem != receipt_id or not re.fullmatch(r"[0-9a-f]{32}", receipt_id):
        raise VolatileFirmwareError("receipt identity does not match its filename")
    _validate_receipt_plan_identity(plan)
    return receipt_id, plan


def _validate_receipt_plan_identity(plan: VolatileFirmwarePlan) -> None:
    path = Path(plan.usb_sysfs_path)
    if (
        plan.schema_version != 1
        or not _SERIAL.fullmatch(plan.serial)
        or not path.is_absolute()
        or path.parent != _USB_ROOT
        or ":" in path.name
        or path.name != plan.usb_port
        or plan.confirmation_phrase != f"RAM BOOT {plan.serial}"
    ):
        raise VolatileFirmwareError("RAM-boot receipt plan identity is invalid")


def _revalidate_plan_image(plan: VolatileFirmwarePlan) -> None:
    profile = STANDALONE_FLASH_PROFILES.get(plan.profile_id)
    if profile is None:
        raise VolatileFirmwareError("receipt references an unknown RAM-boot profile")
    try:
        image = Path(plan.image_path).read_bytes()
        fit = validate_dfu(image)
    except (OSError, FirmwareImageError) as error:
        raise VolatileFirmwareError(f"receipt image cannot be revalidated: {error}") from error
    policy = profile.policy
    if (
        hashlib.sha256(image).hexdigest() != plan.image_sha256
        or plan.image_sha256 != policy.asset_sha256
        or hashlib.sha256(fit).hexdigest() != plan.fit_sha256
        or plan.fit_sha256 != policy.fit_body_sha256
        or len(fit) != plan.fit_size
        or plan.fit_size != policy.fit_body_size
        or plan.expected_firmware != policy.device_firmware
        or plan.expected_metadata_abi != profile.metadata_abi
        or plan.expected_tandem_agc is not profile.tandem_agc
        or plan.expected_ddr_burst_max_iq_bytes != profile.ddr_burst_max_iq_bytes
        or plan.expected_ddr_burst_reserve_bytes != profile.ddr_burst_reserve_bytes
        or plan.expected_ddr_ring_max_iq_bytes != profile.ddr_ring_max_iq_bytes
        or plan.expected_ddr_ring_modes != profile.ddr_ring_modes
        or plan.expected_buffer_metadata_status is not profile.buffer_metadata_status
        or plan.expected_buffer_metadata_timing_log is not profile.buffer_metadata_timing_log
        or plan.expected_iiod_cpu_affinity != profile.iiod_cpu_affinity
        or plan.expected_iiod_rw_cpu_affinity != profile.iiod_rw_cpu_affinity
    ):
        raise VolatileFirmwareError("receipt image no longer matches its immutable profile")


def _current_usb_device_node(path: Path) -> Path:
    try:
        bus = int((path / "busnum").read_text().strip())
        device = int((path / "devnum").read_text().strip())
    except (OSError, ValueError) as error:
        raise VolatileFirmwareError("cannot resolve the current DFU raw USB node") from error
    return Path(f"/dev/bus/usb/{bus:03d}/{device:03d}")


def _attest_ram_return(
    plan: VolatileFirmwarePlan,
    *,
    scanner: Callable[[], Sequence[LocalUsbPluto]],
    iiod_inspector: Callable[[str], dict[str, object]],
    timeout_s: float,
    poll_interval_s: float,
) -> tuple[str, str, str]:
    deadline = time.monotonic() + timeout_s
    last_error: BaseException | None = None
    while time.monotonic() < deadline:
        try:
            matches = [
                item
                for item in scanner()
                if item.usb_path == plan.usb_sysfs_path and item.serial == plan.serial
            ]
            if len(matches) != 1:
                raise VolatileFirmwareError("same serial/path has not returned")
            names = tuple(item.name for item in matches[0].host_network_interfaces)
            if names != (plan.usb_interface,):
                raise VolatileFirmwareError("USB interface changed after RAM boot")
            facts = iiod_inspector(plan.usb_interface)
            serial = str(facts.get("hw_serial") or "").strip()
            firmware = str(facts.get("fw_version") or "").strip()
            phy = str(facts.get("ad9361-phy,model") or "").strip()
            metadata = str(facts.get("iio,buffer-metadata") or "").strip()
            raw_names = facts.get("device_names", ())
            device_names = (
                {str(value) for value in raw_names}
                if isinstance(raw_names, (tuple, list, set, frozenset))
                else set()
            )
            if serial != plan.serial or firmware != plan.expected_firmware:
                raise VolatileFirmwareError("returned RAM image identity/version is wrong")
            if phy != plan.before_phy or metadata != str(plan.expected_metadata_abi):
                raise VolatileFirmwareError("returned RAM image PHY/metadata ABI is wrong")
            if ("tandem-agc" in device_names) is not plan.expected_tandem_agc:
                raise VolatileFirmwareError("returned RAM image tandem capability is wrong")
            observed_burst = str(facts.get("iio,buffer-ddr-burst") or "").strip()
            observed_max = str(facts.get("iio,buffer-ddr-burst-max-iq-bytes") or "").strip()
            observed_reserve = str(facts.get("iio,buffer-ddr-burst-reserve-bytes") or "").strip()
            if plan.expected_ddr_burst_max_iq_bytes is None:
                if observed_burst or observed_max or observed_reserve:
                    raise VolatileFirmwareError(
                        "returned RAM image has an unexpected DDR burst capability"
                    )
            elif (
                observed_burst != "1"
                or observed_max != str(plan.expected_ddr_burst_max_iq_bytes)
                or observed_reserve != str(plan.expected_ddr_burst_reserve_bytes)
            ):
                raise VolatileFirmwareError("returned RAM image DDR burst capability is wrong")
            observed_ring = str(facts.get("iio,buffer-ddr-ring") or "").strip()
            observed_ring_max = str(facts.get("iio,buffer-ddr-ring-max-iq-bytes") or "").strip()
            observed_ring_modes = str(facts.get("iio,buffer-ddr-ring-modes") or "").strip()
            observed_metadata_status = str(facts.get("iio,buffer-metadata-status") or "").strip()
            if plan.expected_ddr_ring_max_iq_bytes is None:
                if (
                    observed_ring
                    or observed_ring_max
                    or observed_ring_modes
                    or observed_metadata_status
                ):
                    raise VolatileFirmwareError(
                        "returned RAM image has an unexpected DDR ring capability"
                    )
            elif (
                observed_ring != "1"
                or observed_ring_max != str(plan.expected_ddr_ring_max_iq_bytes)
                or observed_ring_modes != plan.expected_ddr_ring_modes
                or (observed_metadata_status == "1") is not plan.expected_buffer_metadata_status
            ):
                raise VolatileFirmwareError("returned RAM image DDR ring capability is wrong")
            observed_timing_log = str(facts.get("iio,buffer-metadata-timing-log") or "").strip()
            expected_timing_log = "1" if plan.expected_buffer_metadata_timing_log else ""
            if observed_timing_log != expected_timing_log:
                raise VolatileFirmwareError(
                    "returned RAM image metadata timing-log capability is wrong"
                )
            observed_cpu_affinity = str(facts.get("iio,iiod-cpu-affinity") or "").strip()
            expected_cpu_affinity = (
                ""
                if plan.expected_iiod_cpu_affinity is None
                else str(plan.expected_iiod_cpu_affinity)
            )
            if observed_cpu_affinity != expected_cpu_affinity:
                raise VolatileFirmwareError(
                    "returned RAM image iiOD CPU-affinity capability is wrong"
                )
            observed_rw_cpu_affinity = str(
                facts.get("iio,iiod-rw-cpu-affinity") or ""
            ).strip()
            expected_rw_cpu_affinity = (
                ""
                if plan.expected_iiod_rw_cpu_affinity is None
                else str(plan.expected_iiod_rw_cpu_affinity)
            )
            if observed_rw_cpu_affinity != expected_rw_cpu_affinity:
                raise VolatileFirmwareError(
                    "returned RAM image iiOD R/W CPU-affinity capability is wrong"
                )
            mute_returned_radio_at_path(plan.serial, Path(plan.usb_sysfs_path))
            return serial, firmware, phy
        except BaseException as error:
            last_error = error
            time.sleep(poll_interval_s)
    raise VolatileFirmwareError(f"RAM image return attestation timed out: {last_error}")


def _wait_for_product(
    path: Path,
    expected: str,
    *,
    reader: Callable[[Path], str | None],
    timeout_s: float,
    poll_interval_s: float,
) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if reader(path) == expected:
            return
        time.sleep(poll_interval_s)
    raise VolatileFirmwareError(f"exact USB path {path} did not enumerate as product {expected}")


def _usb_product(path: Path) -> str | None:
    try:
        event = (path / "uevent").read_text()
    except (OSError, UnicodeError):
        return None
    for line in event.splitlines():
        if line.startswith("PRODUCT="):
            parts = line.removeprefix("PRODUCT=").split("/")
            if len(parts) == 3 and parts[0].lower().lstrip("0") == "456":
                return parts[1].lower()
    return None


def _private_file_sha256(path: Path) -> str:
    try:
        stat_result = path.lstat()
        data = path.read_bytes()
    except OSError as error:
        raise VolatileFirmwareError("SSH known-hosts file is not readable") from error
    if path.is_symlink() or not path.is_file() or stat_result.st_mode & 0o077:
        raise VolatileFirmwareError("SSH known-hosts must be a private regular non-symlink file")
    if not data or len(data) > 1024 * 1024:
        raise VolatileFirmwareError("SSH known-hosts is empty or too large")
    return hashlib.sha256(data).hexdigest()


def _write_receipt(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    data = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    descriptor, temporary_name = tempfile.mkstemp(prefix=".ram-boot-", dir=path.parent)
    temporary = Path(temporary_name)
    opened = False
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            opened = True
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        if not opened:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise
