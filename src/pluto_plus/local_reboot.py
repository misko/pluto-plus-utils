"""Serial-scoped local USB reboot with fail-closed attestation and receipts."""

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
from typing import Literal, Protocol

from pluto_plus.inventory import LocalUsbPluto, scan_local_usb_plutos
from pluto_plus.ip_firmware import (
    UsbSshRouteObservation,
    require_unambiguous_usb_ssh_route,
)
from pluto_plus.setup_helper import (
    SetupSshHostKeyChangedError,
    SetupTransport,
    validate_bound_interface,
)

_SERIAL_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


class LocalRebootError(RuntimeError):
    """A local reboot precondition or invariant failed."""


class LocalRebootExecutionError(LocalRebootError):
    """A reboot execution failed and has a durable receipt."""

    def __init__(self, message: str, receipt: LocalRebootReceipt) -> None:
        super().__init__(message)
        self.receipt = receipt


@dataclass(frozen=True, slots=True)
class LocalRebootCapabilities:
    board_model: str
    phy_model: str
    rx_scan_channels: tuple[str, ...]
    tandem_agc: bool


@dataclass(frozen=True, slots=True)
class LocalRebootAttestation:
    serial: str
    firmware: str
    boot_id: str | None
    capabilities: LocalRebootCapabilities


@dataclass(frozen=True, slots=True)
class LocalRebootPlan:
    schema_version: int
    plan_id: str
    created_at: str
    serial: str
    usb_sysfs_path: str
    usb_interface: str
    ssh_host: str
    ssh_route_mode: Literal["usb_gadget", "lan"]
    known_hosts_sha256: str
    route_observation: UsbSshRouteObservation | None
    confirmation_phrase: str


@dataclass(frozen=True, slots=True)
class LocalRebootReceipt:
    schema_version: int
    receipt_id: str
    plan: LocalRebootPlan
    started_at: str
    finished_at: str | None
    outcome: Literal["started", "success", "failed_before_mutation", "unknown"]
    completed_phases: tuple[str, ...]
    before: LocalRebootAttestation | None
    after: LocalRebootAttestation | None
    error: str | None
    receipt_path: str


class LocalRebootTransport(Protocol):
    def attest(self, serial: str) -> LocalRebootAttestation: ...

    def ensure_tx_safe(self, serial: str) -> None: ...

    def reboot(self, serial: str) -> None: ...


class FixedSshLocalRebootTransport:
    """Narrow adapter exposing only attest, TX-safe, and reboot operations."""

    def __init__(self, transport: SetupTransport) -> None:
        self._transport = transport

    def attest(self, serial: str) -> LocalRebootAttestation:
        _validate_serial(serial)
        fields = _parse_report(
            self._transport.run(f"/bin/sh -s -- {serial}", stdin=_ATTEST_SCRIPT, timeout_s=25)
        )
        if fields.get("serial") != serial:
            raise LocalRebootError("remote serial did not match the selected local radio")
        channels = tuple(
            sorted(item for item in fields.get("rx_scan_channels", "").split(",") if item)
        )
        if not channels:
            raise LocalRebootError("remote attestation found no RX scan channels")
        return LocalRebootAttestation(
            serial=serial,
            firmware=_required(fields, "firmware"),
            boot_id=_required(fields, "boot_id"),
            capabilities=LocalRebootCapabilities(
                board_model=_required(fields, "board_model"),
                phy_model=_required(fields, "phy_model"),
                rx_scan_channels=channels,
                tandem_agc=fields.get("tandem_agc") == "1",
            ),
        )

    def ensure_tx_safe(self, serial: str) -> None:
        _validate_serial(serial)
        fields = _parse_report(
            self._transport.run(f"/bin/sh -s -- {serial}", stdin=_TX_SAFE_SCRIPT, timeout_s=20)
        )
        if fields.get("tx_safe") != "1":
            raise LocalRebootError("TX-safe readback was not affirmative")

    def reboot(self, serial: str) -> None:
        _validate_serial(serial)
        self._transport.run(
            "set -eu; "
            f'test "$(cat /sys/kernel/config/usb_gadget/composite_gadget/strings/0x409/'
            f'serialnumber)" = "{serial}"; '
            "printf 'PPU\\treboot_dispatched\\t1\\n'; /bin/sync; "
            "/usr/sbin/device_reboot reset",
            timeout_s=15,
        )


def prepare_local_reboot(
    serial: str,
    usb_sysfs_path: Path,
    *,
    ssh_host: str,
    known_hosts_file: Path,
    scanner: Callable[[], Sequence[LocalUsbPluto]] = scan_local_usb_plutos,
    route_checker: Callable[[str, str], UsbSshRouteObservation] = (
        require_unambiguous_usb_ssh_route
    ),
    interface_validator: Callable[[str, str], None] = validate_bound_interface,
) -> LocalRebootPlan:
    """Build a read-only plan for exactly one locally attached USB radio."""

    _validate_serial(serial)
    path = usb_sysfs_path.expanduser().absolute()
    if path.parent != Path("/sys/bus/usb/devices"):
        raise LocalRebootError("USB path must be one direct /sys/bus/usb/devices child")
    matches = [item for item in scanner() if item.serial == serial and item.usb_path == str(path)]
    if len(matches) != 1:
        raise LocalRebootError("serial and USB path must identify exactly one attached radio")
    local = matches[0]
    if len(local.host_network_interfaces) != 1:
        raise LocalRebootError("selected radio must expose exactly one USB network interface")
    interface = local.host_network_interfaces[0].name
    try:
        host_address = ipaddress.ip_address(ssh_host)
    except ValueError as error:
        raise LocalRebootError("SSH host must be a literal private IPv4 address") from error
    if host_address.version != 4 or not host_address.is_private:
        raise LocalRebootError("SSH host must be a literal private IPv4 address")
    route_mode: Literal["usb_gadget", "lan"] = "usb_gadget" if ssh_host == "192.168.2.1" else "lan"
    try:
        interface_validator(interface, str(path))
        route = route_checker(interface, ssh_host) if route_mode == "usb_gadget" else None
    except (OSError, ValueError, RuntimeError) as error:
        raise LocalRebootError(str(error)) from error
    known_hosts_sha256 = _private_file_sha256(known_hosts_file, "SSH known-hosts")
    return LocalRebootPlan(
        schema_version=2,
        plan_id=uuid.uuid4().hex,
        created_at=_now(),
        serial=serial,
        usb_sysfs_path=str(path),
        usb_interface=interface,
        ssh_host=ssh_host,
        ssh_route_mode=route_mode,
        known_hosts_sha256=known_hosts_sha256,
        route_observation=route,
        confirmation_phrase=f"REBOOT {serial}",
    )


def execute_local_reboot(
    plan: LocalRebootPlan,
    *,
    confirmation: str,
    transport: LocalRebootTransport,
    known_hosts_file: Path,
    receipt_directory: Path,
    scanner: Callable[[], Sequence[LocalUsbPluto]] = scan_local_usb_plutos,
    route_checker: Callable[[str, str], UsbSshRouteObservation] = (
        require_unambiguous_usb_ssh_route
    ),
    interface_validator: Callable[[str, str], None] = validate_bound_interface,
    post_reboot_usb_verifier: Callable[
        [LocalRebootPlan, LocalRebootAttestation], LocalRebootAttestation
    ] = lambda plan, before: attest_and_mute_returned_usb(plan, before),
    timeout_s: float = 60,
    poll_interval_s: float = 0.25,
) -> LocalRebootReceipt:
    """Execute one plan once; any post-dispatch uncertainty is durably receipted."""

    if confirmation != plan.confirmation_phrase:
        raise LocalRebootError(f"confirmation must be exactly {plan.confirmation_phrase!r}")
    if timeout_s <= 0 or poll_interval_s <= 0:
        raise ValueError("reboot timeouts must be positive")
    started_at = _now()
    receipt_id = uuid.uuid4().hex
    destination = receipt_directory / f"{receipt_id}.json"
    completed: list[str] = []
    before: LocalRebootAttestation | None = None
    after: LocalRebootAttestation | None = None
    mutation_dispatched = False
    outcome: Literal["success", "failed_before_mutation", "unknown"] = "failed_before_mutation"
    error_text: str | None = None
    post_reboot_verified_over_usb = False

    def checkpoint(
        checkpoint_outcome: Literal[
            "started", "success", "failed_before_mutation", "unknown"
        ] = "started",
        *,
        finished_at: str | None = None,
        error: str | None = None,
    ) -> LocalRebootReceipt:
        receipt = LocalRebootReceipt(
            schema_version=1,
            receipt_id=receipt_id,
            plan=plan,
            started_at=started_at,
            finished_at=finished_at,
            outcome=checkpoint_outcome,
            completed_phases=tuple(completed),
            before=before,
            after=after,
            error=error,
            receipt_path=str(destination),
        )
        _write_receipt(destination, receipt)
        return receipt

    # Establish the durable attempt record before the first SSH operation. In
    # particular, reboot_dispatch_attempted is fsynced before reset is sent.
    checkpoint()
    try:
        fresh = prepare_local_reboot(
            plan.serial,
            Path(plan.usb_sysfs_path),
            ssh_host=plan.ssh_host,
            known_hosts_file=known_hosts_file,
            scanner=scanner,
            route_checker=route_checker,
            interface_validator=interface_validator,
        )
        if (
            fresh.serial,
            fresh.usb_sysfs_path,
            fresh.usb_interface,
            fresh.ssh_host,
            fresh.ssh_route_mode,
            fresh.known_hosts_sha256,
        ) != (
            plan.serial,
            plan.usb_sysfs_path,
            plan.usb_interface,
            plan.ssh_host,
            plan.ssh_route_mode,
            plan.known_hosts_sha256,
        ):
            raise LocalRebootError("local reboot plan identity or SSH trust changed")
        completed.append("local_identity_reattested")
        checkpoint()
        before = transport.attest(plan.serial)
        completed.append("remote_identity_reattested")
        checkpoint()
        transport.ensure_tx_safe(plan.serial)
        completed.append("tx_safe_before_reboot")
        checkpoint()
        mutation_dispatched = True
        completed.append("reboot_dispatch_attempted")
        checkpoint()
        transport.reboot(plan.serial)
        completed.append("reboot_dispatched")
        checkpoint()
        _wait_for_same_topology(
            plan,
            scanner=scanner,
            timeout_s=timeout_s,
            poll_interval_s=poll_interval_s,
        )
        completed.append("same_topology_reenumerated")
        checkpoint()
        deadline = time.monotonic() + timeout_s
        last_error: BaseException | None = None
        while time.monotonic() < deadline:
            try:
                if plan.ssh_route_mode == "usb_gadget":
                    route_checker(plan.usb_interface, plan.ssh_host)
                candidate = transport.attest(plan.serial)
            except SetupSshHostKeyChangedError:
                # The changed key is never trusted. Reconcile through the already
                # selected physical USB path/interface and exact USB-IIO serial.
                candidate = post_reboot_usb_verifier(plan, before)
                post_reboot_verified_over_usb = True
            except BaseException as error:
                last_error = error
                time.sleep(poll_interval_s)
                continue
            if not post_reboot_verified_over_usb and candidate.boot_id == before.boot_id:
                raise LocalRebootError("radio returned without a new boot identity")
            if candidate.serial != before.serial:
                raise LocalRebootError("radio serial changed across reboot")
            if candidate.firmware != before.firmware:
                raise LocalRebootError("radio firmware changed across reboot")
            if candidate.capabilities != before.capabilities:
                raise LocalRebootError("radio capabilities changed across reboot")
            after = candidate
            break
        if after is None:
            raise LocalRebootError(f"radio did not pass post-reboot attestation: {last_error}")
        completed.append(
            "post_reboot_usb_iiod_attested"
            if post_reboot_verified_over_usb
            else "post_reboot_identity_attested"
        )
        checkpoint()
        if not post_reboot_verified_over_usb:
            transport.ensure_tx_safe(plan.serial)
        completed.append("tx_safe_after_reboot")
        outcome = "success"
    except BaseException as error:
        error_text = f"{type(error).__name__}: {error}"
        outcome = "unknown" if mutation_dispatched else "failed_before_mutation"

    receipt = checkpoint(outcome, finished_at=_now(), error=error_text)
    if outcome != "success":
        raise LocalRebootExecutionError(error_text or "local reboot failed", receipt)
    return receipt


def attest_and_mute_returned_usb(
    plan: LocalRebootPlan,
    before: LocalRebootAttestation,
) -> LocalRebootAttestation:
    """Independently reconcile a rotated SSH key via exact physical USB-IIO."""

    from pluto_plus.bootstrap_firmware import inspect_bound_iiod, mute_returned_radio

    facts = inspect_bound_iiod(plan.usb_interface)
    serial = str(facts.get("hw_serial") or "").strip()
    if serial != plan.serial:
        raise LocalRebootError("returned USB-IIO serial does not match the selected radio")
    firmware = str(facts.get("fw_version") or "").strip()
    board_model = str(facts.get("hw_model") or "").strip()
    phy_model = str(facts.get("ad9361-phy,model") or "").strip()
    raw_names = facts.get("device_names", ())
    names = (
        {str(value) for value in raw_names}
        if isinstance(raw_names, (tuple, list, set, frozenset))
        else set()
    )
    raw_channels = facts.get("cf-ad9361-lpc,scan_channels", ())
    channels = (
        tuple(sorted(str(value) for value in raw_channels))
        if isinstance(raw_channels, (tuple, list, set, frozenset))
        else ()
    )
    if not firmware or not board_model or not phy_model or "cf-ad9361-lpc" not in names:
        raise LocalRebootError("returned USB-IIO capability attestation is incomplete")
    candidate = LocalRebootAttestation(
        serial=serial,
        firmware=firmware,
        # Exact USB disappearance/reappearance is the reset proof in this path;
        # no SSH boot_id is invented.
        boot_id=None,
        capabilities=LocalRebootCapabilities(
            board_model=board_model,
            phy_model=phy_model,
            rx_scan_channels=channels,
            tandem_agc="tandem-agc" in names,
        ),
    )
    if candidate.firmware != before.firmware or candidate.capabilities != before.capabilities:
        raise LocalRebootError("returned USB-IIO firmware or capabilities changed across reboot")
    mute_returned_radio(plan.serial)
    return candidate


def _wait_for_same_topology(
    plan: LocalRebootPlan,
    *,
    scanner: Callable[[], Sequence[LocalUsbPluto]],
    timeout_s: float,
    poll_interval_s: float,
) -> None:
    deadline = time.monotonic() + timeout_s
    disappeared = False
    while time.monotonic() < deadline:
        devices = scanner()
        at_path = [item for item in devices if item.usb_path == plan.usb_sysfs_path]
        if not at_path:
            disappeared = True
        elif disappeared:
            if len(at_path) != 1 or at_path[0].serial != plan.serial:
                raise LocalRebootError("a different radio appeared at the selected USB topology")
            names = tuple(item.name for item in at_path[0].host_network_interfaces)
            if names != (plan.usb_interface,):
                raise LocalRebootError("USB network interface changed across reboot")
            return
        time.sleep(poll_interval_s)
    raise LocalRebootError("selected USB topology did not disappear and reappear")


def _private_file_sha256(path: Path, label: str) -> str:
    try:
        stat_result = path.lstat()
        data = path.read_bytes()
    except OSError as error:
        raise LocalRebootError(f"{label} file is not readable") from error
    if path.is_symlink() or not path.is_file() or stat_result.st_mode & 0o077:
        raise LocalRebootError(f"{label} must be a private regular non-symlink file")
    if not data or len(data) > 1024 * 1024:
        raise LocalRebootError(f"{label} file is empty or too large")
    return hashlib.sha256(data).hexdigest()


def _write_receipt(path: Path, receipt: LocalRebootReceipt) -> None:
    directory = path.parent
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)
    payload = (json.dumps(asdict(receipt), sort_keys=True, separators=(",", ":")) + "\n").encode()
    descriptor, temporary_name = tempfile.mkstemp(prefix=".reboot-", dir=directory)
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


def _parse_report(output: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in output.splitlines():
        if not line.startswith("PPU\t"):
            continue
        parts = line.split("\t", 2)
        if len(parts) != 3 or not parts[1] or parts[1] in fields:
            raise LocalRebootError("malformed or duplicate SSH report field")
        fields[parts[1]] = parts[2]
    return fields


def _required(fields: dict[str, str], key: str) -> str:
    value = fields.get(key, "")
    if not value:
        raise LocalRebootError(f"SSH report omitted {key}")
    return value


def _validate_serial(serial: str) -> None:
    if not _SERIAL_RE.fullmatch(serial):
        raise LocalRebootError("invalid radio serial")


def _now() -> str:
    return datetime.now(UTC).isoformat()


_ATTEST_SCRIPT = rb"""set -eu
serial_expected="$1"
emit() { printf 'PPU\t%s\t%s\n' "$1" "$2"; }
serial=$(cat /sys/kernel/config/usb_gadget/composite_gadget/strings/0x409/serialnumber)
test "$serial" = "$serial_expected"
emit serial "$serial"
emit board_model "$(tr '\000' '\n' </proc/device-tree/model | head -n1)"
emit firmware "$(awk '$1 == "device-fw" {print $2; exit}' /opt/VERSIONS)"
emit boot_id "$(cat /proc/sys/kernel/random/boot_id)"
compatible_path=/proc/device-tree/amba/spi@e0006000/ad9361-phy@0/compatible
compatible=$(tr '\000' '\n' <"$compatible_path" 2>/dev/null | head -n1 || true)
emit phy_model "${compatible#adi,}"
rx=''; tandem=0
for d in /sys/bus/iio/devices/iio:device*; do
  name=$(cat "$d/name" 2>/dev/null || true)
  test "$name" != tandem-agc || tandem=1
  test "$name" = cf-ad9361-lpc || continue
  for f in "$d"/scan_elements/in_voltage[0-3]_en; do
    test -e "$f" || continue
    channel=$(basename "$f" | sed -n 's/^in_\(voltage[0-3]\)_en$/\1/p')
    case ",$rx," in *,$channel,*) ;; *) rx="${rx}${rx:+,}$channel";; esac
  done
done
emit rx_scan_channels "$rx"
emit tandem_agc "$tandem"
"""


_TX_SAFE_SCRIPT = rb"""set -eu
serial_expected="$1"
serial=$(cat /sys/kernel/config/usb_gadget/composite_gadget/strings/0x409/serialnumber)
test "$serial" = "$serial_expected"
phy=''; dds=''
for d in /sys/bus/iio/devices/iio:device*; do
  case "$(cat "$d/name" 2>/dev/null || true)" in
    ad9361-phy) phy="$d" ;;
    cf-ad9361-dds-core-lpc) dds="$d" ;;
  esac
done
test -n "$phy" && test -n "$dds"
printf '%s\n' -80 >"$phy/out_voltage0_hardwaregain"
printf '%s\n' -80 >"$phy/out_voltage1_hardwaregain"
printf '%s\n' 0 >"$dds/buffer/enable"
for f in "$dds"/scan_elements/out_voltage[0-3]_en; do test ! -e "$f" || printf '%s\n' 0 >"$f"; done
for f in "$dds"/out_altvoltage*_scale "$dds"/out_altvoltage*_raw; do printf '%s\n' 0 >"$f"; done
test "$(awk '{print $1}' "$phy/out_voltage0_hardwaregain")" = -80.000000
test "$(awk '{print $1}' "$phy/out_voltage1_hardwaregain")" = -80.000000
test "$(cat "$dds/buffer/enable")" = 0
for f in "$dds"/scan_elements/out_voltage[0-3]_en "$dds"/out_altvoltage*_raw; do
  test ! -e "$f" || test "$(cat "$f")" = 0
done
for f in "$dds"/out_altvoltage*_scale; do
  test ! -e "$f" || awk -v value="$(cat "$f")" 'BEGIN { exit !(value == 0) }'
done
printf 'PPU\ttx_safe\t1\n'
"""
