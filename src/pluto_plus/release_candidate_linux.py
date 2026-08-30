"""Linux backend for the native release-candidate RAM lifecycle."""

from __future__ import annotations

import fcntl
import gc
import hashlib
import importlib
import ipaddress
import json
import math
import os
import re
import stat
import subprocess
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import ExitStack, contextmanager, nullcontext
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from pydantic import ValidationError

from pluto_plus.inventory import LocalUsbPluto, scan_local_usb_plutos
from pluto_plus.radio_lock import RadioLockError, acquire_radio_lock, shared_radio_lock_root
from pluto_plus.release_candidate import (
    CanonicalHardwareSetup,
    CleanupReceipt,
    HostRouteReceipt,
    QspiObservation,
    ReleaseCandidatePlan,
    RuntimeObservation,
    SafeState,
    UsbInventoryTarget,
)
from pluto_plus.release_candidate_lifecycle import (
    DFU_ALTERNATE,
    DFU_SELECTOR,
    REMOTE_RAM_COMMAND,
    FailureReconciliation,
    PasswordFileIdentity,
    ReleaseCandidateLifecycleError,
    ssh_fixed_argv,
    validate_password_file,
)

USB_VENDOR = "0456"
RUNTIME_PRODUCT = "b673"
DFU_PRODUCT = "b674"
F_ADD_SEALS = getattr(fcntl, "F_ADD_SEALS", 1033)
REMOTE_PERSISTENT_RESET_COMMAND = "/bin/sync; /usr/sbin/device_reboot reset"
F_GET_SEALS = getattr(fcntl, "F_GET_SEALS", 1034)
F_SEAL_SEAL = getattr(fcntl, "F_SEAL_SEAL", 0x0001)
F_SEAL_SHRINK = getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
F_SEAL_GROW = getattr(fcntl, "F_SEAL_GROW", 0x0004)
F_SEAL_WRITE = getattr(fcntl, "F_SEAL_WRITE", 0x0008)
REQUIRED_DFU_SEALS = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE

_TOPOLOGY = re.compile(r"^[0-9]+-[0-9]+(?:[.][0-9]+)*$")
_INTERFACE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
_USB_URI = re.compile(r"^usb:(\d+)[.](\d+)[.](\d+)$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_BOOT_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_GITHUB_ORIGIN = re.compile(
    r"^(?:git@github[.]com:|ssh://git@github[.]com/|https://github[.]com/)"
    r"(?P<repository>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:[.]git)?$"
)

REMOTE_IDENTITY_SCRIPT = r"""set -eu
boot_id=$(cat /proc/sys/kernel/random/boot_id)
firmware_version=$(awk '$1 == "device-fw" {print $2; exit}' /opt/VERSIONS)
qspi_partition=/dev/mtdblock3
qspi_mtd_name=$(cat /sys/class/mtd/mtd3/name)
qspi_bytes=$(cat /sys/class/mtd/mtd3/size)
qspi_sha256=$(sha256sum "$qspi_partition" | awk '{print $1}')
uboot_attr_name_absent=0
uboot_attr_val_absent=0
if ! /usr/sbin/fw_printenv -n attr_name >/dev/null 2>&1; then uboot_attr_name_absent=1; fi
if ! /usr/sbin/fw_printenv -n attr_val >/dev/null 2>&1; then uboot_attr_val_absent=1; fi
uboot_compatible=$(/usr/sbin/fw_printenv -n compatible)
uboot_mode=$(/usr/sbin/fw_printenv -n mode)
[ -n "$boot_id" ]
[ -n "$firmware_version" ]
[ "$qspi_mtd_name" = qspi-linux ]
case "$qspi_bytes" in ''|*[!0-9]*) exit 1;; esac
[ "$qspi_bytes" -gt 0 ]
format='boot_id=%s\nfirmware_version=%s\nqspi_partition=%s\nqspi_mtd_name=%s\n'
format="${format}qspi_bytes=%s\nqspi_sha256=%s\n"
format="${format}uboot_attr_name_absent=%s\nuboot_attr_val_absent=%s\n"
format="${format}uboot_compatible=%s\nuboot_mode=%s\n"
printf "$format" \
  "$boot_id" "$firmware_version" "$qspi_partition" "$qspi_mtd_name" \
  "$qspi_bytes" "$qspi_sha256" \
  "$uboot_attr_name_absent" "$uboot_attr_val_absent" \
  "$uboot_compatible" "$uboot_mode"
"""


class LinuxCommandRunner(Protocol):
    def run(
        self,
        argv: Sequence[str],
        *,
        timeout_s: float,
        pass_fds: Sequence[int] = (),
        allowed_returncodes: Sequence[int] = (0,),
    ) -> str: ...


@dataclass(frozen=True, slots=True)
class ToolSourceAttestation:
    """Exact clean GitHub repository and commit used by the live command."""

    repository: str
    commit: str


class SubprocessLinuxCommandRunner:
    """Bounded subprocess runner which never invokes a shell."""

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout_s: float,
        pass_fds: Sequence[int] = (),
        allowed_returncodes: Sequence[int] = (0,),
    ) -> str:
        try:
            completed = subprocess.run(
                tuple(argv),
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout_s,
                pass_fds=tuple(pass_fds),
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ReleaseCandidateLifecycleError(
                f"host command {argv[0]!r} could not run: {error}"
            ) from error
        if completed.returncode not in allowed_returncodes:
            output = (completed.stdout + completed.stderr).strip()[-2000:]
            raise ReleaseCandidateLifecycleError(
                f"host command {argv[0]!r} exited {completed.returncode}: {output}"
            )
        return completed.stdout


RuntimeAttestor = Callable[
    [UsbInventoryTarget, str, PasswordFileIdentity, HostRouteReceipt], RuntimeObservation
]


@dataclass(frozen=True, slots=True)
class _DfuDevice:
    topology: str
    sysfs_path: Path
    vendor_id: str
    product_id: str
    serial: str
    bus_number: int
    device_number: int


class LinuxReleaseCandidateBackend:
    """Exact-route, exact-topology Linux implementation of the RAM lifecycle."""

    def __init__(
        self,
        *,
        state_root: Path,
        timeout_s: float = 45.0,
        sysfs_root: Path = Path("/sys/bus/usb/devices"),
        scanner: Callable[[], Sequence[LocalUsbPluto]] = scan_local_usb_plutos,
        command_runner: LinuxCommandRunner | None = None,
        runtime_attestor: RuntimeAttestor | None = None,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        radio_lock_root: Path | None = None,
        _prelocked_radio_serial: str | None = None,
    ) -> None:
        if timeout_s <= 0:
            raise ValueError("Linux candidate lifecycle timeout must be positive")
        if not state_root.is_absolute() or ".." in state_root.parts:
            raise ValueError("candidate lifecycle state root must be absolute and normalized")
        self.state_root = state_root
        self.timeout_s = timeout_s
        self.sysfs_root = sysfs_root
        self.scanner = scanner
        self.runner = command_runner or SubprocessLinuxCommandRunner()
        self.runtime_attestor = runtime_attestor or self._attest_runtime_linux
        self.sleep = sleep
        self.monotonic = monotonic
        self.radio_lock_root = radio_lock_root or shared_radio_lock_root()
        self._prelocked_radio_serial = _prelocked_radio_serial
        self._active_target: UsbInventoryTarget | None = None
        self._active_route: HostRouteReceipt | None = None
        self._sealed_descriptor: int | None = None
        self._sealed_sha256: str | None = None
        self._sealed_bytes: int | None = None

    @contextmanager
    def transaction_locks(self, target: UsbInventoryTarget, ssh_host: str) -> Iterator[None]:
        """Exclude the daemon, this radio, and all users of the shared endpoint."""

        try:
            if self._prelocked_radio_serial not in {None, target.serial}:
                raise ReleaseCandidateLifecycleError(
                    "prelocked candidate backend serial differs from its target"
                )
            radio_lock = (
                nullcontext()
                if self._prelocked_radio_serial == target.serial
                else acquire_radio_lock(target.serial, root=self.radio_lock_root)
            )
            with radio_lock:
                self._prepare_state_root()
                locks = self.state_root / "locks"
                locks.mkdir(mode=0o700, exist_ok=True)
                _require_private_directory(locks, label="candidate lock directory")
                route_token = hashlib.sha256(ssh_host.encode()).hexdigest()[:24]
                radio_token = hashlib.sha256(target.serial.encode()).hexdigest()[:24]
                with ExitStack() as stack:
                    daemon = stack.enter_context(_exclusive_lock(self.state_root / ".plutod.lock"))
                    route = stack.enter_context(
                        _exclusive_lock(locks / f"release-route-{route_token}.lock")
                    )
                    radio = stack.enter_context(
                        _exclusive_lock(locks / f"release-radio-{radio_token}.lock")
                    )
                    for stream, label in (
                        (daemon, "daemon-exclusion"),
                        (route, f"route={ssh_host}"),
                        (radio, f"serial={target.serial}"),
                    ):
                        stream.seek(0)
                        stream.truncate()
                        stream.write(f"pid={os.getpid()} operation=candidate-ram {label}\n")
                        stream.flush()
                    self._active_target = target
                    try:
                        yield
                    finally:
                        self._active_target = None
        except RadioLockError as error:
            raise ReleaseCandidateLifecycleError(str(error)) from error

    @contextmanager
    def sealed_dfu(self, payload: bytes) -> Iterator[Path]:
        """Copy the verified candidate into an immutable anonymous descriptor."""

        if self._sealed_descriptor is not None:
            raise ReleaseCandidateLifecycleError("a sealed DFU descriptor is already active")
        if not hasattr(os, "memfd_create"):
            raise ReleaseCandidateLifecycleError("this Linux host lacks memfd_create")
        descriptor = os.memfd_create(
            "pluto-plus-release-candidate",
            getattr(os, "MFD_CLOEXEC", 0x0001) | getattr(os, "MFD_ALLOW_SEALING", 0x0002),
        )
        try:
            view = memoryview(payload)
            offset = 0
            while offset < len(view):
                written = os.write(descriptor, view[offset:])
                if written <= 0:
                    raise ReleaseCandidateLifecycleError("could not populate sealed DFU")
                offset += written
            os.fsync(descriptor)
            fcntl.fcntl(descriptor, F_ADD_SEALS, REQUIRED_DFU_SEALS)
            if fcntl.fcntl(descriptor, F_GET_SEALS) != REQUIRED_DFU_SEALS:
                raise ReleaseCandidateLifecycleError("sealed DFU seal inventory is not exact")
            self._sealed_descriptor = descriptor
            self._sealed_bytes = len(payload)
            self._sealed_sha256 = hashlib.sha256(payload).hexdigest()
            yield Path(f"/proc/self/fd/{descriptor}")
        finally:
            self._sealed_descriptor = None
            self._sealed_bytes = None
            self._sealed_sha256 = None
            os.close(descriptor)

    def revalidate_target(self, target: UsbInventoryTarget) -> UsbInventoryTarget:
        matches = tuple(
            item
            for item in self._runtime_targets()
            if item.serial == target.serial and item.topology == target.topology
        )
        if matches != (target,):
            raise ReleaseCandidateLifecycleError(
                "live runtime target differs from the saved serial/topology/address/interface"
            )
        return matches[0]

    def acquire_host_route(self, target: UsbInventoryTarget, ssh_host: str) -> HostRouteReceipt:
        if self._active_route is not None or self._active_target != target:
            raise ReleaseCandidateLifecycleError("candidate route lease state is not empty")
        try:
            address = ipaddress.ip_address(ssh_host)
        except ValueError as error:
            raise ReleaseCandidateLifecycleError("SSH endpoint is not an IP address") from error
        if address.version != 4:
            raise ReleaseCandidateLifecycleError("SSH endpoint must be IPv4")
        destination = f"{address}/32"
        if self._exact_routes(destination):
            raise ReleaseCandidateLifecycleError(
                f"refusing to overwrite pre-existing exact route {destination}"
            )
        source = self._interface_source(target.network_interface)
        if source != target.source_ipv4:
            raise ReleaseCandidateLifecycleError("live USB-interface source changed from plan")
        route = HostRouteReceipt(
            destination=destination,
            interface=target.network_interface,
            source=source,
            release_verified=False,
        )
        self._active_route = route
        try:
            self._add_route(route)
            self.ensure_host_route(route, target)
        except BaseException as error:
            try:
                self.release_host_route(route)
            except BaseException as cleanup_error:
                raise ReleaseCandidateLifecycleError(
                    f"route acquisition failed ({error}); cleanup also failed ({cleanup_error})"
                ) from error
            raise
        return route

    def ensure_host_route(self, route: HostRouteReceipt, target: UsbInventoryTarget) -> None:
        if self._active_route != route or route.interface != target.network_interface:
            raise ReleaseCandidateLifecycleError("host-route lease target is not exact")
        deadline = self.monotonic() + self.timeout_s
        last_error: BaseException | None = None
        while self.monotonic() < deadline:
            try:
                if self._interface_source(route.interface) != route.source:
                    raise ReleaseCandidateLifecycleError("host-route interface source changed")
                records = self._exact_routes(route.destination)
                if not records:
                    self._add_route(route)
                    records = self._exact_routes(route.destination)
                if len(records) != 1 or not _route_record_matches(records[0], route):
                    raise ReleaseCandidateLifecycleError("host-route tuple is not exact")
                lookup = self._ip_json(
                    ("route", "get", route.destination.removesuffix("/32")),
                    label="selected route lookup",
                )
                if (
                    len(lookup) != 1
                    or not isinstance(lookup[0], Mapping)
                    or lookup[0].get("dev") != route.interface
                    or lookup[0].get("prefsrc") != route.source
                ):
                    raise ReleaseCandidateLifecycleError(
                        "selected route does not use the exact interface/source"
                    )
                return
            except ReleaseCandidateLifecycleError as error:
                last_error = error
                records = self._exact_routes(route.destination)
                if records and (len(records) != 1 or not _route_record_matches(records[0], route)):
                    raise
                self.sleep(0.25)
        raise ReleaseCandidateLifecycleError(
            f"timed out verifying candidate host route: {last_error}"
        )

    def release_host_route(self, route: HostRouteReceipt) -> None:
        if self._active_route != route:
            raise ReleaseCandidateLifecycleError("host-route release does not match active lease")
        records = self._exact_routes(route.destination)
        if records:
            if len(records) != 1 or not _route_record_matches(records[0], route):
                raise ReleaseCandidateLifecycleError(
                    "refusing to delete a host route not owned by this lease"
                )
            self.runner.run(
                (
                    "sudo",
                    "-n",
                    "ip",
                    "route",
                    "del",
                    route.destination,
                    "dev",
                    route.interface,
                    "src",
                    route.source,
                    "scope",
                    "link",
                    "proto",
                    "static",
                ),
                timeout_s=self.timeout_s,
            )
        if self._exact_routes(route.destination):
            raise ReleaseCandidateLifecycleError("host-route deletion was not verified")
        self._active_route = None

    def attest_runtime(
        self,
        target: UsbInventoryTarget,
        *,
        expected_firmware: str,
        password: PasswordFileIdentity,
        route: HostRouteReceipt,
    ) -> RuntimeObservation:
        self.ensure_host_route(route, target)
        validate_password_file(password.path, expected=password)
        return self.runtime_attestor(target, expected_firmware, password, route)

    def request_ram_mode(
        self,
        argv: Sequence[str],
        *,
        password: PasswordFileIdentity,
        route: HostRouteReceipt,
    ) -> None:
        target = self._require_active_target()
        self.ensure_host_route(route, target)
        validate_password_file(password.path, expected=password)
        expected = ssh_fixed_argv(
            target,
            ssh_host=route.destination.removesuffix("/32"),
            password_path=password.path,
            remote_command=REMOTE_RAM_COMMAND,
        )
        if tuple(argv) != expected:
            raise ReleaseCandidateLifecycleError("RAM-mode SSH argv differs from fixed policy")
        self.runner.run(
            expected,
            timeout_s=self.timeout_s,
            allowed_returncodes=(0, 255),
        )

    def wait_for_dfu(self, target: UsbInventoryTarget, *, timeout_s: float) -> None:
        deadline = self.monotonic() + timeout_s
        last_error: BaseException | None = None
        while self.monotonic() < deadline:
            try:
                device = self._dfu_device(target.topology)
                if device.serial and device.serial != target.serial:
                    raise ReleaseCandidateLifecycleError(
                        "DFU device exposed a different serial at the selected topology"
                    )
                return
            except ReleaseCandidateLifecycleError as error:
                last_error = error
                self.sleep(0.25)
        raise ReleaseCandidateLifecycleError(
            f"timed out waiting for exact-topology Pluto DFU: {last_error}"
        )

    def download_dfu(self, argv: Sequence[str], *, sealed_path: Path) -> None:
        target = self._require_active_target()
        descriptor = self._require_sealed_descriptor(sealed_path)
        expected = (
            "dfu-util",
            "-d",
            DFU_SELECTOR,
            "-p",
            target.topology,
            "-a",
            DFU_ALTERNATE,
            "-D",
            str(sealed_path),
        )
        if tuple(argv) != expected:
            raise ReleaseCandidateLifecycleError("DFU download argv differs from fixed policy")
        self._verify_sealed_descriptor(descriptor)
        self.runner.run(
            expected,
            timeout_s=max(self.timeout_s, 120),
            pass_fds=(descriptor,),
        )
        self._verify_sealed_descriptor(descriptor)

    def detach_dfu(self, argv: Sequence[str]) -> None:
        target = self._require_active_target()
        expected = (
            "dfu-util",
            "-d",
            DFU_SELECTOR,
            "-p",
            target.topology,
            "-a",
            DFU_ALTERNATE,
            "-e",
        )
        if tuple(argv) != expected:
            raise ReleaseCandidateLifecycleError("DFU detach argv differs from fixed policy")
        self.runner.run(expected, timeout_s=self.timeout_s)

    def wait_for_runtime(
        self, target: UsbInventoryTarget, *, timeout_s: float
    ) -> UsbInventoryTarget:
        deadline = self.monotonic() + timeout_s
        last_error: BaseException | None = None
        while self.monotonic() < deadline:
            try:
                matches = tuple(
                    item
                    for item in self._runtime_targets()
                    if item.serial == target.serial and item.topology == target.topology
                )
                if len(matches) != 1:
                    raise ReleaseCandidateLifecycleError(
                        "same serial/topology runtime has not returned uniquely"
                    )
                returned = matches[0]
                if (
                    returned.network_interface != target.network_interface
                    or returned.source_ipv4 != target.source_ipv4
                ):
                    raise ReleaseCandidateLifecycleError("returned USB network identity changed")
                return returned
            except ReleaseCandidateLifecycleError as error:
                last_error = error
                self.sleep(0.25)
        raise ReleaseCandidateLifecycleError(
            f"timed out waiting for exact runtime return: {last_error}"
        )

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
        errors: list[str] = []
        try:
            device = self._dfu_device(target.topology)
        except ReleaseCandidateLifecycleError:
            device = None
        if device is not None:
            try:
                self.detach_dfu(
                    (
                        "dfu-util",
                        "-d",
                        DFU_SELECTOR,
                        "-p",
                        target.topology,
                        "-a",
                        DFU_ALTERNATE,
                        "-e",
                    )
                )
            except BaseException as error:
                errors.append(f"DFU detach recovery: {error}")
        try:
            returned = self.wait_for_runtime(target, timeout_s=timeout_s)
            self.ensure_host_route(route, returned)
        except BaseException as error:
            errors.append(f"runtime recovery: {error}")
            return FailureReconciliation(
                runtime=None, cleanup=CleanupReceipt(verified=False, errors=tuple(errors))
            )
        observations: list[str] = []
        for expected in (
            candidate.expected_runtime.firmware_version,
            pre_runtime.firmware_version,
        ):
            try:
                observed = self.attest_runtime(
                    returned,
                    expected_firmware=expected,
                    password=password,
                    route=route,
                )
                return FailureReconciliation(
                    runtime=observed, cleanup=CleanupReceipt(verified=True)
                )
            except BaseException as error:
                observations.append(f"{expected}: {error}")
        errors.append("safe runtime attestation: " + "; ".join(observations))
        return FailureReconciliation(
            runtime=None, cleanup=CleanupReceipt(verified=False, errors=tuple(errors))
        )

    def recover_unknown_runtime(
        self,
        target: UsbInventoryTarget,
        *,
        pre_runtime: RuntimeObservation,
        expected_firmware: str,
        password: PasswordFileIdentity,
        ssh_host: str,
        timeout_s: float,
    ) -> tuple[RuntimeObservation, HostRouteReceipt, bool]:
        """Return or re-attest one exact unknown transition without another download."""

        if self._active_target != target:
            raise ReleaseCandidateLifecycleError("DFU recovery target is not lock-bound")
        matches = tuple(
            item
            for item in self._runtime_targets()
            if item.serial == target.serial and item.topology == target.topology
        )
        if len(matches) > 1:
            raise ReleaseCandidateLifecycleError("DFU recovery found multiple matching runtimes")
        detached = not matches
        if detached:
            device = self._dfu_device(target.topology)
            if device.serial and device.serial != target.serial:
                raise ReleaseCandidateLifecycleError(
                    "DFU recovery device exposed a different serial at the selected topology"
                )
            self.detach_dfu(
                (
                    "dfu-util",
                    "-d",
                    DFU_SELECTOR,
                    "-p",
                    target.topology,
                    "-a",
                    DFU_ALTERNATE,
                    "-e",
                )
            )
            returned = self.wait_for_runtime(target, timeout_s=timeout_s)
        else:
            returned = matches[0]
        if (
            returned.serial != target.serial
            or returned.topology != target.topology
            or returned.network_interface != target.network_interface
            or returned.source_ipv4 != target.source_ipv4
        ):
            raise ReleaseCandidateLifecycleError(
                "DFU recovery returned a different physical target"
            )
        self._active_target = returned
        route = self.acquire_host_route(returned, ssh_host)
        try:
            observed = self.attest_runtime(
                returned,
                expected_firmware=expected_firmware,
                password=password,
                route=route,
            )
            if observed.boot_id == pre_runtime.boot_id:
                raise ReleaseCandidateLifecycleError(
                    "DFU recovery did not produce a new runtime boot ID"
                )
            if observed.qspi != pre_runtime.qspi:
                raise ReleaseCandidateLifecycleError("qspi-linux bytes changed across DFU recovery")
        except BaseException:
            self.release_host_route(route)
            raise
        self.release_host_route(route)
        return observed, route.model_copy(update={"release_verified": True}), detached

    def restore_persistent_runtime(
        self,
        target: UsbInventoryTarget,
        *,
        candidate_runtime: RuntimeObservation,
        expected_firmware: str,
        password: PasswordFileIdentity,
        ssh_host: str,
        timeout_s: float,
    ) -> RuntimeObservation:
        """Reset a RAM candidate into unchanged QSPI and attest the exact return."""

        with self.transaction_locks(target, ssh_host):
            fresh = self.revalidate_target(target)
            route = self.acquire_host_route(fresh, ssh_host)
            try:
                before = self.attest_runtime(
                    fresh,
                    expected_firmware=candidate_runtime.firmware_version,
                    password=password,
                    route=route,
                )
                if (
                    before.boot_id != candidate_runtime.boot_id
                    or before.qspi != candidate_runtime.qspi
                ):
                    raise ReleaseCandidateLifecycleError(
                        "candidate runtime changed before persistent restore"
                    )
                command = ssh_fixed_argv(
                    fresh,
                    ssh_host=ssh_host,
                    password_path=password.path,
                    remote_command=REMOTE_PERSISTENT_RESET_COMMAND,
                )
                self.runner.run(
                    command,
                    timeout_s=self.timeout_s,
                    allowed_returncodes=(0, 255),
                )
                returned = self.wait_for_runtime(fresh, timeout_s=timeout_s)
                self.ensure_host_route(route, returned)
                restored = self.attest_runtime(
                    returned,
                    expected_firmware=expected_firmware,
                    password=password,
                    route=route,
                )
                if (
                    restored.serial != candidate_runtime.serial
                    or restored.topology != candidate_runtime.topology
                    or restored.boot_id == candidate_runtime.boot_id
                    or restored.qspi != candidate_runtime.qspi
                ):
                    raise ReleaseCandidateLifecycleError(
                        "persistent restore identity, boot epoch, or QSPI changed"
                    )
            finally:
                self.release_host_route(route)
        return restored

    def _runtime_targets(self) -> tuple[UsbInventoryTarget, ...]:
        targets: list[UsbInventoryTarget] = []
        for device in self.scanner():
            if (
                not device.confirmed_plus
                or not device.serial
                or device.bus_number is None
                or device.device_number is None
                or len(device.host_network_interfaces) != 1
                or len(device.host_network_interfaces[0].ipv4_addresses) != 1
            ):
                continue
            path = Path(device.usb_path)
            if path.parent != self.sysfs_root or not _TOPOLOGY.fullmatch(path.name):
                continue
            targets.append(
                UsbInventoryTarget(
                    serial=device.serial,
                    topology=path.name,
                    sysfs_path=path,
                    bus_number=device.bus_number,
                    device_number=device.device_number,
                    network_interface=device.host_network_interfaces[0].name,
                    source_ipv4=device.host_network_interfaces[0].ipv4_addresses[0],
                )
            )
        return tuple(sorted(targets, key=lambda item: (item.serial, item.topology)))

    def _dfu_device(self, topology: str) -> _DfuDevice:
        if not _TOPOLOGY.fullmatch(topology):
            raise ReleaseCandidateLifecycleError("DFU topology is malformed")
        path = self.sysfs_root / topology
        try:
            resolved = path.resolve(strict=True)
            # /sys/bus/usb/devices/<topology> is a kernel-owned symlink into
            # /sys/devices/.../usbN/<topology>.  The unresolved selector is
            # constructed locally from an exact topology, while the resolved
            # node must retain that same final component.  Requiring its parent
            # to resolve back under /sys/bus is incompatible with real sysfs.
            if path.parent != self.sysfs_root or resolved.name != topology:
                raise ReleaseCandidateLifecycleError("DFU sysfs path is not direct")
            vendor = (resolved / "idVendor").read_text(encoding="ascii").strip().lower()
            product = (resolved / "idProduct").read_text(encoding="ascii").strip().lower()
            bus = int((resolved / "busnum").read_text(encoding="ascii").strip())
            device = int((resolved / "devnum").read_text(encoding="ascii").strip())
            try:
                serial = (resolved / "serial").read_text(encoding="utf-8").strip()
            except FileNotFoundError:
                serial = ""
        except (OSError, UnicodeError, ValueError) as error:
            raise ReleaseCandidateLifecycleError(
                f"DFU sysfs identity unavailable: {error}"
            ) from error
        if vendor != USB_VENDOR or product != DFU_PRODUCT or bus <= 0 or device <= 0:
            raise ReleaseCandidateLifecycleError("exact topology is not one Pluto DFU device")
        return _DfuDevice(topology, path, vendor, product, serial, bus, device)

    def _interface_source(self, interface: str) -> str:
        if not _INTERFACE.fullmatch(interface):
            raise ReleaseCandidateLifecycleError("host-route interface is malformed")
        records = self._ip_json(
            ("address", "show", "dev", interface, "scope", "global"),
            label="interface source inventory",
        )
        sources: list[str] = []
        for record in records:
            if not isinstance(record, Mapping) or record.get("ifname") != interface:
                raise ReleaseCandidateLifecycleError("interface source record is not exact")
            details = record.get("addr_info")
            if not isinstance(details, list):
                raise ReleaseCandidateLifecycleError("interface address inventory is malformed")
            for detail in details:
                if (
                    isinstance(detail, Mapping)
                    and detail.get("family") == "inet"
                    and detail.get("scope") == "global"
                ):
                    sources.append(str(detail.get("local")))
        if len(sources) != 1:
            raise ReleaseCandidateLifecycleError(
                f"expected one global IPv4 source on {interface}; found {sources}"
            )
        try:
            address = ipaddress.ip_address(sources[0])
        except ValueError as error:
            raise ReleaseCandidateLifecycleError("interface source is not an IP address") from error
        if address.version != 4 or str(address) != sources[0]:
            raise ReleaseCandidateLifecycleError("interface source is not canonical IPv4")
        return str(address)

    def _exact_routes(self, destination: str) -> list[object]:
        return self._ip_json(
            ("route", "show", "table", "all", "exact", destination),
            label="exact route inventory",
        )

    def _add_route(self, route: HostRouteReceipt) -> None:
        self.runner.run(
            (
                "sudo",
                "-n",
                "ip",
                "route",
                "add",
                route.destination,
                "dev",
                route.interface,
                "src",
                route.source,
                "scope",
                "link",
                "proto",
                "static",
            ),
            timeout_s=self.timeout_s,
        )

    def _ip_json(self, arguments: Sequence[str], *, label: str) -> list[object]:
        output = self.runner.run(("ip", "-j", "-4", *arguments), timeout_s=self.timeout_s)
        try:
            value = json.loads(output)
        except json.JSONDecodeError as error:
            raise ReleaseCandidateLifecycleError(f"{label} is not JSON") from error
        if not isinstance(value, list):
            raise ReleaseCandidateLifecycleError(f"{label} must be a JSON array")
        return value

    def _attest_runtime_linux(
        self,
        target: UsbInventoryTarget,
        expected_firmware: str,
        password: PasswordFileIdentity,
        route: HostRouteReceipt,
    ) -> RuntimeObservation:
        try:
            iio = importlib.import_module("iio")
        except (ImportError, OSError) as error:
            raise ReleaseCandidateLifecycleError("pylibiio is required for attestation") from error
        # The Pluto USB-IIO function is interface 5.  The target bus/device was
        # already captured from sysfs and is revalidated immediately before
        # attestation; opening that exact URI avoids unrelated network/local
        # discovery backends and still cross-checks the context serial below.
        uri = f"usb:{target.bus_number}.{target.device_number}.5"
        if _USB_URI.fullmatch(uri) is None:
            raise ReleaseCandidateLifecycleError("exact USB-IIO URI is invalid")
        context: Any = None
        try:
            context = iio.Context(uri)
            setter = getattr(context, "set_timeout", None)
            if not callable(setter):
                raise ReleaseCandidateLifecycleError("USB-IIO context cannot set timeout")
            setter(round(self.timeout_s * 1000))
            attrs = {str(key): str(value) for key, value in context.attrs.items()}
            serial = attrs.get("hw_serial", attrs.get("usb,serial", attrs.get("serial", "")))
            firmware = attrs.get("fw_version", "")
            model = attrs.get("hw_model", "")
            if serial != target.serial or firmware != expected_firmware or not model:
                raise ReleaseCandidateLifecycleError(
                    "USB-IIO serial, firmware, or model differs from expected runtime"
                )
            phy = context.find_device("ad9361-phy")
            tx = context.find_device("cf-ad9361-dds-core-lpc")
            tandem = context.find_device("tandem-agc")
            if any(value is None for value in (phy, tx, tandem)):
                raise ReleaseCandidateLifecycleError("runtime lacks PHY/DDS/tandem devices")
            failures: list[str] = []
            for index in (0, 1):
                try:
                    _write_numeric(
                        _channel(phy, f"voltage{index}", True),
                        "hardwaregain",
                        -80.0,
                        tolerance=0.26,
                    )
                except BaseException as error:
                    failures.append(f"TX{index + 1} mute: {error}")
            for index in range(8):
                try:
                    channel = _channel(tx, f"altvoltage{index}", True)
                    _write_numeric(channel, "raw", 0.0, tolerance=1e-9)
                    _write_numeric(channel, "scale", 0.0, tolerance=1e-9)
                except BaseException as error:
                    failures.append(f"DDS{index} disable: {error}")
            for index in range(4):
                try:
                    legacy = 0x0414 + index * 0x40
                    selector = 0x0418 + index * 0x40
                    tx.reg_write(legacy, int(tx.reg_read(legacy)) & ~1)
                    tx.reg_write(selector, 3)
                except BaseException as error:
                    failures.append(f"DAC selector {index}: {error}")
            if failures:
                raise ReleaseCandidateLifecycleError("; ".join(failures))
            gains = tuple(
                _first_float(_read_attr(_channel(phy, f"voltage{i}", True), "hardwaregain"))
                for i in (0, 1)
            )
            dds_raw = tuple(
                round(_first_float(_read_attr(_channel(tx, f"altvoltage{i}", True), "raw")))
                for i in range(8)
            )
            dds_scale = tuple(
                _first_float(_read_attr(_channel(tx, f"altvoltage{i}", True), "scale"))
                for i in range(8)
            )
            selectors = tuple(int(tx.reg_read(0x0418 + i * 0x40)) & 0xF for i in range(4))
            state = round(_first_float(_read_attr(tandem, "state")))
            fifo = round(_first_float(_read_attr(tandem, "fifo_level")))
            faults = round(_first_float(_read_attr(tandem, "fault_flags")))
            from pluto_plus.hardware.iio import context_facts

            facts = context_facts(context)
            metadata_value = facts.get("buffer_metadata_abi")
            if not isinstance(metadata_value, int):
                raise ReleaseCandidateLifecycleError(
                    "runtime metadata ABI capability is absent, malformed, or inconsistent"
                )
            metadata = f"frame-metadata-v{metadata_value}"
            remote = self._remote_identity(target, password, route)
            if remote["firmware_version"] != firmware:
                raise ReleaseCandidateLifecycleError("SSH and USB-IIO firmware differ")
            hardware_setup = _canonical_hardware_setup(facts, remote)
            return RuntimeObservation(
                serial=serial,
                topology=target.topology,
                usb_uri=uri,
                hardware_model=model,
                firmware_version=firmware,
                metadata_abi=metadata,
                capabilities=("tandem-agc",),
                boot_id=remote["boot_id"],
                qspi=QspiObservation(bytes=int(remote["qspi_bytes"]), sha256=remote["qspi_sha256"]),
                safe_state=SafeState.model_validate(
                    {
                        "tx_gain_db": gains,
                        "dds_raw": dds_raw,
                        "dds_scale": dds_scale,
                        "dac_selectors": selectors,
                        "tandem_state": "IDLE" if state == 0 else f"STATE_{state}",
                        "fifo_level": fifo,
                        "fault_flags": faults,
                    }
                ),
                canonical_hardware_setup=hardware_setup,
            )
        finally:
            if context is not None:
                close = getattr(context, "close", None)
                if callable(close):
                    close()
                context = None
                gc.collect()

    def _remote_identity(
        self,
        target: UsbInventoryTarget,
        password: PasswordFileIdentity,
        route: HostRouteReceipt,
    ) -> dict[str, str]:
        self.ensure_host_route(route, target)
        validate_password_file(password.path, expected=password)
        host = route.destination.removesuffix("/32")
        output = self.runner.run(
            ssh_fixed_argv(
                target,
                ssh_host=host,
                password_path=password.path,
                remote_command=REMOTE_IDENTITY_SCRIPT,
            ),
            timeout_s=self.timeout_s,
        )
        fields: dict[str, str] = {}
        for line in output.splitlines():
            if "=" not in line:
                raise ReleaseCandidateLifecycleError("runtime identity line is malformed")
            key, value = line.split("=", 1)
            if key in fields:
                raise ReleaseCandidateLifecycleError("runtime identity has duplicate field")
            fields[key] = value
        expected = {
            "boot_id",
            "firmware_version",
            "qspi_partition",
            "qspi_mtd_name",
            "qspi_bytes",
            "qspi_sha256",
            "uboot_attr_name_absent",
            "uboot_attr_val_absent",
            "uboot_compatible",
            "uboot_mode",
        }
        if set(fields) != expected:
            raise ReleaseCandidateLifecycleError("runtime identity field inventory is not exact")
        if (
            _BOOT_ID.fullmatch(fields["boot_id"]) is None
            or fields["qspi_partition"] != "/dev/mtdblock3"
            or fields["qspi_mtd_name"] != "qspi-linux"
            or not fields["qspi_bytes"].isdigit()
            or int(fields["qspi_bytes"]) <= 0
            or _SHA256.fullmatch(fields["qspi_sha256"]) is None
            or not fields["firmware_version"]
            or fields["uboot_attr_name_absent"] not in {"0", "1"}
            or fields["uboot_attr_val_absent"] not in {"0", "1"}
        ):
            raise ReleaseCandidateLifecycleError("runtime boot/QSPI identity is invalid")
        return fields

    def _require_active_target(self) -> UsbInventoryTarget:
        if self._active_target is None:
            raise ReleaseCandidateLifecycleError("candidate transaction is not locked")
        return self._active_target

    def _require_sealed_descriptor(self, path: Path) -> int:
        match = re.fullmatch(r"/proc/self/fd/([0-9]+)", str(path))
        if match is None or self._sealed_descriptor != int(match.group(1)):
            raise ReleaseCandidateLifecycleError("DFU path is not the active sealed descriptor")
        return int(match.group(1))

    def _verify_sealed_descriptor(self, descriptor: int) -> None:
        if (
            fcntl.fcntl(descriptor, F_GET_SEALS) != REQUIRED_DFU_SEALS
            or self._sealed_bytes is None
            or self._sealed_sha256 is None
            or os.fstat(descriptor).st_size != self._sealed_bytes
            or _descriptor_sha256(descriptor, self._sealed_bytes) != self._sealed_sha256
        ):
            raise ReleaseCandidateLifecycleError("sealed DFU identity changed")

    def _prepare_state_root(self) -> None:
        self.state_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        _require_private_directory(self.state_root, label="candidate state root")


def _canonical_hardware_setup(
    facts: Mapping[str, object], remote: Mapping[str, str]
) -> CanonicalHardwareSetup:
    raw_scan_channels = facts.get("rx_scan_channels")
    if not isinstance(raw_scan_channels, (tuple, list)):
        raise ReleaseCandidateLifecycleError("runtime paired-RX scan layout is absent or malformed")
    try:
        return CanonicalHardwareSetup.model_validate(
            {
                "uboot_attr_name_absent": remote.get("uboot_attr_name_absent") == "1",
                "uboot_attr_val_absent": remote.get("uboot_attr_val_absent") == "1",
                "uboot_compatible": remote.get("uboot_compatible", ""),
                "uboot_mode": remote.get("uboot_mode", ""),
                "phy_model": facts.get("phy_model"),
                "rx_scan_channels": tuple(str(item) for item in raw_scan_channels),
                "tandem_device": facts.get("tandem_agc") is True,
            }
        )
    except ValidationError as error:
        raise ReleaseCandidateLifecycleError(
            "runtime lacks canonical Rev.C AD9361/2R2T/tandem setup proof"
        ) from error


def attest_clean_tool_repository(
    path: Path,
    *,
    imported_package_file: Path | None = None,
    imported_source_files: Sequence[Path] = (),
) -> ToolSourceAttestation:
    """Return the exact clean utility repository and commit used for live I/O."""

    if not path.is_absolute() or ".." in path.parts:
        raise ReleaseCandidateLifecycleError("tool repository must be an absolute normalized path")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ReleaseCandidateLifecycleError(f"tool repository is unavailable: {error}") from error
    runner = SubprocessLinuxCommandRunner()
    commit = runner.run(
        ("git", "-C", str(resolved), "rev-parse", "--verify", "HEAD^{commit}"),
        timeout_s=10,
    ).strip()
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise ReleaseCandidateLifecycleError("tool repository HEAD is not one commit")
    origin = runner.run(
        ("git", "-C", str(resolved), "config", "--get", "remote.origin.url"),
        timeout_s=10,
    ).strip()
    origin_match = _GITHUB_ORIGIN.fullmatch(origin)
    if origin_match is None:
        raise ReleaseCandidateLifecycleError(
            "tool repository origin must be one canonical GitHub SSH or HTTPS URL"
        )
    status = runner.run(
        (
            "git",
            "-C",
            str(resolved),
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        ),
        timeout_s=10,
    )
    if status:
        raise ReleaseCandidateLifecycleError(
            "tool repository must be fully clean, including untracked files"
        )
    bound_sources = (() if imported_package_file is None else (imported_package_file,)) + tuple(
        imported_source_files
    )
    for imported_package_file in bound_sources:
        try:
            imported = imported_package_file.resolve(strict=True)
            relative = imported.relative_to(resolved)
        except (OSError, ValueError) as error:
            raise ReleaseCandidateLifecycleError(
                "executing pluto_plus package is outside the attested tool repository"
            ) from error
        if relative.parts[:2] != ("src", "pluto_plus"):
            raise ReleaseCandidateLifecycleError(
                "executing pluto_plus package is not the attested repository src/pluto_plus tree"
            )
        runner.run(
            ("git", "-C", str(resolved), "ls-files", "--error-unmatch", str(relative)),
            timeout_s=10,
        )
    return ToolSourceAttestation(
        repository=origin_match.group("repository"),
        commit=commit,
    )


def _route_record_matches(record: object, route: HostRouteReceipt) -> bool:
    if not isinstance(record, Mapping):
        return False
    destination = str(record.get("dst", ""))
    if "/" not in destination:
        destination += "/32"
    try:
        destination = str(ipaddress.ip_network(destination, strict=True))
    except ValueError:
        return False
    return bool(
        destination == route.destination
        and record.get("dev") == route.interface
        and record.get("prefsrc") == route.source
        and record.get("scope") == "link"
        and record.get("protocol") == "static"
        and record.get("table", "main") in {"main", 254}
        and "gateway" not in record
        and "metric" not in record
    )


@contextmanager
def _exclusive_lock(path: Path) -> Iterator[Any]:
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise ReleaseCandidateLifecycleError(
            f"cannot open candidate lock {path}: {error}"
        ) from error
    stream: Any = None
    try:
        info = os.fstat(descriptor)
        path_info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or (info.st_dev, info.st_ino) != (path_info.st_dev, path_info.st_ino)
        ):
            raise ReleaseCandidateLifecycleError("candidate lock is not an owned regular file")
        if stat.S_IMODE(info.st_mode) != 0o600:
            os.fchmod(descriptor, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ReleaseCandidateLifecycleError(
                f"candidate lifecycle lock is already owned: {path}"
            ) from error
        stream = os.fdopen(descriptor, "r+", encoding="utf-8")
        descriptor = -1
        yield stream
    finally:
        if stream is not None:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
            stream.close()
        if descriptor >= 0:
            os.close(descriptor)


def _require_private_directory(path: Path, *, label: str) -> None:
    state = path.lstat()
    if (
        not stat.S_ISDIR(state.st_mode)
        or state.st_uid != os.getuid()
        or stat.S_IMODE(state.st_mode) != 0o700
    ):
        raise ReleaseCandidateLifecycleError(f"{label} must be owned mode-0700")


def _descriptor_sha256(descriptor: int, expected_bytes: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < expected_bytes:
        chunk = os.pread(descriptor, min(1 << 20, expected_bytes - offset), offset)
        if not chunk:
            raise ReleaseCandidateLifecycleError("sealed DFU descriptor was truncated")
        digest.update(chunk)
        offset += len(chunk)
    return digest.hexdigest()


def _first_float(value: Any) -> float:
    result = float(str(value).strip().split()[0])
    if not math.isfinite(result):
        raise ReleaseCandidateLifecycleError("IIO numeric value is not finite")
    return result


def _channel(device: Any, name: str, output: bool) -> Any:
    value = device.find_channel(name, output)
    if value is None:
        raise ReleaseCandidateLifecycleError(f"IIO device lacks channel {name!r}")
    return value


def _read_attr(owner: Any, name: str) -> str:
    if name not in owner.attrs:
        raise ReleaseCandidateLifecycleError(f"IIO object lacks attribute {name!r}")
    return str(owner.attrs[name].value)


def _write_numeric(owner: Any, name: str, value: float, *, tolerance: float) -> float:
    if name not in owner.attrs:
        raise ReleaseCandidateLifecycleError(f"IIO object lacks attribute {name!r}")
    owner.attrs[name].value = str(value)
    observed = _first_float(owner.attrs[name].value)
    if abs(observed - value) > tolerance:
        raise ReleaseCandidateLifecycleError(f"IIO {name} readback {observed} differs from {value}")
    return observed
