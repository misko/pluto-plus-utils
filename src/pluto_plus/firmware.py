"""Fail-closed firmware planning and execution primitives.

This module deliberately contains no HTTP or application-service integration.  A
caller supplies the live identity probe and the privileged hardware executor;
the manager binds a validated, content-addressed image to that exact identity
and re-attests it immediately before authorizing an operation.
"""

from __future__ import annotations

import binascii
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import tempfile
import threading
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Literal, Protocol

FIT_MAGIC = b"\xd0\x0d\xfe\xed"
PLUTO_FRM_MAGIC = b"ITB PlutoSDR (ADALM-PLUTO)"
DFU_SUFFIX_LENGTH = 16
DFU_VENDOR_ID = 0x0456
DFU_PRODUCT_ID = 0xB673
DFU_SPECIFICATION = 0x0100
FRM_TRAILER_LENGTH = 33


class FirmwareError(RuntimeError):
    """A firmware operation failed its safety contract."""


class FirmwareImageError(FirmwareError):
    """The supplied image is malformed or unsafe for a Pluto+."""


class FirmwareAuthorizationError(FirmwareError):
    """A confirmation token is absent, invalid, expired, or already consumed."""


class FirmwareIdentityError(FirmwareError):
    """The target radio no longer matches the identity bound into the plan."""


class FirmwareExecutionError(FirmwareError):
    """A privileged firmware attempt failed after authorization."""

    def __init__(self, message: str, receipt: FirmwareReceipt) -> None:
        super().__init__(message)
        self.receipt = receipt


class FirmwareExecutorFailure(FirmwareError):
    """A transport failed after its mutating operation may have begun."""

    def __init__(
        self,
        message: str,
        *,
        outcome: Literal["failed", "unknown"] = "unknown",
        completed_phases: tuple[str, ...] = (),
        failure_phase: str,
        reconciliation_required: bool = True,
        evidence_reference: str | None = None,
    ) -> None:
        super().__init__(message)
        self.outcome = outcome
        self.completed_phases = completed_phases
        self.failure_phase = failure_phase
        self.reconciliation_required = reconciliation_required
        self.evidence_reference = evidence_reference
        self.evidence: object | None = None


class FirmwareMode(StrEnum):
    VOLATILE_DFU = "volatile_dfu"
    PERSISTENT_QSPI = "persistent_qspi"


class FirmwareTransport(StrEnum):
    USB = "usb"
    SSH_FRM = "ssh_frm"


@dataclass(frozen=True, slots=True)
class RadioFirmwareIdentity:
    """Stable identity and observed state used to bind a firmware plan."""

    serial: str
    usb_sysfs_path: str | None
    observed_firmware: str
    endpoint: str | None = None
    host_key_fingerprint: str | None = None

    def __post_init__(self) -> None:
        if not self.serial.strip():
            raise ValueError("radio serial cannot be empty")
        if self.usb_sysfs_path is not None and not self.usb_sysfs_path.startswith(
            "/sys/bus/usb/devices/"
        ):
            raise ValueError("usb_sysfs_path must identify one USB sysfs device")
        if not self.observed_firmware.strip():
            raise ValueError("observed firmware cannot be empty")
        if self.endpoint is not None and not self.endpoint.strip():
            raise ValueError("firmware endpoint cannot be empty")
        if self.host_key_fingerprint is not None and not self.host_key_fingerprint.strip():
            raise ValueError("host key fingerprint cannot be empty")


@dataclass(frozen=True, slots=True)
class FirmwareTransportSummary:
    serial: str
    endpoint: str | None
    host_key_fingerprint: str | None
    current_firmware: str
    expected_firmware: str | None
    source_sha256: str
    image_sha256: str
    fit_sha256: str
    fit_size: int


@dataclass(frozen=True, slots=True)
class FirmwarePlan:
    plan_id: str
    created_at: datetime
    expires_at: datetime
    radio: RadioFirmwareIdentity
    mode: FirmwareMode
    transport: FirmwareTransport
    transport_summary: FirmwareTransportSummary
    source_name: str
    source_sha256: str
    staged_path: str
    image_sha256: str
    image_size: int
    fit_sha256: str
    fit_size: int
    phases: tuple[str, ...]
    expected_firmware: str | None = None


@dataclass(frozen=True, slots=True)
class PlannedFirmware:
    """A plan plus the only copy of its plaintext confirmation token."""

    plan: FirmwarePlan
    confirmation_token: str


@dataclass(frozen=True, slots=True)
class FirmwareReceipt:
    schema_version: int
    receipt_id: str
    plan_id: str
    started_at: datetime
    finished_at: datetime
    radio: RadioFirmwareIdentity
    mode: FirmwareMode
    transport: FirmwareTransport
    image_sha256: str
    image_size: int
    fit_sha256: str | None
    fit_size: int | None
    expected_firmware: str | None
    outcome: Literal["success", "failed", "unknown"]
    completed_phases: tuple[str, ...]
    failure_phase: str | None
    reconciliation_required: bool
    reconciliation_of: str | None
    evidence_reference: str | None
    success: bool
    error: str | None


class FirmwareFilesystem(Protocol):
    """Filesystem seam used for validation, staging, and durable receipts."""

    def read_bytes(self, path: Path) -> bytes: ...

    def write_atomic(self, path: Path, data: bytes, *, mode: int = 0o600) -> None: ...


class LocalFirmwareFilesystem:
    """Local durable implementation; writes are fsync'd before publication."""

    def read_bytes(self, path: Path) -> bytes:
        return path.read_bytes()

    def write_atomic(self, path: Path, data: bytes, *, mode: int = 0o600) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        temporary = Path(temporary_name)
        try:
            os.fchmod(fd, mode)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise


class PrivilegedFirmwareExecutor(Protocol):
    """Narrow privileged boundary; implementations must target this identity only."""

    def effective_uid(self) -> int: ...

    def load_volatile_dfu(self, radio: RadioFirmwareIdentity, image: Path) -> None: ...

    def flash_persistent_qspi(
        self, radio: RadioFirmwareIdentity, image: Path, *, target_name: str
    ) -> None: ...


class BoundaryAuthorizingFirmwareExecutor(Protocol):
    """Executor whose privilege is enforced across a process boundary.

    The method must not claim that the calling process is privileged.  It only
    indicates that every mutating request is authenticated and authorized by
    the remote execution boundary.  The remote side remains responsible for
    checking its own effective UID immediately before mutation.
    """

    def authorize_execution(self) -> None: ...


class ReconcilingFirmwareExecutor(Protocol):
    """Optional read-only attestation seam for an uncertain persistent attempt."""

    def reconcile_persistent_qspi(
        self,
        radio: RadioFirmwareIdentity,
        *,
        expected_firmware: str | None,
        expected_fit_sha256: str,
        expected_fit_size: int,
    ) -> tuple[str, ...]: ...


class CommandRunner(Protocol):
    def run(self, argv: Sequence[str], *, timeout_s: float) -> None: ...


class SubprocessCommandRunner:
    def run(self, argv: Sequence[str], *, timeout_s: float) -> None:
        subprocess.run(argv, check=True, timeout=timeout_s)  # noqa: S603


class QspiUpdater(Protocol):
    """Serial-aware updater-volume seam implemented by a privileged helper."""

    def install(
        self,
        radio: RadioFirmwareIdentity,
        source: Path,
        *,
        target_name: str,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class UpdaterBlockDevice:
    """One updater disk attested by udev's ``ID_SERIAL_SHORT`` property."""

    device: Path
    partition: Path
    id_serial_short: str

    def __post_init__(self) -> None:
        for name, path in (("device", self.device), ("partition", self.partition)):
            if not path.is_absolute() or not str(path).startswith("/dev/"):
                raise ValueError(f"{name} must be an absolute path below /dev")
        if self.device == self.partition:
            raise ValueError("updater device and partition must differ")
        if not self.id_serial_short.strip():
            raise ValueError("ID_SERIAL_SHORT cannot be empty")


class MassStorageFilesystem(Protocol):
    """Filesystem operations used while an updater volume is mounted."""

    def read_bytes(self, path: Path) -> bytes: ...

    def prepare_private_mountpoint(self, path: Path) -> None: ...

    def is_file(self, path: Path) -> bool: ...

    def write_fat_atomic(self, path: Path, data: bytes) -> None: ...


class LocalMassStorageFilesystem:
    """Same-volume temporary-write/replace semantics supported by FAT."""

    def read_bytes(self, path: Path) -> bytes:
        return path.read_bytes()

    def prepare_private_mountpoint(self, path: Path) -> None:
        if not path.is_absolute() or path == Path("/"):
            raise FirmwareError("QSPI mountpoint must be an explicit absolute directory")
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        if path.is_symlink() or not path.is_dir():
            raise FirmwareError("QSPI mountpoint must be a private real directory")
        os.chmod(path, 0o700)
        if any(path.iterdir()):
            raise FirmwareError("QSPI mountpoint is not empty before mount")

    def is_file(self, path: Path) -> bool:
        return path.is_file()

    def write_fat_atomic(self, path: Path, data: bytes) -> None:
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
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
            os.replace(temporary, path)
        except BaseException:
            if descriptor is not None:
                os.close(descriptor)
            temporary.unlink(missing_ok=True)
            raise


class MassStorageQspiUpdater:
    """Serial-scoped Pluto mass-storage updater for the firmware-only partition.

    Enumeration is injected so this class never guesses with ``/dev/sd*`` or
    another broad glob.  Each enumeration result must carry the udev
    ``ID_SERIAL_SHORT`` value used to select exactly one updater disk.
    """

    def __init__(
        self,
        *,
        enumerate_devices: Callable[[], Sequence[UpdaterBlockDevice]],
        command_runner: CommandRunner,
        filesystem: MassStorageFilesystem,
        mountpoint: Path,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        reenumeration_timeout_s: float = 180,
        poll_interval_s: float = 1,
    ) -> None:
        if reenumeration_timeout_s <= 0 or poll_interval_s <= 0:
            raise ValueError("reenumeration timeout and poll interval must be positive")
        self._enumerate = enumerate_devices
        self._commands = command_runner
        self._filesystem = filesystem
        self._mountpoint = mountpoint
        self._monotonic = monotonic
        self._sleep = sleep
        self._timeout = reenumeration_timeout_s
        self._poll_interval = poll_interval_s

    def install(
        self,
        radio: RadioFirmwareIdentity,
        source: Path,
        *,
        target_name: str,
    ) -> None:
        if target_name != "pluto.frm" or Path(target_name).name != target_name:
            raise FirmwareError("mass-storage updater accepts only pluto.frm")
        source_data = self._filesystem.read_bytes(source)
        validate_frm(source_data)
        selected = self._resolve_one(radio.serial)
        self._filesystem.prepare_private_mountpoint(self._mountpoint)

        mount_attempted = False
        operation_error: Exception | None = None
        cleanup_error: Exception | None = None
        try:
            mount_attempted = True
            self._commands.run(
                (
                    "mount",
                    "-o",
                    "rw,nodev,nosuid,noexec",
                    str(selected.partition),
                    str(self._mountpoint),
                ),
                timeout_s=30,
            )
            if not self._filesystem.is_file(self._mountpoint / "info.html"):
                raise FirmwareError("selected updater volume has no info.html")
            destination = self._mountpoint / "pluto.frm"
            self._filesystem.write_fat_atomic(destination, source_data)
            self._commands.run(("sync", "-f", str(destination)), timeout_s=30)
        except Exception as caught:
            operation_error = caught
        finally:
            if mount_attempted:
                try:
                    self._commands.run(("umount", str(self._mountpoint)), timeout_s=30)
                except Exception as caught:
                    cleanup_error = caught

        if operation_error is not None or cleanup_error is not None:
            details = []
            if operation_error is not None:
                details.append(f"operation failed: {operation_error}")
            if cleanup_error is not None:
                details.append(f"unmount failed: {cleanup_error}")
            raise FirmwareError("; ".join(details))

        try:
            self._commands.run(("eject", str(selected.device)), timeout_s=30)
        except Exception as caught:
            raise FirmwareError(f"eject failed: {caught}") from caught
        self._wait_for_absence(radio.serial)
        self._wait_for_reappearance(radio.serial)

    def _matches(self, serial: str) -> tuple[UpdaterBlockDevice, ...]:
        try:
            devices = tuple(self._enumerate())
        except Exception as caught:
            raise FirmwareError(f"updater block-device enumeration failed: {caught}") from caught
        return tuple(device for device in devices if device.id_serial_short == serial)

    def _resolve_one(self, serial: str) -> UpdaterBlockDevice:
        matches = self._matches(serial)
        if len(matches) != 1:
            raise FirmwareError(
                f"expected exactly one updater block device for serial {serial!r}; "
                f"found {len(matches)}"
            )
        return matches[0]

    def _wait_for_absence(self, serial: str) -> None:
        deadline = self._monotonic() + self._timeout
        while self._monotonic() < deadline:
            matches = self._matches(serial)
            if len(matches) > 1:
                raise FirmwareError(
                    f"duplicate updater identities appeared for serial {serial!r}"
                )
            if not matches:
                return
            self._sleep(self._poll_interval)
        raise FirmwareError(f"updater for serial {serial!r} did not disappear after eject")

    def _wait_for_reappearance(self, serial: str) -> None:
        deadline = self._monotonic() + self._timeout
        while self._monotonic() < deadline:
            matches = self._matches(serial)
            if len(matches) > 1:
                raise FirmwareError(
                    f"duplicate updater identities appeared for serial {serial!r}"
                )
            if len(matches) == 1:
                return
            self._sleep(self._poll_interval)
        raise FirmwareError(f"updater for serial {serial!r} did not reappear after eject")


class SysfsRadioFirmwareIdentityProbe:
    """Resolve one runtime Pluto sysfs node and read its observed firmware."""

    def __init__(
        self,
        *,
        enumerate_devices: Callable[[], Sequence[Path]] | None = None,
        text_reader: Callable[[Path], str] | None = None,
        observed_firmware_reader: Callable[[str, str], str],
        usb_root: Path = Path("/sys/bus/usb/devices"),
    ) -> None:
        self._usb_root = usb_root
        self._enumerate = enumerate_devices or (lambda: tuple(usb_root.iterdir()))
        self._read = text_reader or (lambda path: path.read_text())
        self._firmware = observed_firmware_reader

    def __call__(self, serial: str) -> RadioFirmwareIdentity:
        matches: list[Path] = []
        for device in self._enumerate():
            if device.parent != self._usb_root:
                raise FirmwareIdentityError(
                    f"enumerated USB path {device} is outside {self._usb_root}"
                )
            try:
                vendor = self._read(device / "idVendor").strip().lower()
                product = self._read(device / "idProduct").strip().lower()
                candidate_serial = self._read(device / "serial").strip()
            except OSError:
                continue
            if vendor == "0456" and product == "b673" and candidate_serial == serial:
                matches.append(device)
        if len(matches) != 1:
            raise FirmwareIdentityError(
                f"expected exactly one runtime Pluto sysfs device for serial {serial!r}; "
                f"found {len(matches)}"
            )
        device = matches[0]
        observed = self._firmware(serial, str(device)).strip()
        if not observed:
            raise FirmwareIdentityError("observed firmware reader returned an empty value")
        return RadioFirmwareIdentity(
            serial=serial,
            usb_sysfs_path=str(device),
            observed_firmware=observed,
        )


class SystemFirmwareExecutor:
    """Command-backed executor with an injected exact-radio DFU transition.

    The transition command factory is intentionally mandatory: entering DFU via
    the shared 192.168.2.1 address is not identity safe.  The factory must return
    a command that independently binds both serial and physical sysfs path.
    Persistent updates similarly go through a serial-aware updater implementation.
    """

    def __init__(
        self,
        *,
        command_runner: CommandRunner,
        enter_dfu_command: Callable[[RadioFirmwareIdentity], Sequence[str]],
        qspi_updater: QspiUpdater,
        uid_provider: Callable[[], int] = os.geteuid,
    ) -> None:
        self._commands = command_runner
        self._enter_dfu_command = enter_dfu_command
        self._qspi = qspi_updater
        self._uid = uid_provider

    def effective_uid(self) -> int:
        return self._uid()

    def load_volatile_dfu(self, radio: RadioFirmwareIdentity, image: Path) -> None:
        if radio.usb_sysfs_path is None:
            raise FirmwareIdentityError("DFU loading requires a USB sysfs identity")
        enter_command = tuple(self._enter_dfu_command(radio))
        if not enter_command:
            raise FirmwareError("exact-radio DFU transition command is empty")
        self._commands.run(enter_command, timeout_s=30)
        common = (
            "dfu-util",
            "-p",
            Path(radio.usb_sysfs_path).name,
            "-d",
            "0456:b673,0456:b674",
            "-a",
            "firmware.dfu",
        )
        self._commands.run((*common, "-D", str(image)), timeout_s=120)
        self._commands.run((*common, "-e"), timeout_s=30)

    def flash_persistent_qspi(
        self, radio: RadioFirmwareIdentity, image: Path, *, target_name: str
    ) -> None:
        if target_name != "pluto.frm":
            raise FirmwareError("persistent updater target must be exactly pluto.frm")
        self._qspi.install(radio, image, target_name=target_name)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _validate_fit(body: bytes) -> None:
    if len(body) < 40 or body[:4] != FIT_MAGIC:
        raise FirmwareImageError("image does not start with a complete FIT header")
    declared_size = int.from_bytes(body[4:8], "big")
    if declared_size != len(body):
        raise FirmwareImageError(
            f"FIT size is {declared_size} bytes but image body is {len(body)} bytes"
        )
    if PLUTO_FRM_MAGIC not in body:
        raise FirmwareImageError("required Pluto FRM magic is absent from FIT body")


def _dfu_crc(data_without_crc: bytes) -> int:
    # DFU suffixes retain the un-finalized Ethernet CRC accumulator.
    return binascii.crc32(data_without_crc) ^ 0xFFFFFFFF


def validate_dfu(data: bytes) -> bytes:
    """Validate a Pluto DFU and return its raw FIT body."""

    if len(data) <= DFU_SUFFIX_LENGTH:
        raise FirmwareImageError("DFU image is too short")
    body, suffix = data[:-DFU_SUFFIX_LENGTH], data[-DFU_SUFFIX_LENGTH:]
    device, product, vendor, specification = (
        int.from_bytes(suffix[offset : offset + 2], "little")
        for offset in range(0, 8, 2)
    )
    del device  # The release build intentionally permits any device revision.
    if suffix[8:11] != b"UFD" or suffix[11] != DFU_SUFFIX_LENGTH:
        raise FirmwareImageError("invalid DFU suffix signature or length")
    if vendor != DFU_VENDOR_ID or product != DFU_PRODUCT_ID:
        raise FirmwareImageError(
            f"DFU targets {vendor:04x}:{product:04x}, expected 0456:b673"
        )
    if specification != DFU_SPECIFICATION:
        raise FirmwareImageError(
            f"unsupported DFU specification 0x{specification:04x}"
        )
    expected_crc = int.from_bytes(suffix[12:16], "little")
    actual_crc = _dfu_crc(data[:-4])
    if not hmac.compare_digest(
        expected_crc.to_bytes(4, "little"), actual_crc.to_bytes(4, "little")
    ):
        raise FirmwareImageError("DFU suffix CRC mismatch")
    _validate_fit(body)
    return body


def validate_frm(data: bytes) -> bytes:
    """Validate a firmware-only Pluto FRM and return its FIT body."""

    if len(data) <= FRM_TRAILER_LENGTH:
        raise FirmwareImageError("FRM image is too short")
    body, trailer = data[:-FRM_TRAILER_LENGTH], data[-FRM_TRAILER_LENGTH:]
    if trailer[-1:] != b"\n":
        raise FirmwareImageError("FRM MD5 trailer must end in a newline")
    digest = trailer[:-1]
    if len(digest) != 32 or any(byte not in b"0123456789abcdef" for byte in digest):
        raise FirmwareImageError("FRM MD5 trailer must be lowercase hexadecimal")
    actual = hashlib.md5(body, usedforsecurity=False).hexdigest().encode("ascii")  # noqa: S324
    if not hmac.compare_digest(digest, actual):
        raise FirmwareImageError("FRM MD5 trailer mismatch")
    _validate_fit(body)
    return body


def generate_frm(dfu_data: bytes) -> bytes:
    """Generate the sole safe persistent artifact, ``pluto.frm``, from a DFU."""

    body = validate_dfu(dfu_data)
    digest = hashlib.md5(body, usedforsecurity=False).hexdigest().encode("ascii")  # noqa: S324
    result = body + digest + b"\n"
    validate_frm(result)
    return result


@dataclass(slots=True)
class _TokenRecord:
    digest: bytes
    expires_at: datetime
    plan: FirmwarePlan
    used: bool = False


class _ConfirmationTokens:
    def __init__(self) -> None:
        self._records: dict[str, _TokenRecord] = {}
        self._lock = threading.Lock()

    def issue(self, plan: FirmwarePlan) -> str:
        token = secrets.token_urlsafe(32)
        digest = hashlib.sha256(token.encode()).digest()
        with self._lock:
            self._records[plan.plan_id] = _TokenRecord(
                digest=digest,
                expires_at=plan.expires_at,
                plan=plan,
            )
        return token

    def consume(self, plan: FirmwarePlan, token: str, now: datetime) -> None:
        presented = hashlib.sha256(token.encode()).digest()
        with self._lock:
            record = self._records.get(plan.plan_id)
            if record is None or not hmac.compare_digest(record.digest, presented):
                raise FirmwareAuthorizationError("confirmation token is invalid")
            if record.plan != plan:
                raise FirmwareAuthorizationError("confirmation token is bound to another plan")
            if record.used:
                raise FirmwareAuthorizationError("confirmation token was already used")
            if now >= record.expires_at:
                raise FirmwareAuthorizationError("confirmation token has expired")
            record.used = True


class FirmwareManager:
    """Create identity-bound plans and execute them through a privileged seam."""

    def __init__(
        self,
        *,
        staging_directory: Path,
        receipt_directory: Path,
        identity_probe: Callable[[str], RadioFirmwareIdentity],
        executor: PrivilegedFirmwareExecutor,
        transport: FirmwareTransport = FirmwareTransport.USB,
        filesystem: FirmwareFilesystem | None = None,
        clock: Callable[[], datetime] | None = None,
        confirmation_ttl: timedelta = timedelta(minutes=5),
    ) -> None:
        if confirmation_ttl <= timedelta(0):
            raise ValueError("confirmation_ttl must be positive")
        self._staging = staging_directory
        self._receipts = receipt_directory
        self._identity_probe = identity_probe
        self._executor = executor
        self.transport = transport
        self._filesystem = filesystem or LocalFirmwareFilesystem()
        self._clock = clock or (lambda: datetime.now(UTC))
        self._ttl = confirmation_ttl
        self._tokens = _ConfirmationTokens()
        self._receipt_lock = threading.Lock()
        self._receipt_records: dict[str, FirmwareReceipt] = {}
        self._load_receipts()

    def observe_identity(self, serial: str) -> RadioFirmwareIdentity:
        """Return one fresh identity from this manager's configured transport."""

        identity = self._identity_probe(serial)
        self._validate_transport_identity(identity)
        return identity

    @property
    def key_reconciliation_required(self) -> bool:
        """Whether this transport has blocked further mutation pending re-enrollment."""

        if bool(getattr(self._executor, "key_reconciliation_required", False)):
            return True
        with self._receipt_lock:
            receipts = tuple(self._receipt_records.values())
        resolved = {
            receipt.reconciliation_of
            for receipt in receipts
            if receipt.success
            and not receipt.reconciliation_required
            and receipt.reconciliation_of is not None
        }
        return any(
            receipt.transport is FirmwareTransport.SSH_FRM
            and receipt.reconciliation_required
            and receipt.reconciliation_of is None
            and receipt.receipt_id not in resolved
            for receipt in receipts
        )

    def create_plan(
        self,
        radio: RadioFirmwareIdentity,
        source: Path,
        mode: FirmwareMode,
        *,
        expected_firmware: str | None = None,
        transport: FirmwareTransport | None = None,
    ) -> PlannedFirmware:
        selected_transport = transport or self.transport
        if selected_transport is not self.transport:
            raise FirmwareImageError(
                f"firmware manager is not configured for {selected_transport.value}"
            )
        if (
            selected_transport is FirmwareTransport.SSH_FRM
            and mode is not FirmwareMode.PERSISTENT_QSPI
        ):
            raise FirmwareImageError("ssh_frm supports persistent_qspi plans only")
        if (
            selected_transport is FirmwareTransport.SSH_FRM
            and self.key_reconciliation_required
        ):
            raise FirmwareAuthorizationError(
                "ssh_frm is blocked until unresolved durable receipts are reconciled"
            )
        self._validate_transport_identity(radio)
        current = self.observe_identity(radio.serial)
        if current != radio:
            raise FirmwareIdentityError(
                "requested radio identity does not match its current observed identity"
            )
        if source.name.lower() == "boot.frm" or source.suffix.lower() == ".zip":
            raise FirmwareImageError("boot.frm and firmware ZIPs are forbidden")
        source_data = self._filesystem.read_bytes(source)
        source_digest = _sha256(source_data)
        if mode is FirmwareMode.VOLATILE_DFU:
            if source.suffix.lower() != ".dfu":
                raise FirmwareImageError("volatile loading requires a .dfu image")
            fit_body = validate_dfu(source_data)
            staged_name = "firmware.dfu"
            staged_data = source_data
        elif mode is FirmwareMode.PERSISTENT_QSPI:
            if source.suffix.lower() == ".dfu":
                staged_data = generate_frm(source_data)
                fit_body = validate_frm(staged_data)
            elif source.suffix.lower() == ".frm":
                fit_body = validate_frm(source_data)
                staged_data = source_data
            else:
                raise FirmwareImageError("persistent flashing requires a .dfu or .frm image")
            staged_name = "pluto.frm"
        else:  # pragma: no cover - StrEnum protects normal callers
            raise FirmwareImageError(f"unsupported firmware mode: {mode}")

        image_digest = _sha256(staged_data)
        staged_path = self._staging / image_digest / staged_name
        try:
            existing = self._filesystem.read_bytes(staged_path)
        except FileNotFoundError:
            self._filesystem.write_atomic(staged_path, staged_data)
        else:
            if not hmac.compare_digest(
                hashlib.sha256(existing).digest(),
                hashlib.sha256(staged_data).digest(),
            ):
                raise FirmwareImageError("content-addressed staging path contains different data")

        now = self._normalized_now()
        normalized_expected = None
        if expected_firmware is not None:
            normalized_expected = expected_firmware.strip()
            if not normalized_expected:
                raise FirmwareImageError("expected firmware version cannot be empty")
        plan = FirmwarePlan(
            plan_id=uuid.uuid4().hex,
            created_at=now,
            expires_at=now + self._ttl,
            radio=radio,
            mode=mode,
            transport=selected_transport,
            transport_summary=FirmwareTransportSummary(
                serial=radio.serial,
                endpoint=radio.endpoint,
                host_key_fingerprint=radio.host_key_fingerprint,
                current_firmware=radio.observed_firmware,
                expected_firmware=normalized_expected,
                source_sha256=source_digest,
                image_sha256=image_digest,
                fit_sha256=_sha256(fit_body),
                fit_size=len(fit_body),
            ),
            source_name=source.name,
            source_sha256=source_digest,
            staged_path=str(staged_path),
            image_sha256=image_digest,
            image_size=len(staged_data),
            fit_sha256=_sha256(fit_body),
            fit_size=len(fit_body),
            phases=(
                (
                    "preflight",
                    "authorization",
                    "controller_quiesced",
                    "remote_identity_attested",
                    "frm_staged",
                    "persistent_write",
                    "mtd_verified",
                    "reboot_requested",
                    "post_update_attestation",
                )
                if selected_transport is FirmwareTransport.SSH_FRM
                else (
                    "preflight",
                    "authorization",
                    "controller_quiesced",
                    "usb_update",
                    "post_update_attestation",
                )
            ),
            expected_firmware=normalized_expected,
        )
        token = self._tokens.issue(plan)
        return PlannedFirmware(plan=plan, confirmation_token=token)

    def execute(
        self,
        plan: FirmwarePlan,
        confirmation_token: str,
        *,
        before_mutation: Callable[[], None] | None = None,
        after_mutation: Callable[[], None] | None = None,
        operator_confirmation: str | None = None,
    ) -> FirmwareReceipt:
        if plan.transport is FirmwareTransport.SSH_FRM:
            required = f"FLASH {plan.radio.serial}"
            if operator_confirmation != required:
                raise FirmwareAuthorizationError(
                    f"SSH firmware confirmation must exactly match {required!r}"
                )
        boundary_authorize = getattr(self._executor, "authorize_execution", None)
        if boundary_authorize is not None:
            boundary_authorize()
        elif self._executor.effective_uid() != 0:
            raise FirmwareAuthorizationError("firmware operations require root")
        now = self._normalized_now()
        if now >= plan.expires_at:
            raise FirmwareAuthorizationError("firmware plan has expired")
        current = self.observe_identity(plan.radio.serial)
        if current != plan.radio:
            raise FirmwareIdentityError(
                "radio identity or observed firmware changed after plan creation"
            )
        staged_path = Path(plan.staged_path)
        staged_data = self._filesystem.read_bytes(staged_path)
        if len(staged_data) != plan.image_size or not hmac.compare_digest(
            _sha256(staged_data), plan.image_sha256
        ):
            raise FirmwareImageError("staged firmware hash or size changed after planning")
        if plan.mode is FirmwareMode.VOLATILE_DFU:
            validate_dfu(staged_data)
        else:
            if staged_path.name != "pluto.frm":
                raise FirmwareImageError("persistent staged filename must be exactly pluto.frm")
            validate_frm(staged_data)

        # A second plan may have been issued before an earlier attempt became
        # uncertain. Recheck the durable lock at the last non-mutating boundary
        # so a pre-issued token cannot replay an SSH update.
        if (
            plan.transport is FirmwareTransport.SSH_FRM
            and self.key_reconciliation_required
        ):
            raise FirmwareAuthorizationError(
                "ssh_frm is blocked until unresolved durable receipts are reconciled"
            )

        # A valid token is consumed immediately before the first mutating call.
        self._tokens.consume(plan, confirmation_token, now)
        started = self._normalized_now()
        receipt_id = uuid.uuid4().hex
        error: str | None = None
        prepared = False
        mutation_started = False
        outcome: Literal["success", "failed", "unknown"] = "success"
        completed_phases: tuple[str, ...] = ("preflight", "authorization")
        failure_phase: str | None = None
        reconciliation_required = False
        evidence_reference: str | None = None
        try:
            if before_mutation is not None:
                before_mutation()
                prepared = True
                completed_phases = (*completed_phases, "controller_quiesced")
            mutation_started = True
            if plan.mode is FirmwareMode.VOLATILE_DFU:
                self._executor.load_volatile_dfu(plan.radio, staged_path)
            else:
                self._executor.flash_persistent_qspi(
                    plan.radio, staged_path, target_name="pluto.frm"
                )
            if plan.transport is FirmwareTransport.SSH_FRM:
                (
                    transport_phases,
                    evidence_reference,
                    key_reconciliation_required,
                ) = self._validate_ssh_execution_evidence(plan)
                completed_phases = (*completed_phases, *transport_phases)
                reconciliation_required = key_reconciliation_required
            else:
                completed_phases = (*completed_phases, "transport_completed")
        except FirmwareExecutorFailure as caught:
            error = f"{type(caught).__name__}: {caught}"
            outcome = caught.outcome
            completed_phases = (*completed_phases, *caught.completed_phases)
            failure_phase = caught.failure_phase
            reconciliation_required = caught.reconciliation_required
            evidence_reference = caught.evidence_reference
        except BaseException as caught:  # record every authorized mutation attempt
            error = f"{type(caught).__name__}: {caught}"
            evidence = getattr(caught, "evidence", None)
            raw_phases = getattr(evidence, "completed_phases", ())
            if isinstance(raw_phases, (tuple, list)):
                completed_phases = (*completed_phases, *(str(item) for item in raw_phases))
            evidence_outcome = str(getattr(evidence, "outcome", ""))
            outcome = (
                "failed"
                if evidence_outcome == "failed"
                else ("unknown" if mutation_started else "failed")
            )
            failure_phase = str(
                getattr(
                    evidence,
                    "failure_phase",
                    "transport" if mutation_started else "controller_quiesce",
                )
            )
            reconciliation_required = bool(
                getattr(evidence, "reconciliation_required", mutation_started)
            )
            raw_reference = getattr(evidence, "attempt_id", None)
            evidence_reference = None if raw_reference is None else str(raw_reference)
        finally:
            if prepared and after_mutation is not None:
                try:
                    after_mutation()
                except BaseException as caught:
                    recovery_error = f"{type(caught).__name__}: {caught}"
                    error = (
                        recovery_error
                        if error is None
                        else f"{error}; post-update recovery failed: {recovery_error}"
                    )
                    if mutation_started:
                        outcome = "unknown"
                        failure_phase = "controller_recovery"
                        reconciliation_required = True
        if error is None:
            try:
                if plan.transport is FirmwareTransport.USB:
                    verified = self.observe_identity(plan.radio.serial)
                    if (
                        verified.serial != plan.radio.serial
                        or verified.usb_sysfs_path != plan.radio.usb_sysfs_path
                    ):
                        raise FirmwareIdentityError(
                            "post-update radio serial or USB path did not match the plan"
                        )
                    if (
                        plan.expected_firmware is not None
                        and verified.observed_firmware != plan.expected_firmware
                    ):
                        raise FirmwareIdentityError(
                            f"post-update firmware is {verified.observed_firmware!r}, "
                            f"expected {plan.expected_firmware!r}"
                        )
                    completed_phases = (*completed_phases, "post_update_attestation")
            except BaseException as caught:
                error = f"{type(caught).__name__}: {caught}"
                outcome = "unknown"
                failure_phase = "post_update_attestation"
                reconciliation_required = True
        receipt = FirmwareReceipt(
            schema_version=2,
            receipt_id=receipt_id,
            plan_id=plan.plan_id,
            started_at=started,
            finished_at=self._normalized_now(),
            radio=plan.radio,
            mode=plan.mode,
            transport=plan.transport,
            image_sha256=plan.image_sha256,
            image_size=plan.image_size,
            fit_sha256=plan.fit_sha256,
            fit_size=plan.fit_size,
            expected_firmware=plan.expected_firmware,
            outcome=outcome,
            completed_phases=completed_phases,
            failure_phase=failure_phase,
            reconciliation_required=reconciliation_required,
            reconciliation_of=None,
            evidence_reference=evidence_reference,
            success=error is None,
            error=error,
        )
        self._write_receipt(receipt)
        with self._receipt_lock:
            self._receipt_records[receipt.receipt_id] = receipt
        if error is not None:
            raise FirmwareExecutionError(error, receipt)
        return receipt

    def list_receipts(self) -> list[FirmwareReceipt]:
        """Return durable receipts from this manager, newest first."""

        with self._receipt_lock:
            return sorted(
                self._receipt_records.values(),
                key=lambda item: item.started_at,
                reverse=True,
            )

    def reconcile(self, receipt_id: str) -> FirmwareReceipt:
        """Re-attest an uncertain attempt without dispatching another mutation."""

        with self._receipt_lock:
            original = self._receipt_records.get(receipt_id)
        if original is None:
            raise FirmwareImageError(f"unknown firmware receipt: {receipt_id}")
        if not original.reconciliation_required:
            raise FirmwareImageError("firmware receipt does not require reconciliation")
        # Reconciliation attempts are append-only receipts. If a caller retries
        # using a failed reconciliation receipt, always bind the new result to
        # the root mutation receipt so one successful attestation resolves the
        # original uncertainty rather than creating an unresolvable chain.
        seen = {original.receipt_id}
        while original.reconciliation_of is not None:
            parent_id = original.reconciliation_of
            if parent_id in seen:
                raise FirmwareImageError("firmware receipt reconciliation chain is cyclic")
            seen.add(parent_id)
            with self._receipt_lock:
                parent = self._receipt_records.get(parent_id)
            if parent is None:
                raise FirmwareImageError(
                    "firmware receipt reconciliation parent is unavailable"
                )
            original = parent

        started = self._normalized_now()
        error: str | None = None
        reconciliation_phases: tuple[str, ...] = ()
        try:
            reconcile = getattr(self._executor, "reconcile_persistent_qspi", None)
            if original.transport is FirmwareTransport.SSH_FRM:
                if reconcile is None:
                    raise FirmwareIdentityError(
                        "ssh_frm executor has no read-only persistent reconciliation"
                    )
                if original.fit_sha256 is None or original.fit_size is None:
                    raise FirmwareIdentityError(
                        "legacy receipt has no FIT-body attestation target"
                    )
                raw_reconciliation_phases = reconcile(
                    original.radio,
                    expected_firmware=original.expected_firmware,
                    expected_fit_sha256=original.fit_sha256,
                    expected_fit_size=original.fit_size,
                )
                if not isinstance(raw_reconciliation_phases, (tuple, list)):
                    raise FirmwareIdentityError(
                        "SSH reconciliation phases are malformed"
                    )
                reconciliation_phases = tuple(
                    str(item) for item in raw_reconciliation_phases
                )
            observed = self.observe_identity(original.radio.serial)
            if observed.serial != original.radio.serial:
                raise FirmwareIdentityError("reconciled serial does not match the receipt")
            if original.transport is FirmwareTransport.USB:
                if observed.usb_sysfs_path != original.radio.usb_sysfs_path:
                    raise FirmwareIdentityError(
                        "reconciled USB path does not match the receipt"
                    )
            elif (
                observed.endpoint != original.radio.endpoint
            ):
                raise FirmwareIdentityError(
                    "reconciled network endpoint does not match the receipt"
                )
            if (
                original.expected_firmware is not None
                and observed.observed_firmware != original.expected_firmware
            ):
                raise FirmwareIdentityError(
                    f"reconciled firmware is {observed.observed_firmware!r}, "
                    f"expected {original.expected_firmware!r}"
                )
        except BaseException as caught:
            error = f"{type(caught).__name__}: {caught}"

        receipt = FirmwareReceipt(
            schema_version=2,
            receipt_id=uuid.uuid4().hex,
            plan_id=original.plan_id,
            started_at=started,
            finished_at=self._normalized_now(),
            radio=original.radio,
            mode=original.mode,
            transport=original.transport,
            image_sha256=original.image_sha256,
            image_size=original.image_size,
            fit_sha256=original.fit_sha256,
            fit_size=original.fit_size,
            expected_firmware=original.expected_firmware,
            outcome="success" if error is None else "failed",
            completed_phases=(
                *original.completed_phases,
                *reconciliation_phases,
                "read_only_reconciliation",
            ),
            failure_phase=None if error is None else "read_only_reconciliation",
            reconciliation_required=error is not None,
            reconciliation_of=original.receipt_id,
            evidence_reference=original.evidence_reference,
            success=error is None,
            error=error,
        )
        self._write_receipt(receipt)
        with self._receipt_lock:
            self._receipt_records[receipt.receipt_id] = receipt
        return receipt

    def _validate_transport_identity(self, identity: RadioFirmwareIdentity) -> None:
        if self.transport is FirmwareTransport.USB:
            if identity.usb_sysfs_path is None:
                raise FirmwareIdentityError("USB firmware identity requires a USB sysfs path")
            if identity.endpoint is not None or identity.host_key_fingerprint is not None:
                raise FirmwareIdentityError("USB firmware identity cannot include an SSH target")
            return
        if identity.usb_sysfs_path is not None:
            raise FirmwareIdentityError("ssh_frm identity cannot claim a USB sysfs path")
        if identity.endpoint is None or identity.host_key_fingerprint is None:
            raise FirmwareIdentityError(
                "ssh_frm identity requires an endpoint and pinned host-key fingerprint"
            )

    def _validate_ssh_execution_evidence(
        self, plan: FirmwarePlan
    ) -> tuple[tuple[str, ...], str, bool]:
        evidence = getattr(self._executor, "last_evidence", None)
        if evidence is None or str(getattr(evidence, "outcome", "")) != "verified":
            raise FirmwareIdentityError(
                "ssh_frm executor did not return complete verified evidence"
            )
        if getattr(evidence, "finished_at", None) is None:
            raise FirmwareIdentityError("ssh_frm evidence is not durably finalized")
        if (
            str(getattr(evidence, "frm_sha256", "")) != plan.image_sha256
            or int(getattr(evidence, "frm_size", -1)) != plan.image_size
            or str(getattr(evidence, "fit_sha256", "")) != plan.fit_sha256
            or int(getattr(evidence, "fit_size", -1)) != plan.fit_size
        ):
            raise FirmwareIdentityError("ssh_frm evidence hashes do not match the plan")
        qspi = getattr(evidence, "qspi", None)
        if (
            qspi is None
            or str(getattr(qspi, "fit_sha256", "")) != plan.fit_sha256
            or int(getattr(qspi, "fit_size", -1)) != plan.fit_size
        ):
            raise FirmwareIdentityError("ssh_frm MTD3 evidence does not match the FIT body")
        after = getattr(evidence, "after", None)
        if (
            after is None
            or str(getattr(after, "serial", "")) != plan.radio.serial
            or str(getattr(after, "endpoint", "")) != plan.radio.endpoint
            or str(getattr(after, "active_firmware", "")) != plan.expected_firmware
        ):
            raise FirmwareIdentityError(
                "ssh_frm post-reset identity or firmware does not match the plan"
            )
        raw_phases = getattr(evidence, "completed_phases", ())
        if not isinstance(raw_phases, (tuple, list)):
            raise FirmwareIdentityError("ssh_frm evidence phases are malformed")
        phases = tuple(str(item) for item in raw_phases)
        required = {
            "qspi_fit_verified",
            "reset_dispatched",
            "post_reset_attestation",
            "tx_safe_after_reset",
        }
        if not required.issubset(phases):
            raise FirmwareIdentityError("ssh_frm evidence is missing required safe phases")
        reference = str(getattr(evidence, "attempt_id", ""))
        if not reference:
            raise FirmwareIdentityError("ssh_frm evidence has no durable attempt reference")
        return (
            phases,
            reference,
            bool(getattr(evidence, "key_reconciliation_required", False)),
        )

    def _normalized_now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise ValueError("firmware clock must return a timezone-aware datetime")
        return value.astimezone(UTC)

    def _write_receipt(self, receipt: FirmwareReceipt) -> None:
        payload = asdict(receipt)
        payload["started_at"] = receipt.started_at.isoformat()
        payload["finished_at"] = receipt.finished_at.isoformat()
        payload["radio"] = asdict(receipt.radio)
        payload["mode"] = receipt.mode.value
        payload["transport"] = receipt.transport.value
        encoded = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
        self._filesystem.write_atomic(self._receipts / f"{receipt.receipt_id}.json", encoded)

    def _load_receipts(self) -> None:
        try:
            paths = tuple(self._receipts.glob("*.json"))
        except OSError:
            return
        for path in paths:
            try:
                document = json.loads(self._filesystem.read_bytes(path))
                if not isinstance(document, Mapping):
                    raise TypeError("firmware receipt must be an object")
                radio_document = document["radio"]
                if not isinstance(radio_document, Mapping):
                    raise TypeError("firmware receipt radio must be an object")
                success = bool(document["success"])
                raw_phases = document.get("completed_phases", [])
                if not isinstance(raw_phases, list):
                    raise TypeError("completed phases must be a list")
                outcome = str(document.get("outcome", "success" if success else "unknown"))
                if outcome not in {"success", "failed", "unknown"}:
                    raise ValueError("invalid firmware receipt outcome")
                transport = FirmwareTransport(str(document.get("transport", "usb")))
                receipt = FirmwareReceipt(
                    schema_version=int(document.get("schema_version", 1)),
                    receipt_id=str(document["receipt_id"]),
                    plan_id=str(document["plan_id"]),
                    started_at=datetime.fromisoformat(str(document["started_at"])),
                    finished_at=datetime.fromisoformat(str(document["finished_at"])),
                    radio=RadioFirmwareIdentity(
                        serial=str(radio_document["serial"]),
                        usb_sysfs_path=(
                            None
                            if radio_document.get("usb_sysfs_path") is None
                            else str(radio_document["usb_sysfs_path"])
                        ),
                        observed_firmware=str(radio_document["observed_firmware"]),
                        endpoint=(
                            None
                            if radio_document.get("endpoint") is None
                            else str(radio_document["endpoint"])
                        ),
                        host_key_fingerprint=(
                            None
                            if radio_document.get("host_key_fingerprint") is None
                            else str(radio_document["host_key_fingerprint"])
                        ),
                    ),
                    mode=FirmwareMode(str(document["mode"])),
                    transport=transport,
                    image_sha256=str(document["image_sha256"]),
                    image_size=int(document["image_size"]),
                    fit_sha256=(
                        None
                        if document.get("fit_sha256") is None
                        else str(document["fit_sha256"])
                    ),
                    fit_size=(
                        None
                        if document.get("fit_size") is None
                        else int(document["fit_size"])
                    ),
                    expected_firmware=(
                        None
                        if document.get("expected_firmware") is None
                        else str(document["expected_firmware"])
                    ),
                    outcome=outcome,  # type: ignore[arg-type]
                    completed_phases=tuple(str(item) for item in raw_phases),
                    failure_phase=(
                        None
                        if document.get("failure_phase") is None
                        else str(document["failure_phase"])
                    ),
                    reconciliation_required=bool(
                        document.get("reconciliation_required", not success)
                    ),
                    reconciliation_of=(
                        None
                        if document.get("reconciliation_of") is None
                        else str(document["reconciliation_of"])
                    ),
                    evidence_reference=(
                        None
                        if document.get("evidence_reference") is None
                        else str(document["evidence_reference"])
                    ),
                    success=success,
                    error=None if document.get("error") is None else str(document["error"]),
                )
            except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
                continue
            self._receipt_records[receipt.receipt_id] = receipt
