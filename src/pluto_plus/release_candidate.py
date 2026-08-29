"""Versioned contracts for owner-operated release-candidate RAM deployment.

These models deliberately contain no device I/O. They define the offline
candidate document, the per-radio no-hardware plan, and the durable semantic
receipt produced by the native lifecycle engine.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import re
import stat
import tempfile
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, Literal, TypeVar

from pydantic import Field, field_validator, model_validator

from pluto_plus.inventory import LocalUsbPluto
from pluto_plus.models import ApiModel

CANDIDATE_PLAN_SCHEMA: Literal["pluto-plus-utils.release-candidate-plan.v1"] = (
    "pluto-plus-utils.release-candidate-plan.v1"
)
OPERATION_PLAN_SCHEMA: Literal["pluto-plus-utils.release-candidate-operation-plan.v1"] = (
    "pluto-plus-utils.release-candidate-operation-plan.v1"
)
RAM_RECEIPT_SCHEMA: Literal["pluto-plus-utils.release-candidate-ram-receipt.v1"] = (
    "pluto-plus-utils.release-candidate-ram-receipt.v1"
)
RECOVERY_RECEIPT_SCHEMA: Literal["pluto-plus-utils.release-candidate-recovery-receipt.v1"] = (
    "pluto-plus-utils.release-candidate-recovery-receipt.v1"
)
USB_INVENTORY_SCHEMA: Literal["pluto-plus-utils.release-usb-inventory.v1"] = (
    "pluto-plus-utils.release-usb-inventory.v1"
)
MAX_CONTRACT_BYTES = 4 * 1024 * 1024

Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
SourceCommit = Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
Identifier = Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
Serial = Annotated[str, Field(pattern=r"^[A-Za-z0-9._:-]{1,128}$")]
Topology = Annotated[str, Field(pattern=r"^[0-9]+-[0-9]+(?:[.][0-9]+)*$")]
Interface = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")]
FirmwareVersion = Annotated[str, Field(min_length=1, max_length=256)]
HardwareModel = Annotated[str, Field(min_length=1, max_length=256)]
ContractModel = TypeVar("ContractModel", bound=ApiModel)


class ReleaseCandidateContractError(RuntimeError):
    """A retained release-candidate contract is unsafe or non-canonical."""


def _absolute_normalized(value: Path, *, label: str) -> Path:
    if not value.is_absolute() or ".." in value.parts:
        raise ValueError(f"{label} must be an absolute normalized path")
    return value


def _utc_timestamp(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
    if value.utcoffset() != UTC.utcoffset(value):
        raise ValueError(f"{label} must be expressed in UTC")
    return value


def _canonical_ipv4(value: str, *, label: str, require_private: bool = False) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise ValueError(f"{label} must be a canonical IPv4 address") from error
    if address.version != 4 or str(address) != value:
        raise ValueError(f"{label} must be a canonical IPv4 address")
    if require_private and not address.is_private:
        raise ValueError(f"{label} must be a private IPv4 address")
    return value


def _canonical_capabilities(value: tuple[str, ...]) -> tuple[str, ...]:
    if not value or len(set(value)) != len(value):
        raise ValueError("expected capabilities must be non-empty and unique")
    if value != tuple(sorted(value)):
        raise ValueError("expected capabilities must use canonical sorted order")
    if any(re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,63}", item) is None for item in value):
        raise ValueError("expected capability name is malformed")
    return value


class ContentIdentity(ApiModel):
    bytes: int = Field(gt=0)
    sha256: Sha256


class FileIdentity(ContentIdentity):
    path: Path

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: Path) -> Path:
        return _absolute_normalized(value, label="file identity path")


class DfuIdentity(ApiModel):
    vendor_id: Literal["0456"] = "0456"
    runtime_product_id: Literal["b673"] = "b673"
    dfu_product_id: Literal["b674"] = "b674"
    selector: Literal["0456:b673,0456:b674"] = "0456:b673,0456:b674"
    alternate: Literal["firmware.dfu"] = "firmware.dfu"


class ExpectedRuntime(ApiModel):
    firmware_version: FirmwareVersion
    hardware_model: HardwareModel
    metadata_abi: Annotated[str, Field(pattern=r"^frame-metadata-v[1-9][0-9]*$")]
    capabilities: tuple[str, ...]

    @field_validator("capabilities")
    @classmethod
    def validate_capabilities(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _canonical_capabilities(value)


class ReleaseCandidatePlan(ApiModel):
    schema_id: Literal["pluto-plus-utils.release-candidate-plan.v1"] = Field(
        CANDIDATE_PLAN_SCHEMA, alias="schema"
    )
    schema_version: Literal[1] = 1
    candidate_id: Identifier
    created_at: datetime
    source_repository: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")]
    source_commit: SourceCommit
    device_tool_repository: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")]
    device_tool_version: Annotated[str, Field(min_length=1, max_length=128)]
    device_tool_source_commit: SourceCommit
    artifact_index: FileIdentity
    dfu: FileIdentity
    fit: ContentIdentity
    expected_runtime: ExpectedRuntime
    dfu_identity: DfuIdentity = Field(default_factory=DfuIdentity)
    allowed_operation: Literal["ram-only"] = "ram-only"

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, value: datetime) -> datetime:
        return _utc_timestamp(value, label="candidate creation time")

    @model_validator(mode="after")
    def validate_relationships(self) -> ReleaseCandidatePlan:
        if self.fit.bytes >= self.dfu.bytes:
            raise ValueError("FIT body must be smaller than its DFU container")
        if self.dfu.path == self.artifact_index.path:
            raise ValueError("candidate DFU and artifact index must be distinct files")
        return self


class UsbInventoryTarget(ApiModel):
    serial: Serial
    topology: Topology
    sysfs_path: Path
    vendor_id: Literal["0456"] = "0456"
    product_id: Literal["b673"] = "b673"
    bus_number: int = Field(gt=0)
    device_number: int = Field(gt=0)
    network_interface: Interface
    source_ipv4: str

    @field_validator("sysfs_path")
    @classmethod
    def validate_sysfs_path(cls, value: Path) -> Path:
        return _absolute_normalized(value, label="USB sysfs path")

    @field_validator("source_ipv4")
    @classmethod
    def validate_source_ipv4(cls, value: str) -> str:
        return _canonical_ipv4(value, label="USB host source", require_private=True)

    @model_validator(mode="after")
    def validate_topology_path(self) -> UsbInventoryTarget:
        if self.sysfs_path != Path("/sys/bus/usb/devices") / self.topology:
            raise ValueError("USB sysfs path does not match the direct topology")
        return self


class ReleaseUsbInventory(ApiModel):
    schema_id: Literal["pluto-plus-utils.release-usb-inventory.v1"] = Field(
        USB_INVENTORY_SCHEMA, alias="schema"
    )
    schema_version: Literal[1] = 1
    created_at: datetime
    devices: tuple[UsbInventoryTarget, ...]

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, value: datetime) -> datetime:
        return _utc_timestamp(value, label="USB-inventory creation time")

    @field_validator("devices")
    @classmethod
    def validate_devices(
        cls, value: tuple[UsbInventoryTarget, ...]
    ) -> tuple[UsbInventoryTarget, ...]:
        if not value:
            raise ValueError("release USB inventory must contain at least one device")
        serials = tuple(device.serial for device in value)
        topologies = tuple(device.topology for device in value)
        if len(set(serials)) != len(serials):
            raise ValueError("release USB inventory contains duplicate serials")
        if len(set(topologies)) != len(topologies):
            raise ValueError("release USB inventory contains duplicate topologies")
        if value != tuple(sorted(value, key=lambda device: (device.serial, device.topology))):
            raise ValueError("release USB inventory must use canonical serial order")
        return value


class ReleaseCandidateOperationPlan(ApiModel):
    schema_id: Literal["pluto-plus-utils.release-candidate-operation-plan.v1"] = Field(
        OPERATION_PLAN_SCHEMA, alias="schema"
    )
    schema_version: Literal[1] = 1
    plan_id: Identifier
    created_at: datetime
    candidate_plan: FileIdentity
    usb_inventory: FileIdentity
    target: UsbInventoryTarget
    expected_current_firmware: FirmwareVersion
    ssh_host: str = "192.168.2.1"
    receipt_path: Path
    confirmation_phrase: str
    hardware_accessed: Literal[False] = False

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, value: datetime) -> datetime:
        return _utc_timestamp(value, label="operation-plan creation time")

    @field_validator("ssh_host")
    @classmethod
    def validate_ssh_host(cls, value: str) -> str:
        return _canonical_ipv4(value, label="SSH host", require_private=True)

    @field_validator("receipt_path")
    @classmethod
    def validate_receipt_path(cls, value: Path) -> Path:
        return _absolute_normalized(value, label="receipt path")

    @model_validator(mode="after")
    def validate_relationships(self) -> ReleaseCandidateOperationPlan:
        if self.ssh_host == self.target.source_ipv4:
            raise ValueError("SSH host and local source address must differ")
        expected = f"RAM BOOT RELEASE CANDIDATE {self.target.serial}"
        if self.confirmation_phrase != expected:
            raise ValueError(f"confirmation phrase must be exactly {expected!r}")
        if self.candidate_plan.path == self.usb_inventory.path:
            raise ValueError("candidate plan and USB inventory must be distinct files")
        return self


class SafeState(ApiModel):
    tx_gain_db: tuple[float, float]
    dds_raw: tuple[int, int, int, int, int, int, int, int]
    dds_scale: tuple[float, float, float, float, float, float, float, float]
    dac_selectors: tuple[int, int, int, int]
    tandem_state: Literal["IDLE"]
    fifo_level: Literal[0]
    fault_flags: Literal[0]

    @model_validator(mode="after")
    def validate_safe_values(self) -> SafeState:
        if any(not math.isfinite(value) or value > -80.0 for value in self.tx_gain_db):
            raise ValueError("both TX gains must be finite and at or below -80 dB")
        if any(value != 0 for value in self.dds_raw):
            raise ValueError("every DDS raw value must be zero")
        if any(not math.isfinite(value) or value != 0.0 for value in self.dds_scale):
            raise ValueError("every DDS scale must be finite and zero")
        if self.dac_selectors != (3, 3, 3, 3):
            raise ValueError("every DAC selector must select the safe zero source")
        return self


class QspiObservation(ApiModel):
    partition: Literal["/dev/mtdblock3"] = "/dev/mtdblock3"
    mtd_name: Literal["qspi-linux"] = "qspi-linux"
    bytes: int = Field(gt=0)
    sha256: Sha256


class RuntimeObservation(ApiModel):
    serial: Serial
    topology: Topology
    usb_uri: Annotated[str, Field(pattern=r"^usb:[0-9]+[.][0-9]+[.][0-9]+$")]
    hardware_model: HardwareModel
    firmware_version: FirmwareVersion
    metadata_abi: Annotated[str, Field(pattern=r"^frame-metadata-v[1-9][0-9]*$")]
    capabilities: tuple[str, ...]
    boot_id: Annotated[
        str,
        Field(
            pattern=(
                r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
                r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
            )
        ),
    ]
    qspi: QspiObservation
    safe_state: SafeState

    @field_validator("capabilities")
    @classmethod
    def validate_capabilities(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _canonical_capabilities(value)


class HostRouteReceipt(ApiModel):
    destination: Annotated[str, Field(pattern=r"^[0-9]+(?:[.][0-9]+){3}/32$")]
    interface: Interface
    source: str
    release_verified: bool

    @field_validator("destination")
    @classmethod
    def validate_destination(cls, value: str) -> str:
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as error:
            raise ValueError("host-route destination must be canonical IPv4 /32") from error
        if network.version != 4 or network.prefixlen != 32 or str(network) != value:
            raise ValueError("host-route destination must be canonical IPv4 /32")
        return value

    @field_validator("source")
    @classmethod
    def validate_source(cls, value: str) -> str:
        return _canonical_ipv4(value, label="host-route source", require_private=True)


class TransitionReceipt(ApiModel):
    method: Literal["download-then-detach-e"] = "download-then-detach-e"
    selector: Literal["0456:b673,0456:b674"] = "0456:b673,0456:b674"
    topology: Topology
    alternate: Literal["firmware.dfu"] = "firmware.dfu"
    sealed_input: bool
    download_completed: bool
    detach_completed: bool
    persistent_write: Literal[False] = False


class CleanupReceipt(ApiModel):
    verified: bool
    errors: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_errors(self) -> CleanupReceipt:
        if self.verified and self.errors:
            raise ValueError("verified cleanup cannot contain errors")
        if not self.verified and not self.errors:
            raise ValueError("unverified cleanup must explain at least one error")
        return self


class ReleaseCandidateRamReceipt(ApiModel):
    schema_id: Literal["pluto-plus-utils.release-candidate-ram-receipt.v1"] = Field(
        RAM_RECEIPT_SCHEMA, alias="schema"
    )
    schema_version: Literal[1] = 1
    receipt_id: Identifier
    outcome: Literal["pass", "failed", "unknown"]
    started_at: datetime
    completed_at: datetime
    tool_repository: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")]
    tool_version: Annotated[str, Field(min_length=1, max_length=128)]
    tool_source_commit: SourceCommit
    operation_plan: FileIdentity
    candidate_plan: FileIdentity
    candidate_dfu: ContentIdentity
    candidate_fit: ContentIdentity
    target: UsbInventoryTarget
    expected_firmware: FirmwareVersion
    expected_hardware_model: HardwareModel
    expected_metadata_abi: Annotated[str, Field(pattern=r"^frame-metadata-v[1-9][0-9]*$")]
    required_capabilities: tuple[str, ...]
    pre_runtime: RuntimeObservation | None
    post_runtime: RuntimeObservation | None
    host_route: HostRouteReceipt
    transition: TransitionReceipt
    cleanup: CleanupReceipt
    failure_phase: str | None = None
    error: str | None = None

    @field_validator("started_at", "completed_at")
    @classmethod
    def validate_timestamps(cls, value: datetime) -> datetime:
        return _utc_timestamp(value, label="receipt timestamp")

    @field_validator("required_capabilities")
    @classmethod
    def validate_capabilities(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _canonical_capabilities(value)

    @model_validator(mode="after")
    def validate_relationships(self) -> ReleaseCandidateRamReceipt:
        if self.completed_at < self.started_at:
            raise ValueError("receipt completion precedes its start")
        if self.operation_plan.path == self.candidate_plan.path:
            raise ValueError("operation and candidate plan files must be distinct")
        if self.candidate_fit.bytes >= self.candidate_dfu.bytes:
            raise ValueError("receipt FIT body must be smaller than its DFU container")
        for runtime in (self.pre_runtime, self.post_runtime):
            if runtime is not None and (
                runtime.serial != self.target.serial or runtime.topology != self.target.topology
            ):
                raise ValueError("runtime observation does not match the target")
        if self.transition.topology != self.target.topology:
            raise ValueError("transition topology does not match the target")
        if self.host_route.interface != self.target.network_interface:
            raise ValueError("host route interface does not match the target")
        if self.host_route.source != self.target.source_ipv4:
            raise ValueError("host route source does not match the target")
        if self.outcome == "pass":
            if self.pre_runtime is None or self.post_runtime is None:
                raise ValueError("passing receipt requires pre/post runtime observations")
            if self.post_runtime.hardware_model != self.expected_hardware_model:
                raise ValueError("postboot hardware model does not match the candidate")
            if self.pre_runtime.hardware_model != self.post_runtime.hardware_model:
                raise ValueError("hardware model changed across RAM boot")
            if self.post_runtime.firmware_version != self.expected_firmware:
                raise ValueError("postboot firmware does not match the candidate")
            if self.post_runtime.metadata_abi != self.expected_metadata_abi:
                raise ValueError("postboot metadata ABI does not match the candidate")
            if self.post_runtime.capabilities != self.required_capabilities:
                raise ValueError("postboot capabilities do not match the candidate")
            if self.pre_runtime.boot_id == self.post_runtime.boot_id:
                raise ValueError("passing RAM boot requires a new boot ID")
            if self.pre_runtime.qspi != self.post_runtime.qspi:
                raise ValueError("passing RAM boot requires unchanged qspi-linux bytes")
            if not (
                self.host_route.release_verified
                and self.transition.sealed_input
                and self.transition.download_completed
                and self.transition.detach_completed
                and self.cleanup.verified
            ):
                raise ValueError("passing receipt lacks completed transition or cleanup")
            if self.failure_phase is not None or self.error is not None:
                raise ValueError("passing receipt cannot contain a failure")
        elif self.failure_phase is None or self.error is None:
            raise ValueError("non-passing receipt must identify its failure")
        return self


class ReleaseCandidateRecoveryReceipt(ApiModel):
    schema_id: Literal["pluto-plus-utils.release-candidate-recovery-receipt.v1"] = Field(
        RECOVERY_RECEIPT_SCHEMA, alias="schema"
    )
    schema_version: Literal[1] = 1
    recovery_id: Identifier
    started_at: datetime
    completed_at: datetime
    tool_repository: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")]
    tool_version: Annotated[str, Field(min_length=1, max_length=128)]
    tool_source_commit: SourceCommit
    source_receipt: FileIdentity
    operation_plan: FileIdentity
    candidate_plan: FileIdentity
    target: UsbInventoryTarget
    pre_runtime: RuntimeObservation
    recovered_runtime: RuntimeObservation
    expected_return_firmware: FirmwareVersion
    host_route: HostRouteReceipt
    recovery_action: Literal["dfu-detach-e", "runtime-attestation"]
    dfu_detach_completed: bool
    persistent_write: Literal[False] = False
    qspi_unchanged: Literal[True] = True
    cleanup: CleanupReceipt

    @field_validator("started_at", "completed_at")
    @classmethod
    def validate_timestamps(cls, value: datetime) -> datetime:
        return _utc_timestamp(value, label="recovery receipt timestamp")

    @model_validator(mode="after")
    def validate_relationships(self) -> ReleaseCandidateRecoveryReceipt:
        if self.completed_at < self.started_at:
            raise ValueError("recovery completion precedes its start")
        if self.source_receipt.path in {
            self.operation_plan.path,
            self.candidate_plan.path,
        }:
            raise ValueError("recovery inputs must be distinct files")
        if self.operation_plan.path == self.candidate_plan.path:
            raise ValueError("operation and candidate plan files must be distinct")
        if (
            self.pre_runtime.serial != self.target.serial
            or self.recovered_runtime.serial != self.target.serial
        ):
            raise ValueError("recovery runtime serial does not match the target")
        if (
            self.pre_runtime.topology != self.target.topology
            or self.recovered_runtime.topology != self.target.topology
        ):
            raise ValueError("recovery runtime topology does not match the target")
        if self.recovered_runtime.firmware_version != self.expected_return_firmware:
            raise ValueError("recovered firmware does not match the expected return")
        if self.pre_runtime.hardware_model != self.recovered_runtime.hardware_model:
            raise ValueError("hardware model changed during recovery")
        if self.pre_runtime.boot_id == self.recovered_runtime.boot_id:
            raise ValueError("DFU recovery requires a new runtime boot ID")
        if self.pre_runtime.qspi != self.recovered_runtime.qspi:
            raise ValueError("DFU recovery requires unchanged qspi-linux bytes")
        if self.dfu_detach_completed != (self.recovery_action == "dfu-detach-e"):
            raise ValueError("recovery action and DFU detach verdict disagree")
        if not self.host_route.release_verified:
            raise ValueError("recovery host route release is not verified")
        if (
            self.host_route.interface != self.target.network_interface
            or self.host_route.source != self.target.source_ipv4
        ):
            raise ValueError("recovery host route does not match the target")
        if not self.cleanup.verified:
            raise ValueError("recovery cleanup is not verified")
        return self


ReleaseContract = (
    ReleaseCandidatePlan
    | ReleaseCandidateOperationPlan
    | ReleaseCandidateRamReceipt
    | ReleaseCandidateRecoveryReceipt
)


def canonical_json_bytes(value: ApiModel | dict[str, Any]) -> bytes:
    """Return one deterministic newline-terminated JSON representation."""

    payload = value.model_dump(mode="json", by_alias=True) if isinstance(value, ApiModel) else value
    return (
        json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode("utf-8")


def model_file_identity(path: Path, value: ApiModel) -> FileIdentity:
    """Return the identity of the exact canonical bytes for one contract model."""

    data = canonical_json_bytes(value)
    return FileIdentity(path=path, bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def _json_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ReleaseCandidateContractError(
                f"release-candidate JSON contains duplicate key {key!r}"
            )
        value[key] = item
    return value


def _stable_file_identity(value: os.stat_result) -> tuple[int, ...]:
    """Return metadata that must remain stable while one contract is read."""

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


def load_private_contract(path: Path, model: type[ContractModel]) -> ContractModel:
    """Read one exact owned mode-0600 canonical contract without following links."""

    selected = _absolute_normalized(path, label="contract path")
    try:
        before = selected.lstat()
    except OSError as error:
        raise ReleaseCandidateContractError(f"contract is not readable: {error}") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.getuid()
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > MAX_CONTRACT_BYTES
    ):
        raise ReleaseCandidateContractError(
            "contract must be one owned mode-0600 regular file with one link"
        )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(selected, flags)
    except OSError as error:
        raise ReleaseCandidateContractError(f"contract cannot be opened safely: {error}") from error
    try:
        opened = os.fstat(descriptor)
        opened_identity = _stable_file_identity(opened)
        if opened_identity != _stable_file_identity(before):
            raise ReleaseCandidateContractError("contract changed while it was opened")
        data = bytearray()
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1 << 20))
            if not chunk:
                raise ReleaseCandidateContractError("contract was truncated during read")
            data.extend(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ReleaseCandidateContractError("contract grew during read")
        if _stable_file_identity(os.fstat(descriptor)) != opened_identity:
            raise ReleaseCandidateContractError("contract changed during read")
    finally:
        os.close(descriptor)
    try:
        document = json.loads(
            bytes(data).decode("utf-8"),
            object_pairs_hook=_json_no_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ReleaseCandidateContractError(
                    f"release-candidate JSON contains non-finite value {value}"
                )
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseCandidateContractError("contract is not valid UTF-8 JSON") from error
    if not isinstance(document, dict):
        raise ReleaseCandidateContractError("contract root must be a JSON object")
    parsed = model.model_validate(document)
    if canonical_json_bytes(parsed) != bytes(data):
        raise ReleaseCandidateContractError("contract bytes are not canonical JSON")
    return parsed


def write_private_contract(path: Path, value: ApiModel) -> FileIdentity:
    """Atomically publish an absent-only canonical contract beneath an owned 0700 parent."""

    selected = _absolute_normalized(path, label="contract path")
    parent = selected.parent
    try:
        parent_state = parent.lstat()
    except OSError as error:
        raise ReleaseCandidateContractError(f"contract parent is unavailable: {error}") from error
    if (
        not stat.S_ISDIR(parent_state.st_mode)
        or parent_state.st_uid != os.getuid()
        or stat.S_IMODE(parent_state.st_mode) != 0o700
    ):
        raise ReleaseCandidateContractError("contract parent must be an owned mode-0700 directory")
    payload = canonical_json_bytes(value)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{selected.name}.", dir=parent)
    temporary = Path(temporary_name)
    opened = False
    published = False
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            opened = True
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, selected, follow_symlinks=False)
        except FileExistsError as error:
            raise ReleaseCandidateContractError("contract destination already exists") from error
        published = True
        temporary.unlink()
        directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        if not opened:
            os.close(descriptor)
        if published:
            selected.unlink(missing_ok=True)
        temporary.unlink(missing_ok=True)
        raise
    return model_file_identity(selected, value)


def build_release_usb_inventory(
    devices: Sequence[LocalUsbPluto], *, created_at: datetime
) -> ReleaseUsbInventory:
    """Convert one read-only runtime scan into the strict release snapshot."""

    targets: list[UsbInventoryTarget] = []
    for device in devices:
        if not device.confirmed_plus:
            raise ValueError("release USB inventory requires a confirmed Pluto+")
        if not device.serial:
            raise ValueError("release USB inventory requires a stable serial")
        if device.bus_number is None or device.device_number is None:
            raise ValueError("release USB inventory requires positive bus/device numbers")
        if len(device.host_network_interfaces) != 1:
            raise ValueError("release USB inventory requires one network interface per radio")
        interface = device.host_network_interfaces[0]
        if len(interface.ipv4_addresses) != 1:
            raise ValueError("release USB inventory requires one host IPv4 per radio")
        path = Path(device.usb_path)
        targets.append(
            UsbInventoryTarget(
                serial=device.serial,
                topology=path.name,
                sysfs_path=path,
                bus_number=device.bus_number,
                device_number=device.device_number,
                network_interface=interface.name,
                source_ipv4=interface.ipv4_addresses[0],
            )
        )
    return ReleaseUsbInventory(
        schema=USB_INVENTORY_SCHEMA,
        created_at=created_at,
        devices=tuple(sorted(targets, key=lambda target: (target.serial, target.topology))),
    )


def build_operation_plan(
    candidate: ReleaseCandidatePlan,
    inventory: ReleaseUsbInventory,
    *,
    candidate_path: Path,
    inventory_path: Path,
    serial: str,
    expected_current_firmware: str,
    receipt_path: Path,
    plan_id: str,
    created_at: datetime,
    ssh_host: str = "192.168.2.1",
) -> ReleaseCandidateOperationPlan:
    """Build one deterministic no-hardware operation plan from retained files."""

    matches = tuple(device for device in inventory.devices if device.serial == serial)
    if len(matches) != 1:
        raise ValueError("expected one release USB inventory device for the serial")
    return ReleaseCandidateOperationPlan(
        schema=OPERATION_PLAN_SCHEMA,
        plan_id=plan_id,
        created_at=created_at,
        candidate_plan=model_file_identity(candidate_path, candidate),
        usb_inventory=model_file_identity(inventory_path, inventory),
        target=matches[0],
        expected_current_firmware=expected_current_firmware,
        ssh_host=ssh_host,
        receipt_path=receipt_path,
        confirmation_phrase=f"RAM BOOT RELEASE CANDIDATE {serial}",
        hardware_accessed=False,
    )


def validate_contract_bundle(
    candidate: ReleaseCandidatePlan,
    operation: ReleaseCandidateOperationPlan,
    receipt: ReleaseCandidateRamReceipt,
    *,
    candidate_path: Path,
    operation_path: Path,
) -> None:
    """Prove semantic and byte-identity coherence across the three contracts."""

    candidate_identity = model_file_identity(candidate_path, candidate)
    operation_identity = model_file_identity(operation_path, operation)
    if operation.candidate_plan != candidate_identity:
        raise ValueError("operation plan does not bind the exact candidate plan bytes")
    if receipt.candidate_plan != candidate_identity:
        raise ValueError("receipt does not bind the exact candidate plan bytes")
    if receipt.operation_plan != operation_identity:
        raise ValueError("receipt does not bind the exact operation plan bytes")
    if receipt.target != operation.target:
        raise ValueError("receipt target does not match the operation plan")
    if (
        receipt.tool_repository != candidate.device_tool_repository
        or receipt.tool_version != candidate.device_tool_version
        or receipt.tool_source_commit != candidate.device_tool_source_commit
    ):
        raise ValueError("receipt device tool identity does not match the candidate plan")
    if receipt.pre_runtime is not None and (
        receipt.pre_runtime.firmware_version != operation.expected_current_firmware
    ):
        raise ValueError("preboot firmware does not match the operation plan")
    if receipt.candidate_dfu != ContentIdentity(
        bytes=candidate.dfu.bytes, sha256=candidate.dfu.sha256
    ):
        raise ValueError("receipt DFU identity does not match the candidate plan")
    if receipt.candidate_fit != candidate.fit:
        raise ValueError("receipt FIT identity does not match the candidate plan")
    expected = candidate.expected_runtime
    if (
        receipt.expected_firmware != expected.firmware_version
        or receipt.expected_hardware_model != expected.hardware_model
        or receipt.expected_metadata_abi != expected.metadata_abi
        or receipt.required_capabilities != expected.capabilities
    ):
        raise ValueError("receipt expected runtime does not match the candidate plan")
    expected_destination = f"{operation.ssh_host}/32"
    if receipt.host_route.destination != expected_destination:
        raise ValueError("receipt host route does not match the operation plan")
