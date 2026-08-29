"""Guarded RAM-only deployment of the immutable approved-v7 comparator.

This module intentionally has its own plan and receipt contracts.  The
release-candidate contracts are not relabeled or translated into comparator
evidence.  Live Linux mechanics are delegated to the same exact-radio backend
used by the release-candidate lifecycle so route, lock, DFU, and safe-state
behavior cannot drift.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import stat
import subprocess
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, cast

from pydantic import Field, field_validator, model_validator

from pluto_plus.firmware import FirmwareImageError, validate_dfu
from pluto_plus.models import ApiModel
from pluto_plus.release_candidate import (
    CleanupReceipt,
    ContentIdentity,
    DfuIdentity,
    ExpectedRuntime,
    FileIdentity,
    HostRouteReceipt,
    ReleaseUsbInventory,
    RuntimeObservation,
    Sha256,
    SourceCommit,
    UsbInventoryTarget,
    load_private_contract,
    model_file_identity,
    write_private_contract,
)
from pluto_plus.release_candidate_lifecycle import (
    PasswordFileIdentity,
    ReleaseCandidateRamBackend,
    ssh_fixed_argv,
    validate_password_file,
)
from pluto_plus.release_candidate_linux import attest_clean_tool_repository

COMPARATOR_PLAN_SCHEMA: Literal["pluto-plus-utils.comparator-ram-plan.v1"] = (
    "pluto-plus-utils.comparator-ram-plan.v1"
)
COMPARATOR_RECEIPT_SCHEMA: Literal["pluto-plus-utils.comparator-ram-receipt.v1"] = (
    "pluto-plus-utils.comparator-ram-receipt.v1"
)

APPROVED_V7_PROFILE_ID = "tandem-agc-v7-release-ram"
APPROVED_V7_RELEASE_TAG = "v0.40-plutoplus-spf-tandem-agc-v7"
APPROVED_V7_FIRMWARE = "v0.40-plutoplus-spf-tandem-agc-v7"
APPROVED_V7_SOURCE_REPOSITORY = "misko/plutosdr-fw"
APPROVED_V7_SOURCE_COMMIT = "e0049c2d0077770eeb1f6850b957878a373623d9"
APPROVED_V7_BUNDLE_NAME = "plutoplus-spf-tandem-agc-v2-e0049c2d0077.tar.gz"
APPROVED_V7_BUNDLE_BYTES = 104_855_551
APPROVED_V7_BUNDLE_SHA256 = "5468827aa7eca6badd69a518df6bf70ef4220e3f39cdca66b7ba8e3fb452fbb4"
APPROVED_V7_DFU_NAME = "plutoplus-spf-tandem-agc-v2-e0049c2d0077-pluto.dfu"
APPROVED_V7_DFU_BYTES = 12_776_839
APPROVED_V7_DFU_SHA256 = "4fe286f9756e3c721d5322ba9c18831f43ab4678c34bb9ef7f238cbb1236debe"
APPROVED_V7_FIT_BYTES = 12_776_823
APPROVED_V7_FIT_SHA256 = "4c19876d09082adfdbd255726e84be397eb4e18a4c0d96b9722d7d543c2ebae7"

APPROVED_V7_HARNESS_REPOSITORY = "misko/pluto-plus-utils"
APPROVED_V7_HARNESS_COMMIT = "6ebb7aab092468cb89e75191190d7db5262f6801"
APPROVED_V7_HARNESS_MODULE = "src/pluto_plus/tandem_qualification.py"
APPROVED_V7_HARNESS_MODULE_SHA256 = (
    "57e95a6e96374f118e9801d01f644c6fa0b051f44eef71d906e441e616dad44f"
)
APPROVED_V7_HARNESS_CLI = "src/pluto_plus/cli.py"
APPROVED_V7_HARNESS_CLI_SHA256 = "7765d7f7b2e5a71a275b78f888d448b2a34284b75e56905b5118ff0ad6fde178"
APPROVED_V7_FREQUENCIES_HZ = (915_000_000, 2_450_000_000, 5_800_000_000)
APPROVED_V7_STRONG_TX_GAIN_DB = -10.0
APPROVED_V7_WEAK_TX_GAIN_DB = -60.0

DFU_SELECTOR = "0456:b673,0456:b674"
DFU_ALTERNATE = "firmware.dfu"
REMOTE_RAM_COMMAND = "/usr/sbin/device_reboot ram"
COMPARATOR_WRAPPER_RELATIVE = Path("src/pluto_plus/comparator_ram.py")
MAX_PLAN_LIFETIME = timedelta(minutes=30)
MAX_ARTIFACT_BYTES = 256 * 1024 * 1024

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ComparatorRamError(RuntimeError):
    """Comparator planning, execution, or semantic replay failed."""

    def __init__(
        self,
        message: str,
        *,
        receipt: ComparatorRamReceipt | None = None,
        receipt_sha256: str | None = None,
    ) -> None:
        super().__init__(message)
        self.receipt = receipt
        self.receipt_sha256 = receipt_sha256


def _absolute_path(value: Path, *, label: str) -> Path:
    if not value.is_absolute() or ".." in value.parts:
        raise ValueError(f"{label} must be an absolute normalized path")
    return value


def _utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
        raise ValueError(f"{label} must be expressed in UTC")
    return value


class ComparatorToolIdentity(ApiModel):
    repository: Literal["misko/pluto-plus-utils"] = "misko/pluto-plus-utils"
    repository_path: Path
    version: str = Field(min_length=1, max_length=128)
    source_commit: SourceCommit
    source_tree_sha256: Sha256
    execution_wrapper: FileIdentity

    @field_validator("repository_path")
    @classmethod
    def validate_repository_path(cls, value: Path) -> Path:
        return _absolute_path(value, label="tool repository path")

    @model_validator(mode="after")
    def validate_wrapper_path(self) -> ComparatorToolIdentity:
        expected = self.repository_path / COMPARATOR_WRAPPER_RELATIVE
        if self.execution_wrapper.path != expected:
            raise ValueError("comparator wrapper is not the exact tool source path")
        return self


class ApprovedV7HarnessIdentity(ApiModel):
    repository: Literal["misko/pluto-plus-utils"] = "misko/pluto-plus-utils"
    source_commit: Literal["6ebb7aab092468cb89e75191190d7db5262f6801"] = (
        "6ebb7aab092468cb89e75191190d7db5262f6801"
    )
    command: Literal["radio qualify-tandem"] = "radio qualify-tandem"
    module_path: Literal["src/pluto_plus/tandem_qualification.py"] = (
        "src/pluto_plus/tandem_qualification.py"
    )
    module_sha256: Literal["57e95a6e96374f118e9801d01f644c6fa0b051f44eef71d906e441e616dad44f"] = (
        "57e95a6e96374f118e9801d01f644c6fa0b051f44eef71d906e441e616dad44f"
    )
    cli_path: Literal["src/pluto_plus/cli.py"] = "src/pluto_plus/cli.py"
    cli_sha256: Literal["7765d7f7b2e5a71a275b78f888d448b2a34284b75e56905b5118ff0ad6fde178"] = (
        "7765d7f7b2e5a71a275b78f888d448b2a34284b75e56905b5118ff0ad6fde178"
    )
    frequencies_hz: tuple[int, ...] = APPROVED_V7_FREQUENCIES_HZ
    strong_tx_gain_db: float = APPROVED_V7_STRONG_TX_GAIN_DB
    weak_tx_gain_db: float = APPROVED_V7_WEAK_TX_GAIN_DB

    @field_validator("frequencies_hz")
    @classmethod
    def validate_frequencies(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        if value != APPROVED_V7_FREQUENCIES_HZ:
            raise ValueError("approved-v7 comparator frequencies are not exact")
        return value

    @model_validator(mode="after")
    def validate_gains(self) -> ApprovedV7HarnessIdentity:
        if (
            self.strong_tx_gain_db != APPROVED_V7_STRONG_TX_GAIN_DB
            or self.weak_tx_gain_db != APPROVED_V7_WEAK_TX_GAIN_DB
        ):
            raise ValueError("approved-v7 comparator TX gains are not exact")
        return self


class ApprovedV7Artifact(ApiModel):
    profile_id: Literal["tandem-agc-v7-release-ram"] = "tandem-agc-v7-release-ram"
    release_tag: Literal["v0.40-plutoplus-spf-tandem-agc-v7"] = "v0.40-plutoplus-spf-tandem-agc-v7"
    source_repository: Literal["misko/plutosdr-fw"] = "misko/plutosdr-fw"
    source_commit: Literal["e0049c2d0077770eeb1f6850b957878a373623d9"] = (
        "e0049c2d0077770eeb1f6850b957878a373623d9"
    )
    retained_bundle: FileIdentity
    dfu: FileIdentity
    fit: ContentIdentity

    @model_validator(mode="after")
    def validate_immutable_artifact(self) -> ApprovedV7Artifact:
        if (
            self.retained_bundle.path.name != APPROVED_V7_BUNDLE_NAME
            or self.retained_bundle.bytes != APPROVED_V7_BUNDLE_BYTES
            or self.retained_bundle.sha256 != APPROVED_V7_BUNDLE_SHA256
        ):
            raise ValueError("retained approved-v7 bundle identity is not exact")
        if (
            self.dfu.path.name != APPROVED_V7_DFU_NAME
            or self.dfu.bytes != APPROVED_V7_DFU_BYTES
            or self.dfu.sha256 != APPROVED_V7_DFU_SHA256
        ):
            raise ValueError("retained approved-v7 DFU identity is not exact")
        if self.fit != ContentIdentity(bytes=APPROVED_V7_FIT_BYTES, sha256=APPROVED_V7_FIT_SHA256):
            raise ValueError("retained approved-v7 FIT identity is not exact")
        if self.retained_bundle.path.parent != self.dfu.path.parent:
            raise ValueError("retained approved-v7 bundle and DFU must share one archive root")
        return self


class ComparatorRamPlan(ApiModel):
    schema_id: Literal["pluto-plus-utils.comparator-ram-plan.v1"] = Field(
        COMPARATOR_PLAN_SCHEMA, alias="schema"
    )
    schema_version: Literal[1] = 1
    plan_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    created_at: datetime
    expires_at: datetime
    tool: ComparatorToolIdentity
    artifact: ApprovedV7Artifact
    harness: ApprovedV7HarnessIdentity = Field(default_factory=ApprovedV7HarnessIdentity)
    usb_inventory: FileIdentity
    target: UsbInventoryTarget
    expected_current_runtime: ExpectedRuntime
    expected_runtime: ExpectedRuntime
    ssh_host: str = "192.168.2.1"
    receipt_path: Path
    confirmation_phrase: str
    dfu_identity: DfuIdentity = Field(default_factory=DfuIdentity)
    allowed_operation: Literal["ram-only"] = "ram-only"
    hardware_accessed: Literal[False] = False

    @field_validator("created_at", "expires_at")
    @classmethod
    def validate_timestamp(cls, value: datetime) -> datetime:
        return _utc(value, label="comparator plan timestamp")

    @field_validator("receipt_path")
    @classmethod
    def validate_receipt_path(cls, value: Path) -> Path:
        return _absolute_path(value, label="comparator receipt path")

    @field_validator("ssh_host")
    @classmethod
    def validate_ssh_host(cls, value: str) -> str:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as error:
            raise ValueError("comparator SSH host must be a canonical private IPv4") from error
        if address.version != 4 or str(address) != value or not address.is_private:
            raise ValueError("comparator SSH host must be a canonical private IPv4")
        return value

    @model_validator(mode="after")
    def validate_relationships(self) -> ComparatorRamPlan:
        lifetime = self.expires_at - self.created_at
        if lifetime <= timedelta(0) or lifetime > MAX_PLAN_LIFETIME:
            raise ValueError("comparator plan lifetime must be positive and at most 30 minutes")
        if self.ssh_host == self.target.source_ipv4:
            raise ValueError("SSH host and local source address must differ")
        expected_confirmation = f"COMPARATOR RAM BOOT {self.target.serial}"
        if self.confirmation_phrase != expected_confirmation:
            raise ValueError(
                f"comparator confirmation phrase must be exactly {expected_confirmation!r}"
            )
        if self.target.serial not in self.receipt_path.parts:
            raise ValueError("comparator receipt path must be scoped to the exact serial")
        if self.expected_current_runtime.hardware_model != self.expected_runtime.hardware_model:
            raise ValueError("comparator plan hardware model must remain unchanged")
        if (
            self.expected_runtime.firmware_version != APPROVED_V7_FIRMWARE
            or self.expected_runtime.metadata_abi != "frame-metadata-v2"
            or self.expected_runtime.capabilities != ("tandem-agc",)
        ):
            raise ValueError("comparator expected runtime is not the approved-v7 profile")
        return self


class ComparatorTransitionReceipt(ApiModel):
    remote_command: Literal["/usr/sbin/device_reboot ram"] = "/usr/sbin/device_reboot ram"
    selector: Literal["0456:b673,0456:b674"] = "0456:b673,0456:b674"
    topology: str = Field(pattern=r"^[0-9]+-[0-9]+(?:[.][0-9]+)*$")
    alternate: Literal["firmware.dfu"] = "firmware.dfu"
    method: Literal["download-then-detach-e"] = "download-then-detach-e"
    download_argv: tuple[str, ...]
    detach_argv: tuple[str, ...]
    sealed_input: bool
    download_completed: bool
    detach_completed: bool
    reset_after_download: Literal[False] = False
    serial_selector_used: Literal[False] = False
    persistent_write: Literal[False] = False

    @model_validator(mode="after")
    def validate_commands(self) -> ComparatorTransitionReceipt:
        expected_download = (
            "dfu-util",
            "-d",
            DFU_SELECTOR,
            "-p",
            self.topology,
            "-a",
            DFU_ALTERNATE,
            "-D",
            "<sealed-fd>",
        )
        expected_detach = (
            "dfu-util",
            "-d",
            DFU_SELECTOR,
            "-p",
            self.topology,
            "-a",
            DFU_ALTERNATE,
            "-e",
        )
        if self.download_argv != expected_download or self.detach_argv != expected_detach:
            raise ValueError("comparator DFU command inventory is not exact")
        forbidden = {"-R", "-S"}
        if forbidden.intersection((*self.download_argv, *self.detach_argv)):
            raise ValueError("comparator transition contains a forbidden DFU option")
        return self


class ComparatorRamReceipt(ApiModel):
    schema_id: Literal["pluto-plus-utils.comparator-ram-receipt.v1"] = Field(
        COMPARATOR_RECEIPT_SCHEMA, alias="schema"
    )
    schema_version: Literal[1] = 1
    receipt_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    outcome: Literal["pass", "unknown"]
    started_at: datetime
    completed_at: datetime
    plan: FileIdentity
    tool: ComparatorToolIdentity
    artifact: ApprovedV7Artifact
    harness: ApprovedV7HarnessIdentity
    target: UsbInventoryTarget
    expected_current_runtime: ExpectedRuntime
    expected_runtime: ExpectedRuntime
    pre_runtime: RuntimeObservation
    post_runtime: RuntimeObservation | None
    host_route: HostRouteReceipt
    transition: ComparatorTransitionReceipt
    cleanup: CleanupReceipt
    failure_phase: str | None = None
    error: str | None = None

    @field_validator("started_at", "completed_at")
    @classmethod
    def validate_timestamp(cls, value: datetime) -> datetime:
        return _utc(value, label="comparator receipt timestamp")

    @model_validator(mode="after")
    def validate_relationships(self) -> ComparatorRamReceipt:
        if self.completed_at < self.started_at:
            raise ValueError("comparator receipt completion precedes its start")
        if (
            self.pre_runtime.serial != self.target.serial
            or self.pre_runtime.topology != self.target.topology
        ):
            raise ValueError("preboot runtime does not match the comparator target")
        if self.post_runtime is not None and (
            self.post_runtime.serial != self.target.serial
            or self.post_runtime.topology != self.target.topology
        ):
            raise ValueError("postboot runtime does not match the comparator target")
        if self.transition.topology != self.target.topology:
            raise ValueError("comparator transition topology does not match the target")
        if (
            self.host_route.interface != self.target.network_interface
            or self.host_route.source != self.target.source_ipv4
        ):
            raise ValueError("comparator host route does not match the target")
        if not _runtime_matches(self.pre_runtime, self.expected_current_runtime):
            raise ValueError("preboot runtime differs from the planned current runtime")
        if self.outcome == "pass":
            if self.post_runtime is None:
                raise ValueError("passing comparator receipt requires a postboot runtime")
            if not _runtime_matches(self.post_runtime, self.expected_runtime):
                raise ValueError("postboot runtime differs from the approved-v7 profile")
            if self.pre_runtime.boot_id == self.post_runtime.boot_id:
                raise ValueError("passing comparator RAM boot requires a new boot ID")
            if self.pre_runtime.qspi != self.post_runtime.qspi:
                raise ValueError("passing comparator RAM boot requires unchanged qspi-linux")
            if not (
                self.host_route.release_verified
                and self.transition.sealed_input
                and self.transition.download_completed
                and self.transition.detach_completed
                and self.cleanup.verified
            ):
                raise ValueError("passing comparator receipt lacks transition or cleanup proof")
            if self.failure_phase is not None or self.error is not None:
                raise ValueError("passing comparator receipt cannot contain a failure")
        elif self.failure_phase is None or self.error is None:
            raise ValueError("unknown comparator receipt must identify its failure")
        return self


def _runtime_matches(observed: RuntimeObservation, expected: ExpectedRuntime) -> bool:
    return bool(
        observed.firmware_version == expected.firmware_version
        and observed.hardware_model == expected.hardware_model
        and observed.metadata_abi == expected.metadata_abi
        and observed.capabilities == expected.capabilities
    )


def attest_comparator_tool_repository(
    repository: Path, *, version: str, wrapper_path: Path
) -> ComparatorToolIdentity:
    """Attest one clean checkout, its complete Git tree, and execution wrapper."""

    selected = _absolute_path(repository, label="tool repository")
    wrapper = _absolute_path(wrapper_path, label="comparator wrapper")
    source = attest_clean_tool_repository(selected, imported_source_files=(wrapper,))
    if source.repository != "misko/pluto-plus-utils":
        raise ComparatorRamError("comparator tool repository identity is not exact")
    try:
        resolved = selected.resolve(strict=True)
        resolved_wrapper = wrapper.resolve(strict=True)
        relative = resolved_wrapper.relative_to(resolved)
    except (OSError, ValueError) as error:
        raise ComparatorRamError("comparator wrapper is outside the tool repository") from error
    if relative != COMPARATOR_WRAPPER_RELATIVE:
        raise ComparatorRamError("comparator wrapper path is not the reviewed module")
    tree_listing = _git_bytes(resolved, "ls-tree", "--full-tree", "-r", "-z", "HEAD")
    if not tree_listing:
        raise ComparatorRamError("tool source tree inventory is empty")
    wrapper_payload = _read_stable_file(
        resolved_wrapper,
        label="comparator wrapper",
        allow_group_writable_git_source=True,
    )
    committed_wrapper = _git_bytes(resolved, "show", f"HEAD:{relative.as_posix()}")
    if wrapper_payload != committed_wrapper:
        raise ComparatorRamError("comparator wrapper differs from committed bytes")
    return ComparatorToolIdentity(
        repository_path=resolved,
        version=version,
        source_commit=source.commit,
        source_tree_sha256=hashlib.sha256(tree_listing).hexdigest(),
        execution_wrapper=FileIdentity(
            path=resolved_wrapper,
            bytes=len(wrapper_payload),
            sha256=hashlib.sha256(wrapper_payload).hexdigest(),
        ),
    )


def prepare_comparator_ram_plan(
    inventory: ReleaseUsbInventory,
    *,
    inventory_path: Path,
    retained_bundle_path: Path,
    dfu_path: Path,
    serial: str,
    expected_current_runtime: ExpectedRuntime,
    receipt_path: Path,
    tool: ComparatorToolIdentity,
    created_at: datetime,
    expires_at: datetime,
    plan_id: str,
    ssh_host: str = "192.168.2.1",
) -> ComparatorRamPlan:
    """Build a file-only comparator plan; no radio transport is opened."""

    selected_inventory = _absolute_path(inventory_path, label="USB inventory")
    bundle = _artifact_identity(
        retained_bundle_path,
        label="retained approved-v7 bundle",
        expected_name=APPROVED_V7_BUNDLE_NAME,
        expected_bytes=APPROVED_V7_BUNDLE_BYTES,
        expected_sha256=APPROVED_V7_BUNDLE_SHA256,
    )
    dfu_payload = _read_stable_file(
        _absolute_path(dfu_path, label="approved-v7 DFU"), label="approved-v7 DFU"
    )
    dfu = FileIdentity(
        path=dfu_path,
        bytes=len(dfu_payload),
        sha256=hashlib.sha256(dfu_payload).hexdigest(),
    )
    if (
        dfu.path.name != APPROVED_V7_DFU_NAME
        or dfu.bytes != APPROVED_V7_DFU_BYTES
        or dfu.sha256 != APPROVED_V7_DFU_SHA256
    ):
        raise ComparatorRamError("approved-v7 DFU bytes do not match the immutable profile")
    try:
        fit_payload = validate_dfu(dfu_payload)
    except FirmwareImageError as error:
        raise ComparatorRamError(f"approved-v7 DFU is invalid: {error}") from error
    fit = ContentIdentity(bytes=len(fit_payload), sha256=hashlib.sha256(fit_payload).hexdigest())
    if fit != ContentIdentity(bytes=APPROVED_V7_FIT_BYTES, sha256=APPROVED_V7_FIT_SHA256):
        raise ComparatorRamError("approved-v7 FIT body does not match the immutable profile")
    matches = tuple(device for device in inventory.devices if device.serial == serial)
    if len(matches) != 1:
        raise ComparatorRamError("expected one exact USB inventory target for the serial")
    target = matches[0]
    expected_runtime = ExpectedRuntime(
        firmware_version=APPROVED_V7_FIRMWARE,
        hardware_model=expected_current_runtime.hardware_model,
        metadata_abi="frame-metadata-v2",
        capabilities=("tandem-agc",),
    )
    return ComparatorRamPlan(
        schema=COMPARATOR_PLAN_SCHEMA,
        plan_id=plan_id,
        created_at=created_at,
        expires_at=expires_at,
        tool=tool,
        artifact=ApprovedV7Artifact(retained_bundle=bundle, dfu=dfu, fit=fit),
        usb_inventory=model_file_identity(selected_inventory, inventory),
        target=target,
        expected_current_runtime=expected_current_runtime,
        expected_runtime=expected_runtime,
        ssh_host=ssh_host,
        receipt_path=receipt_path,
        confirmation_phrase=f"COMPARATOR RAM BOOT {serial}",
        allowed_operation="ram-only",
        hardware_accessed=False,
    )


def comparator_ssh_argv(plan: ComparatorRamPlan, password_path: Path) -> tuple[str, ...]:
    """Return the sole fixed SSH transition accepted by comparator execution."""

    return ssh_fixed_argv(
        plan.target,
        ssh_host=plan.ssh_host,
        password_path=password_path,
        remote_command=REMOTE_RAM_COMMAND,
    )


def comparator_dfu_download_argv(plan: ComparatorRamPlan, sealed_path: Path) -> tuple[str, ...]:
    """Return a paired runtime/DFU selector and the volatile firmware alternate."""

    return (
        "dfu-util",
        "-d",
        DFU_SELECTOR,
        "-p",
        plan.target.topology,
        "-a",
        DFU_ALTERNATE,
        "-D",
        str(sealed_path),
    )


def comparator_dfu_detach_argv(plan: ComparatorRamPlan) -> tuple[str, ...]:
    """Return the sole detach vector accepted after the volatile download."""

    return (
        "dfu-util",
        "-d",
        DFU_SELECTOR,
        "-p",
        plan.target.topology,
        "-a",
        DFU_ALTERNATE,
        "-e",
    )


def execute_comparator_ram(
    plan_path: Path,
    *,
    expected_plan_sha256: str,
    password_path: Path,
    confirmation: str,
    backend: ReleaseCandidateRamBackend,
    tool: ComparatorToolIdentity,
    timeout_s: float = 45.0,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
    receipt_id_factory: Callable[[], str] = lambda: uuid.uuid4().hex,
) -> tuple[ComparatorRamReceipt, str]:
    """Execute one exact reviewed comparator plan and publish a native receipt."""

    if timeout_s <= 0:
        raise ValueError("comparator RAM timeout must be positive")
    if _SHA256.fullmatch(expected_plan_sha256) is None:
        raise ComparatorRamError("expected plan SHA-256 must be lowercase hexadecimal")
    selected_plan = _absolute_path(plan_path, label="comparator plan")
    plan = load_private_contract(selected_plan, ComparatorRamPlan)
    plan_identity = model_file_identity(selected_plan, plan)
    if plan_identity.sha256 != expected_plan_sha256:
        raise ComparatorRamError("comparator plan SHA-256 differs from operator approval")
    if confirmation != plan.confirmation_phrase:
        raise ComparatorRamError(f"confirmation must be exactly {plan.confirmation_phrase!r}")
    started_at = _utc(now(), label="comparator execution start")
    if started_at < plan.created_at or started_at > plan.expires_at:
        raise ComparatorRamError("comparator plan is not within its approved execution window")
    if tool != plan.tool:
        raise ComparatorRamError("executing utility source differs from the comparator plan")
    inventory = load_private_contract(plan.usb_inventory.path, ReleaseUsbInventory)
    if model_file_identity(plan.usb_inventory.path, inventory) != plan.usb_inventory:
        raise ComparatorRamError("comparator plan does not bind current inventory bytes")
    matches = tuple(device for device in inventory.devices if device.serial == plan.target.serial)
    if matches != (plan.target,):
        raise ComparatorRamError("comparator target is not exact in the retained inventory")
    payload = _verify_artifact_files(plan.artifact)
    password = validate_password_file(password_path)
    for archive_path in (plan.artifact.retained_bundle.path, plan.artifact.dfu.path):
        try:
            password.path.relative_to(archive_path.parent)
        except ValueError:
            continue
        raise ComparatorRamError("SSH password must be outside the retained comparator archive")
    _require_absent_receipt(plan.receipt_path, serial=plan.target.serial)

    with backend.transaction_locks(plan.target, plan.ssh_host):
        _require_approved_plan_unchanged(selected_plan, plan, plan_identity)
        _require_absent_receipt(plan.receipt_path, serial=plan.target.serial)
        fresh_target = backend.revalidate_target(plan.target)
        if fresh_target != plan.target:
            raise ComparatorRamError("live target changed from the comparator plan")
        route = backend.acquire_host_route(plan.target, plan.ssh_host)
        expected_route = HostRouteReceipt(
            destination=f"{plan.ssh_host}/32",
            interface=plan.target.network_interface,
            source=plan.target.source_ipv4,
            release_verified=False,
        )
        if route != expected_route:
            _release_after_preflight_failure(backend, route)
            raise ComparatorRamError("backend acquired an unexpected comparator host route")
        try:
            pre = backend.attest_runtime(
                plan.target,
                expected_firmware=plan.expected_current_runtime.firmware_version,
                password=password,
                route=route,
            )
            _validate_runtime(pre, plan.target, plan.expected_current_runtime, label="preboot")
        except BaseException:
            _release_after_preflight_failure(backend, route)
            raise

        mutation_started = False
        download_completed = False
        detach_completed = False
        post: RuntimeObservation | None = None
        failure_phase = "seal-dfu"
        try:
            with backend.sealed_dfu(payload) as sealed_path:
                _validate_sealed_path(sealed_path)
                password = validate_password_file(password.path, expected=password)
                _require_approved_plan_unchanged(selected_plan, plan, plan_identity)
                mutation_at = _utc(now(), label="comparator mutation start")
                if mutation_at < plan.created_at or mutation_at > plan.expires_at:
                    raise ComparatorRamError(
                        "comparator plan expired before the RAM mutation boundary"
                    )
                mutation_started = True
                failure_phase = "request-ram-mode"
                backend.request_ram_mode(
                    comparator_ssh_argv(plan, password.path), password=password, route=route
                )
                failure_phase = "wait-for-dfu"
                backend.wait_for_dfu(plan.target, timeout_s=timeout_s)
                failure_phase = "download-dfu"
                backend.download_dfu(
                    comparator_dfu_download_argv(plan, sealed_path), sealed_path=sealed_path
                )
                download_completed = True
                failure_phase = "detach-dfu"
                backend.detach_dfu(comparator_dfu_detach_argv(plan))
                detach_completed = True
                failure_phase = "wait-for-runtime"
                returned = backend.wait_for_runtime(plan.target, timeout_s=timeout_s)
                if not _same_physical_target(returned, plan.target):
                    raise ComparatorRamError(
                        "returned runtime differs from the exact comparator target"
                    )
                failure_phase = "postboot-route"
                backend.ensure_host_route(route, returned)
                failure_phase = "postboot-attestation"
                password = validate_password_file(password.path, expected=password)
                post = backend.attest_runtime(
                    returned,
                    expected_firmware=plan.expected_runtime.firmware_version,
                    password=password,
                    route=route,
                )
                _validate_runtime(post, plan.target, plan.expected_runtime, label="postboot")
                if post.boot_id == pre.boot_id or post.qspi != pre.qspi:
                    raise ComparatorRamError(
                        "comparator postboot epoch or qspi-linux identity is unsafe"
                    )
        except BaseException as error:
            if not mutation_started:
                _release_after_preflight_failure(backend, route)
                raise
            return _publish_uncertain_receipt(
                error,
                backend=backend,
                plan=plan,
                plan_path=selected_plan,
                password=password,
                route=route,
                pre=pre,
                failure_phase=failure_phase,
                download_completed=download_completed,
                detach_completed=detach_completed,
                started_at=started_at,
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
                plan=plan,
                plan_path=selected_plan,
                password=password,
                route=route,
                pre=pre,
                failure_phase="release-host-route",
                download_completed=True,
                detach_completed=True,
                started_at=started_at,
                timeout_s=timeout_s,
                now=now,
                receipt_id_factory=receipt_id_factory,
            )
        receipt = _build_receipt(
            receipt_id=receipt_id_factory(),
            outcome="pass",
            started_at=started_at,
            completed_at=_utc(now(), label="comparator execution completion"),
            plan=plan,
            plan_path=selected_plan,
            pre=pre,
            post=post,
            route=route.model_copy(update={"release_verified": True}),
            download_completed=True,
            detach_completed=True,
            cleanup=CleanupReceipt(verified=True),
        )
        validate_comparator_contract_bundle(plan, receipt, plan_path=selected_plan)
        identity = write_private_contract(plan.receipt_path, receipt)
        return receipt, identity.sha256


def _publish_uncertain_receipt(
    error: BaseException,
    *,
    backend: ReleaseCandidateRamBackend,
    plan: ComparatorRamPlan,
    plan_path: Path,
    password: PasswordFileIdentity,
    route: HostRouteReceipt,
    pre: RuntimeObservation,
    failure_phase: str,
    download_completed: bool,
    detach_completed: bool,
    started_at: datetime,
    timeout_s: float,
    now: Callable[[], datetime],
    receipt_id_factory: Callable[[], str],
) -> tuple[ComparatorRamReceipt, str]:
    cleanup_errors: list[str] = []
    reconciled: RuntimeObservation | None = None
    try:
        result = backend.reconcile_failure(
            plan.target,
            candidate=cast(Any, plan),
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
    release_verified = False
    try:
        backend.release_host_route(route)
        release_verified = True
    except BaseException as route_error:
        cleanup_errors = [*cleanup.errors, f"host route release: {route_error}"]
        cleanup = CleanupReceipt(verified=False, errors=tuple(cleanup_errors))
    receipt = _build_receipt(
        receipt_id=receipt_id_factory(),
        outcome="unknown",
        started_at=started_at,
        completed_at=_utc(now(), label="comparator failure completion"),
        plan=plan,
        plan_path=plan_path,
        pre=pre,
        post=reconciled,
        route=route.model_copy(update={"release_verified": release_verified}),
        download_completed=download_completed,
        detach_completed=detach_completed,
        cleanup=cleanup,
        failure_phase=failure_phase,
        error=f"{type(error).__name__}: {error}",
    )
    validate_comparator_contract_bundle(plan, receipt, plan_path=plan_path)
    identity = write_private_contract(plan.receipt_path, receipt)
    raise ComparatorRamError(str(error), receipt=receipt, receipt_sha256=identity.sha256) from error


def _build_receipt(
    *,
    receipt_id: str,
    outcome: Literal["pass", "unknown"],
    started_at: datetime,
    completed_at: datetime,
    plan: ComparatorRamPlan,
    plan_path: Path,
    pre: RuntimeObservation,
    post: RuntimeObservation | None,
    route: HostRouteReceipt,
    download_completed: bool,
    detach_completed: bool,
    cleanup: CleanupReceipt,
    failure_phase: str | None = None,
    error: str | None = None,
) -> ComparatorRamReceipt:
    return ComparatorRamReceipt(
        schema=COMPARATOR_RECEIPT_SCHEMA,
        receipt_id=receipt_id,
        outcome=outcome,
        started_at=started_at,
        completed_at=completed_at,
        plan=model_file_identity(plan_path, plan),
        tool=plan.tool,
        artifact=plan.artifact,
        harness=plan.harness,
        target=plan.target,
        expected_current_runtime=plan.expected_current_runtime,
        expected_runtime=plan.expected_runtime,
        pre_runtime=pre,
        post_runtime=post,
        host_route=route,
        transition=ComparatorTransitionReceipt(
            topology=plan.target.topology,
            download_argv=(
                "dfu-util",
                "-d",
                DFU_SELECTOR,
                "-p",
                plan.target.topology,
                "-a",
                DFU_ALTERNATE,
                "-D",
                "<sealed-fd>",
            ),
            detach_argv=comparator_dfu_detach_argv(plan),
            sealed_input=True,
            download_completed=download_completed,
            detach_completed=detach_completed,
        ),
        cleanup=cleanup,
        failure_phase=failure_phase,
        error=error,
    )


def validate_comparator_contract_bundle(
    plan: ComparatorRamPlan,
    receipt: ComparatorRamReceipt,
    *,
    plan_path: Path,
) -> None:
    """Prove exact semantic coherence between native comparator contracts."""

    if receipt.plan != model_file_identity(plan_path, plan):
        raise ComparatorRamError("comparator receipt does not bind exact plan bytes")
    if receipt.started_at < plan.created_at or receipt.started_at > plan.expires_at:
        raise ComparatorRamError("comparator receipt began outside the approved execution window")
    if (
        receipt.tool != plan.tool
        or receipt.artifact != plan.artifact
        or receipt.harness != plan.harness
        or receipt.target != plan.target
        or receipt.expected_current_runtime != plan.expected_current_runtime
        or receipt.expected_runtime != plan.expected_runtime
    ):
        raise ComparatorRamError("comparator receipt semantics differ from the plan")
    if receipt.host_route.destination != f"{plan.ssh_host}/32":
        raise ComparatorRamError("comparator receipt route differs from the plan")
    if receipt.transition.topology != plan.target.topology:
        raise ComparatorRamError("comparator receipt DFU topology differs from the plan")


def verify_comparator_ram_receipt(
    receipt_path: Path, *, tool: ComparatorToolIdentity
) -> ComparatorRamReceipt:
    """Deep-replay a receipt, its plan, inventory, source, and retained artifacts."""

    selected = _absolute_path(receipt_path, label="comparator receipt")
    receipt = load_private_contract(selected, ComparatorRamReceipt)
    plan = load_private_contract(receipt.plan.path, ComparatorRamPlan)
    if selected != plan.receipt_path:
        raise ComparatorRamError("comparator receipt path differs from the plan")
    validate_comparator_contract_bundle(plan, receipt, plan_path=receipt.plan.path)
    if tool != plan.tool:
        raise ComparatorRamError("current utility source differs from the comparator plan")
    inventory = load_private_contract(plan.usb_inventory.path, ReleaseUsbInventory)
    if model_file_identity(plan.usb_inventory.path, inventory) != plan.usb_inventory:
        raise ComparatorRamError("retained comparator USB inventory changed")
    if tuple(item for item in inventory.devices if item.serial == plan.target.serial) != (
        plan.target,
    ):
        raise ComparatorRamError("retained comparator target is no longer exact")
    _verify_artifact_files(plan.artifact)
    return receipt


def _verify_artifact_files(artifact: ApprovedV7Artifact) -> bytes:
    bundle = _artifact_identity(
        artifact.retained_bundle.path,
        label="retained approved-v7 bundle",
        expected_name=APPROVED_V7_BUNDLE_NAME,
        expected_bytes=APPROVED_V7_BUNDLE_BYTES,
        expected_sha256=APPROVED_V7_BUNDLE_SHA256,
    )
    if bundle != artifact.retained_bundle:
        raise ComparatorRamError("retained approved-v7 bundle changed after planning")
    payload = _read_stable_file(artifact.dfu.path, label="approved-v7 DFU")
    observed = FileIdentity(
        path=artifact.dfu.path,
        bytes=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
    )
    if observed != artifact.dfu:
        raise ComparatorRamError("approved-v7 DFU changed after planning")
    try:
        fit_payload = validate_dfu(payload)
    except FirmwareImageError as error:
        raise ComparatorRamError(f"approved-v7 DFU is invalid: {error}") from error
    fit = ContentIdentity(bytes=len(fit_payload), sha256=hashlib.sha256(fit_payload).hexdigest())
    if fit != artifact.fit:
        raise ComparatorRamError("approved-v7 FIT changed after planning")
    return payload


def _artifact_identity(
    path: Path,
    *,
    label: str,
    expected_name: str,
    expected_bytes: int,
    expected_sha256: str,
) -> FileIdentity:
    selected = _absolute_path(path, label=label)
    if selected.name != expected_name:
        raise ComparatorRamError(f"{label} filename is not exact")
    payload = _read_stable_file(selected, label=label)
    identity = FileIdentity(
        path=selected,
        bytes=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
    )
    if identity.bytes != expected_bytes or identity.sha256 != expected_sha256:
        raise ComparatorRamError(f"{label} bytes do not match the immutable profile")
    return identity


def _read_stable_file(
    path: Path,
    *,
    label: str,
    allow_group_writable_git_source: bool = False,
) -> bytes:
    selected = _absolute_path(path, label=label)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        before = selected.lstat()
        descriptor = os.open(selected, flags)
    except OSError as error:
        raise ComparatorRamError(f"{label} cannot be opened safely: {error}") from error
    try:
        opened = os.fstat(descriptor)
        stable = _stable_identity(opened)
        if _stable_identity(before) != stable:
            raise ComparatorRamError(f"{label} changed while opening")
        writable_by_others = opened.st_mode & 0o022
        exact_git_source_mode = stat.S_IMODE(opened.st_mode) == 0o664
        writable_mode_is_unsafe = bool(
            writable_by_others & 0o002
            or (
                writable_by_others & 0o020
                and not (allow_group_writable_git_source and exact_git_source_mode)
            )
        )
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or opened.st_nlink != 1
            or writable_mode_is_unsafe
            or opened.st_size <= 0
            or opened.st_size > MAX_ARTIFACT_BYTES
        ):
            raise ComparatorRamError(
                f"{label} must be one owned regular file with a permitted writable mode"
            )
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1 << 20))
            if not chunk:
                raise ComparatorRamError(f"{label} was truncated during read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ComparatorRamError(f"{label} grew during read")
        if _stable_identity(os.fstat(descriptor)) != stable:
            raise ComparatorRamError(f"{label} changed during read")
    finally:
        os.close(descriptor)
    return b"".join(chunks)


def _git_bytes(repository: Path, *arguments: str) -> bytes:
    try:
        result = subprocess.run(
            ("git", "-C", str(repository), *arguments),
            check=False,
            capture_output=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ComparatorRamError(f"cannot attest comparator Git source: {error}") from error
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()[-1000:]
        raise ComparatorRamError(f"comparator Git attestation failed: {detail}")
    return result.stdout


def _validate_runtime(
    observed: RuntimeObservation,
    target: UsbInventoryTarget,
    expected: ExpectedRuntime,
    *,
    label: str,
) -> None:
    if (
        observed.serial != target.serial
        or observed.topology != target.topology
        or not _runtime_matches(observed, expected)
    ):
        raise ComparatorRamError(f"{label} comparator runtime differs from the plan")


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


def _validate_sealed_path(path: Path) -> None:
    if re.fullmatch(r"/proc/self/fd/[0-9]+", str(path)) is None:
        raise ComparatorRamError("comparator DFU input is not a sealed descriptor path")


def _release_after_preflight_failure(
    backend: ReleaseCandidateRamBackend, route: HostRouteReceipt
) -> None:
    try:
        backend.release_host_route(route)
    except BaseException as error:
        raise ComparatorRamError(
            f"comparator preflight failed and route cleanup also failed: {error}"
        ) from error


def _require_absent_receipt(path: Path, *, serial: str) -> None:
    selected = _absolute_path(path, label="comparator receipt")
    if serial not in selected.parts:
        raise ComparatorRamError("comparator receipt path is not serial-scoped")
    if selected.exists() or selected.is_symlink():
        raise ComparatorRamError("comparator receipt destination must be absent")
    try:
        parent = selected.parent.lstat()
    except OSError as error:
        raise ComparatorRamError(f"comparator receipt parent is unavailable: {error}") from error
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.getuid()
        or stat.S_IMODE(parent.st_mode) != 0o700
    ):
        raise ComparatorRamError("comparator receipt parent must be owned mode-0700")


def _require_approved_plan_unchanged(
    plan_path: Path,
    approved_plan: ComparatorRamPlan,
    approved_identity: FileIdentity,
) -> None:
    """Revalidate the exact operator-approved plan at an authorization boundary."""

    current_plan = load_private_contract(plan_path, ComparatorRamPlan)
    current_identity = model_file_identity(plan_path, current_plan)
    if current_plan != approved_plan or current_identity != approved_identity:
        raise ComparatorRamError("comparator plan changed after operator approval")


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
