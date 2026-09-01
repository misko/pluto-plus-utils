"""RX-only release-candidate RAM contracts.

Version 2 is intentionally parallel to, rather than a relaxation of, the
legacy tandem-capable v1 contract.  A v2 candidate is expected to return with
one 1R1T receive path and no host-visible transmit datapath.
"""

from __future__ import annotations

import math
import re
from datetime import datetime
from pathlib import Path
from typing import Annotated, Literal, TypeVar

from pydantic import Field, ValidationError, field_validator, model_validator

from pluto_plus.models import ApiModel
from pluto_plus.release_candidate import (
    PLUTO_REV_C_AD9361_MODEL,
    PLUTO_REV_C_AD9363A_MODEL,
    CleanupReceipt,
    ContentIdentity,
    DfuIdentity,
    FileIdentity,
    FirmwareVersion,
    HardwareModel,
    HostRouteReceipt,
    Identifier,
    QspiObservation,
    ReleaseCandidateContractError,
    ReleaseCandidateOperationPlan,
    ReleaseCandidatePlan,
    ReleaseCandidateRamReceipt,
    ReleaseCandidateRecoveryReceipt,
    ReleaseUsbInventory,
    Serial,
    SourceCommit,
    Topology,
    TransitionReceipt,
    UsbInventoryTarget,
    _absolute_normalized,
    _supported_hardware_model,
    _utc_timestamp,
    load_private_contract,
    model_file_identity,
)

RX_ONLY_CANDIDATE_PLAN_SCHEMA: Literal[
    "pluto-plus-utils.release-candidate-plan.v2"
] = "pluto-plus-utils.release-candidate-plan.v2"
RX_ONLY_OPERATION_PLAN_SCHEMA: Literal[
    "pluto-plus-utils.release-candidate-operation-plan.v2"
] = "pluto-plus-utils.release-candidate-operation-plan.v2"
RX_ONLY_RAM_RECEIPT_SCHEMA: Literal[
    "pluto-plus-utils.release-candidate-ram-receipt.v2"
] = "pluto-plus-utils.release-candidate-ram-receipt.v2"
RX_ONLY_RECOVERY_RECEIPT_SCHEMA: Literal[
    "pluto-plus-utils.release-candidate-recovery-receipt.v2"
] = "pluto-plus-utils.release-candidate-recovery-receipt.v2"

RX_ONLY_POLICY_PROFILE: Literal["rx-only-v1"] = "rx-only-v1"
RX_ONLY_ROOT_DT_MARKER: Literal["misko,rx-only-fpga"] = "misko,rx-only-fpga"
RX_ONLY_RUNTIME_TARGETS: tuple[
    Literal["ad9361-1r1t"], Literal["ad9363a-1r1t"]
] = ("ad9361-1r1t", "ad9363a-1r1t")
RxOnlyRuntimeTarget = Literal["ad9361-1r1t", "ad9363a-1r1t"]
MetadataAbi = Annotated[str, Field(pattern=r"^frame-metadata-v[1-9][0-9]*$")]
LegacyContract = TypeVar("LegacyContract", bound=ApiModel)
RxOnlyContract = TypeVar("RxOnlyContract", bound=ApiModel)

TX_CAPABLE_PREBOOT_PROFILE: Literal["tx-capable-1r1t-v1"] = "tx-capable-1r1t-v1"
RX_DMA_DEVICE: Literal["cf-ad9361-lpc"] = "cf-ad9361-lpc"
DDS_DEVICE: Literal["cf-ad9361-dds-core-lpc"] = "cf-ad9361-dds-core-lpc"
TX_DMA_DEVICE: Literal["dma@7c420000"] = "dma@7c420000"
TANDEM_DEVICE: Literal["tandem-agc"] = "tandem-agc"
SHARED_TX_LO_CONTROL: Literal["out_altvoltage1_TX_LO_powerdown"] = (
    "out_altvoltage1_TX_LO_powerdown"
)


def _canonical_optional_capabilities(value: tuple[str, ...]) -> tuple[str, ...]:
    if len(set(value)) != len(value) or value != tuple(sorted(value)):
        raise ValueError("expected capabilities must be unique and canonically sorted")
    if any(re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,63}", item) is None for item in value):
        raise ValueError("expected capability name is malformed")
    return value


def _expected_driver(target: RxOnlyRuntimeTarget) -> str:
    return "ad9361" if target == "ad9361-1r1t" else "ad9363a"


def _expected_model(target: RxOnlyRuntimeTarget) -> str:
    return (
        PLUTO_REV_C_AD9361_MODEL
        if target == "ad9361-1r1t"
        else PLUTO_REV_C_AD9363A_MODEL
    )


class RxOnlyAttestationPolicy(ApiModel):
    """Reviewed topology policy; changing its marker requires a new profile."""

    profile: Literal["rx-only-v1"] = RX_ONLY_POLICY_PROFILE
    supported_runtime_targets: tuple[
        Literal["ad9361-1r1t"], Literal["ad9363a-1r1t"]
    ] = RX_ONLY_RUNTIME_TARGETS
    root_device_tree_marker: Literal["misko,rx-only-fpga"] = RX_ONLY_ROOT_DT_MARKER


class ExpectedRuntimeV2(ApiModel):
    firmware_version: FirmwareVersion
    hardware_model: HardwareModel
    metadata_abi: MetadataAbi | None = None
    capabilities: tuple[str, ...] = ()

    @field_validator("hardware_model")
    @classmethod
    def validate_hardware_model(cls, value: str) -> str:
        return _supported_hardware_model(value)

    @field_validator("capabilities")
    @classmethod
    def validate_capabilities(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _canonical_optional_capabilities(value)


class ReleaseCandidatePlanV2(ApiModel):
    schema_id: Literal["pluto-plus-utils.release-candidate-plan.v2"] = Field(
        RX_ONLY_CANDIDATE_PLAN_SCHEMA, alias="schema"
    )
    schema_version: Literal[2] = 2
    candidate_id: Identifier
    created_at: datetime
    source_repository: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")]
    source_commit: SourceCommit
    device_tool_repository: Annotated[
        str, Field(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
    ]
    device_tool_version: Annotated[str, Field(min_length=1, max_length=128)]
    device_tool_source_commit: SourceCommit
    artifact_index: FileIdentity
    dfu: FileIdentity
    fit: ContentIdentity
    expected_runtime: ExpectedRuntimeV2
    attestation_policy: RxOnlyAttestationPolicy = Field(
        default_factory=RxOnlyAttestationPolicy
    )
    dfu_identity: DfuIdentity = Field(default_factory=DfuIdentity)
    allowed_operation: Literal["ram-only"] = "ram-only"

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, value: datetime) -> datetime:
        return _utc_timestamp(value, label="candidate creation time")

    @model_validator(mode="after")
    def validate_relationships(self) -> ReleaseCandidatePlanV2:
        if self.fit.bytes >= self.dfu.bytes:
            raise ValueError("FIT body must be smaller than its DFU container")
        if self.dfu.path == self.artifact_index.path:
            raise ValueError("candidate DFU and artifact index must be distinct files")
        return self


class ReleaseCandidateOperationPlanV2(ApiModel):
    schema_id: Literal["pluto-plus-utils.release-candidate-operation-plan.v2"] = Field(
        RX_ONLY_OPERATION_PLAN_SCHEMA, alias="schema"
    )
    schema_version: Literal[2] = 2
    plan_id: Identifier
    created_at: datetime
    candidate_plan: FileIdentity
    usb_inventory: FileIdentity
    target: UsbInventoryTarget
    runtime_target: RxOnlyRuntimeTarget
    preboot_profile: Literal["tx-capable-1r1t-v1"] = TX_CAPABLE_PREBOOT_PROFILE
    preboot_quiesce_policy: Literal["tx-quiesce-v1"] = "tx-quiesce-v1"
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
        from pluto_plus.release_candidate import _canonical_ipv4

        return _canonical_ipv4(value, label="SSH host", require_private=True)

    @field_validator("receipt_path")
    @classmethod
    def validate_receipt_path(cls, value: Path) -> Path:
        return _absolute_normalized(value, label="receipt path")

    @model_validator(mode="after")
    def validate_relationships(self) -> ReleaseCandidateOperationPlanV2:
        if self.ssh_host == self.target.source_ipv4:
            raise ValueError("SSH host and local source address must differ")
        expected = (
            f"RAM BOOT RX-ONLY RELEASE CANDIDATE {self.target.serial} "
            f"{self.runtime_target}"
        )
        if self.confirmation_phrase != expected:
            raise ValueError(f"confirmation phrase must be exactly {expected!r}")
        if self.candidate_plan.path == self.usb_inventory.path:
            raise ValueError("candidate plan and USB inventory must be distinct files")
        return self


class SharedTxLoSafeState(ApiModel):
    controls: tuple[Literal["out_altvoltage1_TX_LO_powerdown"]] = (
        SHARED_TX_LO_CONTROL,
    )
    powerdown: tuple[Literal[True]] = (True,)


class TxCapableSingleRxSafeStateV2(ApiModel):
    """Exact TX-capable 1R1T safety inventory before RAM boot."""

    tx_gain_controls: tuple[Literal["out_voltage0_hardwaregain"]] = (
        "out_voltage0_hardwaregain",
    )
    tx_gain_db: tuple[float]
    dds_raw: tuple[int, int, int, int]
    dds_scale: tuple[float, float, float, float]
    dac_selectors: tuple[int, int]
    tandem_state: Literal["IDLE"]
    fifo_level: Literal[0]
    fault_flags: Literal[0]
    shared_tx_lo: SharedTxLoSafeState = Field(default_factory=SharedTxLoSafeState)

    @model_validator(mode="after")
    def validate_safe_values(self) -> TxCapableSingleRxSafeStateV2:
        if any(not math.isfinite(gain) or gain > -80.0 for gain in self.tx_gain_db):
            raise ValueError("the exact exposed 1R1T TX gain must be at or below -80 dB")
        if any(value != 0 for value in self.dds_raw):
            raise ValueError("every exposed 1R1T DDS raw value must be zero")
        if any(not math.isfinite(value) or value != 0.0 for value in self.dds_scale):
            raise ValueError("every exposed 1R1T DDS scale must be finite and zero")
        if self.dac_selectors != (3, 3):
            raise ValueError("both exposed 1R1T DAC selectors must select the safe zero source")
        return self


class SingleRxSafeStateV2(ApiModel):
    """Exact 1R1T controls; the AD936x TX LO is shared, not duplicated."""

    tx_gain_controls: tuple[Literal["out_voltage0_hardwaregain"]] = (
        "out_voltage0_hardwaregain",
    )
    tx_gain_db: tuple[float]
    shared_tx_lo: SharedTxLoSafeState = Field(default_factory=SharedTxLoSafeState)

    @field_validator("tx_gain_db")
    @classmethod
    def validate_gain(cls, value: tuple[float]) -> tuple[float]:
        if any(not math.isfinite(gain) or gain > -80.0 for gain in value):
            raise ValueError("the exact exposed 1R1T TX gain must be at or below -80 dB")
        return value


class SingleRxSetupObservation(ApiModel):
    runtime_target: RxOnlyRuntimeTarget
    uboot_attr_name: Literal["compatible"] | None
    uboot_attr_val: Literal["ad9361", "ad9363a"] | None
    uboot_compatible: Literal["ad9361", "ad9363a"]
    uboot_mode: Literal["1r1t"]
    phy_model: Literal["ad9361", "ad9363a"]
    rx_scan_channels: tuple[Literal["voltage0"], Literal["voltage1"]]

    @model_validator(mode="after")
    def validate_target(self) -> SingleRxSetupObservation:
        expected = _expected_driver(self.runtime_target)
        if self.uboot_compatible != expected or self.phy_model != expected:
            raise ValueError("1R1T U-Boot/PHY identity does not match the runtime target")
        pair = (self.uboot_attr_name, self.uboot_attr_val)
        if pair not in {(None, None), ("compatible", expected)}:
            raise ValueError("1R1T attr_name/attr_val pair is not exact for the runtime target")
        return self


class TxCapableLayoutV2(ApiModel):
    kind: Literal["tx-capable"] = "tx-capable"
    rx_dma_device: Literal["cf-ad9361-lpc"] = RX_DMA_DEVICE
    dds_device: Literal["cf-ad9361-dds-core-lpc"] = DDS_DEVICE
    tx_dma_device: Literal["dma@7c420000"] = TX_DMA_DEVICE
    tandem_device: Literal["tandem-agc"] = TANDEM_DEVICE
    root_device_tree_marker: None = None
    safe_state: TxCapableSingleRxSafeStateV2


class RxOnlyLayoutV2(ApiModel):
    kind: Literal["rx-only"] = "rx-only"
    rx_dma_device: Literal["cf-ad9361-lpc"] = RX_DMA_DEVICE
    dds_device: None = None
    tx_dma_device: None = None
    tandem_device: None = None
    root_device_tree_marker: Literal["misko,rx-only-fpga"] = RX_ONLY_ROOT_DT_MARKER
    safe_state: SingleRxSafeStateV2


RuntimeLayoutV2 = Annotated[
    TxCapableLayoutV2 | RxOnlyLayoutV2, Field(discriminator="kind")
]


class RuntimeObservationV2(ApiModel):
    serial: Serial
    topology: Topology
    usb_uri: Annotated[str, Field(pattern=r"^usb:[0-9]+[.][0-9]+[.][0-9]+$")]
    hardware_model: HardwareModel
    firmware_version: FirmwareVersion
    metadata_abi: MetadataAbi | None
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
    layout: RuntimeLayoutV2
    single_rx_setup: SingleRxSetupObservation

    @field_validator("hardware_model")
    @classmethod
    def validate_hardware_model(cls, value: str) -> str:
        return _supported_hardware_model(value)

    @field_validator("capabilities")
    @classmethod
    def validate_capabilities(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _canonical_optional_capabilities(value)

    @model_validator(mode="after")
    def validate_layout_setup(self) -> RuntimeObservationV2:
        if self.hardware_model != _expected_model(self.single_rx_setup.runtime_target):
            raise ValueError("hardware model does not match its 1R1T runtime target")
        return self


class PrebootQuiesceReceiptV2(ApiModel):
    """Safe-direction preflight writes; TX is deliberately never re-enabled."""

    policy: Literal["tx-quiesce-v1"] = "tx-quiesce-v1"
    tx_gain_controls: tuple[Literal["out_voltage0_hardwaregain"]] = (
        "out_voltage0_hardwaregain",
    )
    dds_raw_controls: tuple[
        Literal["out_altvoltage0_raw"],
        Literal["out_altvoltage1_raw"],
        Literal["out_altvoltage2_raw"],
        Literal["out_altvoltage3_raw"],
    ] = (
        "out_altvoltage0_raw",
        "out_altvoltage1_raw",
        "out_altvoltage2_raw",
        "out_altvoltage3_raw",
    )
    dds_scale_controls: tuple[
        Literal["out_altvoltage0_scale"],
        Literal["out_altvoltage1_scale"],
        Literal["out_altvoltage2_scale"],
        Literal["out_altvoltage3_scale"],
    ] = (
        "out_altvoltage0_scale",
        "out_altvoltage1_scale",
        "out_altvoltage2_scale",
        "out_altvoltage3_scale",
    )
    dac_selector_registers: tuple[Literal["0x0418"], Literal["0x0458"]] = (
        "0x0418",
        "0x0458",
    )
    shared_tx_lo_control: Literal["out_altvoltage1_TX_LO_powerdown"] = (
        SHARED_TX_LO_CONTROL
    )
    readback_verified: Literal[True]
    restore_policy: Literal["leave-quiesced-until-reboot"] = (
        "leave-quiesced-until-reboot"
    )


class ReleaseCandidateRamReceiptV2(ApiModel):
    schema_id: Literal["pluto-plus-utils.release-candidate-ram-receipt.v2"] = Field(
        RX_ONLY_RAM_RECEIPT_SCHEMA, alias="schema"
    )
    schema_version: Literal[2] = 2
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
    runtime_target: RxOnlyRuntimeTarget
    expected_firmware: FirmwareVersion
    expected_hardware_model: HardwareModel
    expected_metadata_abi: MetadataAbi | None
    required_capabilities: tuple[str, ...]
    pre_runtime: RuntimeObservationV2 | None
    post_runtime: RuntimeObservationV2 | None
    preboot_quiesce: PrebootQuiesceReceiptV2 | None
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
        return _canonical_optional_capabilities(value)

    @field_validator("expected_hardware_model")
    @classmethod
    def validate_hardware_model(cls, value: str) -> str:
        return _supported_hardware_model(value)

    @model_validator(mode="after")
    def validate_relationships(self) -> ReleaseCandidateRamReceiptV2:
        if self.completed_at < self.started_at:
            raise ValueError("receipt completion precedes its start")
        if self.operation_plan.path == self.candidate_plan.path:
            raise ValueError("operation and candidate plan files must be distinct")
        if self.candidate_fit.bytes >= self.candidate_dfu.bytes:
            raise ValueError("receipt FIT body must be smaller than its DFU container")
        if self.expected_hardware_model != _expected_model(self.runtime_target):
            raise ValueError("expected hardware model does not match the runtime target")
        for runtime in (self.pre_runtime, self.post_runtime):
            if runtime is not None and (
                runtime.serial != self.target.serial or runtime.topology != self.target.topology
            ):
                raise ValueError("runtime observation does not match the target")
        if self.pre_runtime is not None and (
            self.pre_runtime.layout.kind != "tx-capable"
            or self.pre_runtime.hardware_model != self.expected_hardware_model
            or self.pre_runtime.single_rx_setup.runtime_target != self.runtime_target
        ):
            raise ValueError(
                "preboot runtime is not the target-aware TX-capable 1R1T baseline"
            )
        if self.transition.topology != self.target.topology:
            raise ValueError("transition topology does not match the target")
        if (
            self.host_route.interface != self.target.network_interface
            or self.host_route.source != self.target.source_ipv4
        ):
            raise ValueError("host route does not match the target")
        if self.transition.detach_completed and not self.transition.download_completed:
            raise ValueError("DFU detach cannot precede a completed download")
        if self.transition.download_completed and not self.transition.sealed_input:
            raise ValueError("DFU download cannot precede sealed transition input")
        if self.outcome == "pass":
            if self.pre_runtime is None or self.post_runtime is None:
                raise ValueError("passing receipt requires pre/post runtime observations")
            if self.pre_runtime.layout.kind != "tx-capable":
                raise ValueError("passing RX-only receipt requires TX-capable preboot proof")
            if self.post_runtime.layout.kind != "rx-only":
                raise ValueError("passing RX-only receipt requires RX-only postboot proof")
            pre_setup = self.pre_runtime.single_rx_setup
            setup = self.post_runtime.single_rx_setup
            if (
                pre_setup != setup
                or setup.runtime_target != self.runtime_target
            ):
                raise ValueError("postboot setup does not match the planned runtime target")
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
            if self.preboot_quiesce is None or not self.preboot_quiesce.readback_verified:
                raise ValueError("passing RAM boot requires a verified preboot TX quiesce")
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
        else:
            if self.failure_phase is None or self.error is None:
                raise ValueError("non-passing receipt must identify its failure")
            if self.outcome == "failed":
                if (
                    self.pre_runtime is None
                    or self.preboot_quiesce is None
                    or not self.preboot_quiesce.readback_verified
                    or self.transition.sealed_input
                    or self.transition.download_completed
                    or self.transition.detach_completed
                    or self.post_runtime is not None
                    or self.cleanup.verified
                ):
                    raise ValueError(
                        "failed receipt must describe a quiesced pre-transition failure"
                    )
            else:
                if (
                    self.pre_runtime is None
                    or self.pre_runtime.layout.kind != "tx-capable"
                    or self.preboot_quiesce is None
                    or not self.preboot_quiesce.readback_verified
                    or not self.transition.sealed_input
                ):
                    raise ValueError(
                        "unknown receipt requires a quiesced TX-capable baseline "
                        "and a started transition"
                    )
                if self.cleanup.verified and self.post_runtime is None:
                    raise ValueError(
                        "verified unknown reconciliation requires a runtime observation"
                    )
                if self.post_runtime is not None:
                    self._validate_reconciled_runtime()
        return self

    def _validate_reconciled_runtime(self) -> None:
        """Prove that an UNKNOWN receipt's optional post state is one safe endpoint."""

        assert self.pre_runtime is not None
        assert self.post_runtime is not None
        pre = self.pre_runtime
        post = self.post_runtime
        if post.layout.kind == "rx-only":
            if (
                post.hardware_model != self.expected_hardware_model
                or post.firmware_version != self.expected_firmware
                or post.metadata_abi != self.expected_metadata_abi
                or post.capabilities != self.required_capabilities
                or post.single_rx_setup != pre.single_rx_setup
                or post.single_rx_setup.runtime_target != self.runtime_target
                or post.boot_id == pre.boot_id
                or post.qspi != pre.qspi
            ):
                raise ValueError(
                    "unknown receipt's reconciled RX-only runtime differs from the candidate"
                )
        elif (
            post.hardware_model != pre.hardware_model
            or post.firmware_version != pre.firmware_version
            or post.metadata_abi != pre.metadata_abi
            or post.capabilities != pre.capabilities
            or post.layout != pre.layout
            or post.single_rx_setup != pre.single_rx_setup
            or post.qspi != pre.qspi
            or (self.transition.download_completed and post.boot_id == pre.boot_id)
        ):
            raise ValueError(
                "unknown receipt's reconciled TX-capable runtime differs from the baseline"
            )


class ReleaseCandidateRecoveryReceiptV2(ApiModel):
    schema_id: Literal["pluto-plus-utils.release-candidate-recovery-receipt.v2"] = Field(
        RX_ONLY_RECOVERY_RECEIPT_SCHEMA, alias="schema"
    )
    schema_version: Literal[2] = 2
    recovery_id: Identifier
    started_at: datetime
    completed_at: datetime
    tool_repository: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")]
    tool_version: Annotated[str, Field(min_length=1, max_length=128)]
    tool_source_commit: SourceCommit
    source_receipt: FileIdentity
    source_outcome: Literal["pass", "unknown"]
    operation_plan: FileIdentity
    candidate_plan: FileIdentity
    target: UsbInventoryTarget
    runtime_target: RxOnlyRuntimeTarget
    pre_runtime: RuntimeObservationV2
    recovered_runtime: RuntimeObservationV2
    recovery_quiesce: PrebootQuiesceReceiptV2
    expected_return_firmware: FirmwareVersion
    expected_return_layout: Literal["tx-capable"] = "tx-capable"
    host_route: HostRouteReceipt
    recovery_action: Literal[
        "persistent-reset", "dfu-detach-then-persistent-reset"
    ]
    dfu_detach_completed: bool
    persistent_reset_completed: Literal[True] = True
    pre_reset_usb_departure_verified: Literal[True]
    persistent_write: Literal[False] = False
    qspi_unchanged: Literal[True] = True
    cleanup: CleanupReceipt

    @field_validator("started_at", "completed_at")
    @classmethod
    def validate_timestamps(cls, value: datetime) -> datetime:
        return _utc_timestamp(value, label="recovery receipt timestamp")

    @model_validator(mode="after")
    def validate_relationships(self) -> ReleaseCandidateRecoveryReceiptV2:
        if self.completed_at < self.started_at:
            raise ValueError("recovery completion precedes its start")
        if self.source_receipt.path in {self.operation_plan.path, self.candidate_plan.path}:
            raise ValueError("recovery inputs must be distinct files")
        if self.operation_plan.path == self.candidate_plan.path:
            raise ValueError("operation and candidate plan files must be distinct")
        for runtime in (self.pre_runtime, self.recovered_runtime):
            if runtime.serial != self.target.serial or runtime.topology != self.target.topology:
                raise ValueError("recovery runtime does not match the target")
        if self.recovered_runtime.firmware_version != self.expected_return_firmware:
            raise ValueError("recovered firmware does not match the expected return")
        if self.pre_runtime.hardware_model != self.recovered_runtime.hardware_model:
            raise ValueError("hardware model changed during recovery")
        if self.pre_runtime.boot_id == self.recovered_runtime.boot_id:
            raise ValueError("DFU recovery requires a new runtime boot ID")
        if self.pre_runtime.qspi != self.recovered_runtime.qspi:
            raise ValueError("DFU recovery requires unchanged qspi-linux bytes")
        if self.recovered_runtime.layout.kind != self.expected_return_layout:
            raise ValueError("recovered runtime layout differs from the recovery plan")
        if not self.recovery_quiesce.readback_verified:
            raise ValueError("recovery lacks verified persistent-runtime TX quiesce")
        if (
            self.pre_runtime.single_rx_setup != self.recovered_runtime.single_rx_setup
            or self.recovered_runtime.single_rx_setup.runtime_target != self.runtime_target
        ):
            raise ValueError("recovered 1R1T setup differs from the preboot target")
        if self.dfu_detach_completed != (
            self.recovery_action == "dfu-detach-then-persistent-reset"
        ):
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


def build_rx_only_operation_plan(
    candidate: ReleaseCandidatePlanV2,
    inventory: ReleaseUsbInventory,
    *,
    candidate_path: Path,
    inventory_path: Path,
    serial: str,
    runtime_target: RxOnlyRuntimeTarget,
    expected_current_firmware: str,
    receipt_path: Path,
    plan_id: str,
    created_at: datetime,
    ssh_host: str = "192.168.2.1",
) -> ReleaseCandidateOperationPlanV2:
    """Build one offline v2 operation plan for an explicit 1R1T target."""

    matches = tuple(device for device in inventory.devices if device.serial == serial)
    if len(matches) != 1:
        raise ValueError("expected one release USB inventory device for the serial")
    if candidate.expected_runtime.hardware_model != _expected_model(runtime_target):
        raise ValueError("candidate hardware model does not match the selected runtime target")
    return ReleaseCandidateOperationPlanV2(
        schema=RX_ONLY_OPERATION_PLAN_SCHEMA,
        plan_id=plan_id,
        created_at=created_at,
        candidate_plan=model_file_identity(candidate_path, candidate),
        usb_inventory=model_file_identity(inventory_path, inventory),
        target=matches[0],
        runtime_target=runtime_target,
        expected_current_firmware=expected_current_firmware,
        ssh_host=ssh_host,
        receipt_path=receipt_path,
        confirmation_phrase=(
            f"RAM BOOT RX-ONLY RELEASE CANDIDATE {serial} {runtime_target}"
        ),
        hardware_accessed=False,
    )


def validate_rx_only_contract_bundle(
    candidate: ReleaseCandidatePlanV2,
    operation: ReleaseCandidateOperationPlanV2,
    receipt: ReleaseCandidateRamReceiptV2,
    *,
    candidate_path: Path,
    operation_path: Path,
) -> None:
    """Prove semantic and byte-identity coherence across the v2 contracts."""

    candidate_identity = model_file_identity(candidate_path, candidate)
    operation_identity = model_file_identity(operation_path, operation)
    if operation.candidate_plan != candidate_identity:
        raise ValueError("operation plan does not bind the exact candidate plan bytes")
    if receipt.candidate_plan != candidate_identity:
        raise ValueError("receipt does not bind the exact candidate plan bytes")
    if receipt.operation_plan != operation_identity:
        raise ValueError("receipt does not bind the exact operation plan bytes")
    if receipt.target != operation.target or receipt.runtime_target != operation.runtime_target:
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
    if receipt.host_route.destination != f"{operation.ssh_host}/32":
        raise ValueError("receipt host route does not match the operation plan")


def validate_rx_only_recovery_source(source: ReleaseCandidateRamReceiptV2) -> None:
    """Admit completed trials and started uncertain transitions, never preflight failures."""

    common = bool(
        source.pre_runtime is not None
        and source.pre_runtime.layout.kind == "tx-capable"
        and source.preboot_quiesce is not None
        and source.preboot_quiesce.readback_verified
        and source.host_route.release_verified
        and not source.transition.persistent_write
    )
    eligible_outcome = source.outcome == "pass" or (
        source.outcome == "unknown" and source.transition.sealed_input
    )
    if not common or not eligible_outcome:
        raise ValueError(
            "recovery requires one route-released PASS or transition-started "
            "UNKNOWN v2 RAM receipt"
        )


def validate_rx_only_recovery_bundle(
    candidate: ReleaseCandidatePlanV2,
    operation: ReleaseCandidateOperationPlanV2,
    source: ReleaseCandidateRamReceiptV2,
    recovery: ReleaseCandidateRecoveryReceiptV2,
    *,
    candidate_path: Path,
    operation_path: Path,
    source_path: Path,
) -> None:
    """Bind v2 recovery to the exact persistent preboot baseline."""

    validate_rx_only_contract_bundle(
        candidate,
        operation,
        source,
        candidate_path=candidate_path,
        operation_path=operation_path,
    )
    validate_rx_only_recovery_source(source)
    if source_path != operation.receipt_path:
        raise ValueError("recovery source path differs from the operation receipt path")
    if recovery.source_receipt != model_file_identity(source_path, source):
        raise ValueError("recovery does not bind the exact source receipt bytes")
    if recovery.source_outcome != source.outcome:
        raise ValueError("recovery source outcome differs from the bound source receipt")
    if (
        recovery.operation_plan != source.operation_plan
        or recovery.candidate_plan != source.candidate_plan
    ):
        raise ValueError("recovery plan identities differ from the source receipt")
    if recovery.target != operation.target or recovery.runtime_target != operation.runtime_target:
        raise ValueError("recovery target differs from the operation plan")
    if recovery.host_route.destination != f"{operation.ssh_host}/32":
        raise ValueError("recovery host route destination differs from the operation plan")
    if source.pre_runtime is None or recovery.pre_runtime != source.pre_runtime:
        raise ValueError("recovery baseline differs from the source preboot runtime")
    if recovery.expected_return_firmware != operation.expected_current_firmware:
        raise ValueError("recovery firmware is not the persistent operation baseline")
    if (
        source.post_runtime is not None
        and recovery.recovered_runtime.boot_id == source.post_runtime.boot_id
    ):
        raise ValueError("recovery reused the source receipt's post-runtime boot ID")
    if (
        recovery.tool_repository != candidate.device_tool_repository
        or recovery.tool_version != candidate.device_tool_version
        or recovery.tool_source_commit != candidate.device_tool_source_commit
    ):
        raise ValueError("recovery tool identity differs from the candidate plan")


def _load_exact_variant(
    path: Path,
    legacy: type[LegacyContract],
    rx_only: type[RxOnlyContract],
    *,
    label: str,
) -> LegacyContract | RxOnlyContract:
    """Load only one exact supported literal schema without coercion."""

    try:
        return load_private_contract(path, legacy)
    except ValidationError:
        try:
            return load_private_contract(path, rx_only)
        except ValidationError as error:
            raise ReleaseCandidateContractError(
                f"{label} schema is not an exact supported v1 or v2 contract"
            ) from error


def load_candidate_plan_document(
    path: Path,
) -> ReleaseCandidatePlan | ReleaseCandidatePlanV2:
    return _load_exact_variant(
        path, ReleaseCandidatePlan, ReleaseCandidatePlanV2, label="candidate plan"
    )


def load_operation_plan_document(
    path: Path,
) -> ReleaseCandidateOperationPlan | ReleaseCandidateOperationPlanV2:
    return _load_exact_variant(
        path,
        ReleaseCandidateOperationPlan,
        ReleaseCandidateOperationPlanV2,
        label="operation plan",
    )


def load_ram_receipt_document(
    path: Path,
) -> ReleaseCandidateRamReceipt | ReleaseCandidateRamReceiptV2:
    return _load_exact_variant(
        path,
        ReleaseCandidateRamReceipt,
        ReleaseCandidateRamReceiptV2,
        label="RAM receipt",
    )


def load_recovery_receipt_document(
    path: Path,
) -> ReleaseCandidateRecoveryReceipt | ReleaseCandidateRecoveryReceiptV2:
    return _load_exact_variant(
        path,
        ReleaseCandidateRecoveryReceipt,
        ReleaseCandidateRecoveryReceiptV2,
        label="recovery receipt",
    )
