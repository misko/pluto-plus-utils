"""Plan-gated, RX-only environment surveys with durable spectral evidence."""

from __future__ import annotations

import errno
import hashlib
import math
import os
import shutil
import stat
import uuid
from collections.abc import Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, Literal, Protocol

import numpy as np
from pydantic import Field, field_validator, model_validator

from pluto_plus.artifacts import complex_to_ci16
from pluto_plus.hardware.base import SampleBlock
from pluto_plus.inventory import LocalUsbPluto
from pluto_plus.models import ApiModel, GainMode, RadioSettings
from pluto_plus.release_candidate import (
    FileIdentity,
    Serial,
    Sha256,
    SourceCommit,
    Topology,
    canonical_json_bytes,
    load_private_contract,
    model_file_identity,
)
from pluto_plus.release_candidate_linux import ToolSourceAttestation

SURVEY_PLAN_SCHEMA: Literal["pluto-plus-utils.environment-survey-plan.v1"] = (
    "pluto-plus-utils.environment-survey-plan.v1"
)
SURVEY_MANIFEST_SCHEMA: Literal["pluto-plus-utils.environment-survey-manifest.v1"] = (
    "pluto-plus-utils.environment-survey-manifest.v1"
)
SURVEY_RECEIPT_SCHEMA: Literal["pluto-plus-utils.environment-survey-receipt.v1"] = (
    "pluto-plus-utils.environment-survey-receipt.v1"
)
SURVEY_EMITTER_INVENTORY_SCHEMA: Literal[
    "pluto-plus-utils.environment-survey-emitter-inventory.v1"
] = "pluto-plus-utils.environment-survey-emitter-inventory.v1"
SURVEY_FLEET_SELECTION_SCHEMA: Literal["pluto-plus-utils.environment-survey-fleet-selection.v1"] = (
    "pluto-plus-utils.environment-survey-fleet-selection.v1"
)
OBJECTIVE_RULE: Literal["minimum-worst-rx-p99-then-burst-occupancy-then-lowest-frequency"] = (
    "minimum-worst-rx-p99-then-burst-occupancy-then-lowest-frequency"
)
FLEET_OBJECTIVE_RULE: Literal[
    "minimum-global-worst-rx-p99-then-burst-occupancy-then-lowest-frequency"
] = "minimum-global-worst-rx-p99-then-burst-occupancy-then-lowest-frequency"

SURVEY_START_HZ = 2_400_000_000
SURVEY_STOP_HZ = 2_490_000_000
SURVEY_STEP_HZ = 1_000_000
SURVEY_CENTER_FREQUENCIES_HZ = tuple(
    range(SURVEY_START_HZ, SURVEY_STOP_HZ + SURVEY_STEP_HZ, SURVEY_STEP_HZ)
)
ANCHOR_CENTER_FREQUENCY_HZ = 2_445_000_000
AUTHORIZING_BASELINE_FREQUENCIES_HZ = (
    1_050_000_000,
    1_550_000_000,
    2_050_000_000,
    5_800_000_000,
)
RESERVED_SURVEY_SERIALS = (
    "winbond-db6968136727402c",
    "1040007c4a94000211000b009186843ef2",
    "winbond-db620818a328172c",
    "104000bac4950008230026001b440a003a",
)
SAMPLE_RATE_HZ = 2_500_000
RF_BANDWIDTH_HZ = 1_500_000
MANUAL_GAIN_DB = 40.0
SAMPLES_PER_WINDOW = 65_536
WINDOWS_PER_CENTER = 32
SETTLE_BUFFERS = 2
FFT_SIZE = 4_096
STFT_HOP_SAMPLES = 2_048
STFT_FRAMES_PER_WINDOW = 31
OBJECTIVE_HALF_WIDTH_HZ = 750_000
AP_EXCLUSION_GUARD_HZ = 750_000
BURST_THRESHOLD_DB = 6.0
P99_DRIFT_LIMIT_DB = 3.0
OCCUPANCY_DRIFT_LIMIT = 0.10
ADC_FULL_SCALE = 2_048.0
ADC_CLIP_THRESHOLD = 2_047
TOTAL_RETAINED_WINDOWS = (
    len(SURVEY_CENTER_FREQUENCIES_HZ) + len(AUTHORIZING_BASELINE_FREQUENCIES_HZ) + 2
) * WINDOWS_PER_CENTER
RAW_BYTES_PER_WINDOW = SAMPLES_PER_WINDOW * 2 * 2 * 2
SPECTRAL_BYTES_PER_WINDOW = (2 * STFT_FRAMES_PER_WINDOW * FFT_SIZE * 4) + (2 * FFT_SIZE * 4)
RAW_PAYLOAD_BYTES = TOTAL_RETAINED_WINDOWS * RAW_BYTES_PER_WINDOW
SPECTRAL_PAYLOAD_BYTES = TOTAL_RETAINED_WINDOWS * SPECTRAL_BYTES_PER_WINDOW
CAPTURE_PAYLOAD_BYTES = RAW_PAYLOAD_BYTES + SPECTRAL_PAYLOAD_BYTES
FAILURE_RESERVE_BYTES = 64 * 1024 * 1024
MINIMUM_FREE_SPACE_BYTES = 5 * 1024 * 1024 * 1024
MANIFEST_ALLOWANCE_BYTES = 400 * 1024 * 1024

assert len(SURVEY_CENTER_FREQUENCIES_HZ) == 91
assert STFT_FRAMES_PER_WINDOW == ((SAMPLES_PER_WINDOW - FFT_SIZE) // STFT_HOP_SAMPLES) + 1
assert TOTAL_RETAINED_WINDOWS == 3_104
assert RAW_PAYLOAD_BYTES == 1_627_389_952
assert SPECTRAL_PAYLOAD_BYTES == 3_254_779_904
assert CAPTURE_PAYLOAD_BYTES == 4_882_169_856
assert FAILURE_RESERVE_BYTES == 67_108_864
assert MINIMUM_FREE_SPACE_BYTES == 5_368_709_120
assert MANIFEST_ALLOWANCE_BYTES == 419_430_400
assert (
    CAPTURE_PAYLOAD_BYTES + FAILURE_RESERVE_BYTES + MANIFEST_ALLOWANCE_BYTES
    == MINIMUM_FREE_SPACE_BYTES
)

Identifier = Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
UsbUri = Annotated[str, Field(pattern=r"^usb:[0-9]+[.][0-9]+[.]5$")]
EmitterId = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")]
StableEmitterText = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[^\r\n]+$")]


def _linear_power_to_dbfs(value: float) -> float:
    if not math.isfinite(value) or value <= 0.0:
        raise ValueError("linear full-scale power must be finite and strictly positive")
    return float(10.0 * np.log10(value))


class EnvironmentSurveyError(RuntimeError):
    """A survey contract or execution violated the RX-only safety boundary."""


class EnvironmentSurveyExecutionError(EnvironmentSurveyError):
    """A failed execution which retained a durable failure receipt."""

    def __init__(self, message: str, *, receipt_path: Path, receipt_sha256: str) -> None:
        super().__init__(message)
        self.receipt_path = receipt_path
        self.receipt_sha256 = receipt_sha256


class EnvironmentSurveyTarget(ApiModel):
    serial: Serial
    topology: Topology
    usb_path: Path
    bus_number: int = Field(gt=0)
    device_number: int = Field(gt=0)
    usb_uri: UsbUri
    vendor_id: Literal["0456"] = "0456"
    product_id: Literal["b673"] = "b673"

    @field_validator("usb_path")
    @classmethod
    def validate_usb_path(cls, value: Path) -> Path:
        if not value.is_absolute() or ".." in value.parts:
            raise ValueError("survey USB path must be absolute and normalized")
        return value

    @model_validator(mode="after")
    def validate_relationships(self) -> EnvironmentSurveyTarget:
        if self.usb_path != Path("/sys/bus/usb/devices") / self.topology:
            raise ValueError("survey USB path must be the direct topology path")
        expected = f"usb:{self.bus_number}.{self.device_number}.5"
        if self.usb_uri != expected:
            raise ValueError(f"survey USB URI must be exactly {expected!r}")
        return self


class SurveyFrequencySpan(ApiModel):
    start_hz: int = Field(gt=0)
    stop_hz: int = Field(gt=0)

    @model_validator(mode="after")
    def validate_relationships(self) -> SurveyFrequencySpan:
        if self.start_hz >= self.stop_hz:
            raise ValueError("emitter occupied start must be strictly below stop")
        return self


class SurveyEmitter(ApiModel):
    emitter_id: EmitterId
    band: Literal["2.4-ghz", "5-ghz"]
    channel: StableEmitterText
    center_hz: int = Field(gt=0)
    occupied_start_hz: int = Field(gt=0)
    occupied_stop_hz: int = Field(gt=0)
    channel_width_hz: int = Field(gt=0)
    power_setting: StableEmitterText
    traffic_state: StableEmitterText

    @field_validator("channel", "power_setting", "traffic_state")
    @classmethod
    def validate_stable_text(cls, value: str) -> str:
        if value.strip() != value or not value.strip():
            raise ValueError("emitter text must be nonblank and have no edge whitespace")
        return value

    @model_validator(mode="after")
    def validate_relationships(self) -> SurveyEmitter:
        if self.occupied_start_hz >= self.occupied_stop_hz:
            raise ValueError("emitter occupied start must be strictly below stop")
        if not self.occupied_start_hz <= self.center_hz <= self.occupied_stop_hz:
            raise ValueError("emitter center must lie inside its closed occupied span")
        if self.band == "2.4-ghz" and not (
            self.occupied_start_hz <= SURVEY_STOP_HZ and self.occupied_stop_hz >= SURVEY_START_HZ
        ):
            raise ValueError("every 2.4 GHz emitter span must intersect the survey grid")
        return self


class EnvironmentSurveyEmitterInventory(ApiModel):
    schema_id: Literal["pluto-plus-utils.environment-survey-emitter-inventory.v1"] = Field(
        SURVEY_EMITTER_INVENTORY_SCHEMA, alias="schema"
    )
    schema_version: Literal[1] = 1
    state: Literal["worst-normal"] = "worst-normal"
    emitters: tuple[SurveyEmitter, ...]

    @model_validator(mode="after")
    def validate_relationships(self) -> EnvironmentSurveyEmitterInventory:
        if not self.emitters:
            raise ValueError("emitter inventory must be nonempty")
        identifiers = tuple(emitter.emitter_id for emitter in self.emitters)
        if identifiers != tuple(sorted(set(identifiers))):
            raise ValueError("emitter inventory must have sorted unique emitter IDs")
        spans = project_occupied_2_4_spans(self)
        if not spans:
            raise ValueError("emitter inventory requires at least one 2.4 GHz emitter")
        _validate_canonical_2_4_spans(spans)
        return self


def project_occupied_2_4_spans(
    inventory: EnvironmentSurveyEmitterInventory,
) -> tuple[SurveyFrequencySpan, ...]:
    return tuple(
        sorted(
            (
                SurveyFrequencySpan(
                    start_hz=emitter.occupied_start_hz,
                    stop_hz=emitter.occupied_stop_hz,
                )
                for emitter in inventory.emitters
                if emitter.band == "2.4-ghz"
            ),
            key=lambda span: (span.start_hz, span.stop_hz),
        )
    )


def _validate_canonical_2_4_spans(spans: tuple[SurveyFrequencySpan, ...]) -> None:
    if not spans:
        raise ValueError("occupied 2.4 GHz spans must be nonempty")
    canonical = tuple(sorted(spans, key=lambda span: (span.start_hz, span.stop_hz)))
    if spans != canonical or len(set(spans)) != len(spans):
        raise ValueError("occupied 2.4 GHz spans must be sorted and unique")
    for previous, current in zip(spans, spans[1:], strict=False):
        if previous.stop_hz >= current.start_hz:
            raise ValueError("closed 2.4 GHz emitter spans must not touch or overlap")
    if any(span.start_hz > SURVEY_STOP_HZ or span.stop_hz < SURVEY_START_HZ for span in spans):
        raise ValueError("every occupied 2.4 GHz span must intersect the survey grid")


def _ap_eligible_candidates(spans: tuple[SurveyFrequencySpan, ...]) -> tuple[int, ...]:
    return tuple(
        center
        for center in SURVEY_CENTER_FREQUENCIES_HZ
        if all(
            center + OBJECTIVE_HALF_WIDTH_HZ < span.start_hz - AP_EXCLUSION_GUARD_HZ
            or center - OBJECTIVE_HALF_WIDTH_HZ > span.stop_hz + AP_EXCLUSION_GUARD_HZ
            for span in spans
        )
    )


class EnvironmentSurveyParameters(ApiModel):
    occupied_2_4_spans_hz: tuple[SurveyFrequencySpan, ...]
    center_frequencies_hz: tuple[int, ...] = SURVEY_CENTER_FREQUENCIES_HZ
    control_candidates_hz: tuple[int, ...] = ()
    sample_rate_hz: int = SAMPLE_RATE_HZ
    rf_bandwidth_hz: int = RF_BANDWIDTH_HZ
    manual_gain_db: float = MANUAL_GAIN_DB
    samples_per_window: int = SAMPLES_PER_WINDOW
    windows_per_center: int = WINDOWS_PER_CENTER
    settle_buffers: int = SETTLE_BUFFERS
    fft_size: int = FFT_SIZE
    stft_hop_samples: int = STFT_HOP_SAMPLES
    stft_frames_per_window: int = STFT_FRAMES_PER_WINDOW
    anchor_center_frequency_hz: int = ANCHOR_CENTER_FREQUENCY_HZ
    anchor_windows: int = WINDOWS_PER_CENTER
    authorizing_baseline_frequencies_hz: tuple[int, ...] = AUTHORIZING_BASELINE_FREQUENCIES_HZ
    objective_half_width_hz: int = OBJECTIVE_HALF_WIDTH_HZ
    ap_exclusion_guard_hz: int = AP_EXCLUSION_GUARD_HZ
    burst_threshold_db: float = BURST_THRESHOLD_DB
    p99_drift_limit_db: float = P99_DRIFT_LIMIT_DB
    occupancy_drift_limit: float = OCCUPANCY_DRIFT_LIMIT
    adc_full_scale: float = ADC_FULL_SCALE
    adc_clip_threshold: int = ADC_CLIP_THRESHOLD
    raw_payload_bytes: int = RAW_PAYLOAD_BYTES
    spectral_payload_bytes: int = SPECTRAL_PAYLOAD_BYTES
    capture_payload_bytes: int = CAPTURE_PAYLOAD_BYTES
    failure_reserve_bytes: int = FAILURE_RESERVE_BYTES
    manifest_allowance_bytes: int = MANIFEST_ALLOWANCE_BYTES
    minimum_free_space_bytes: int = MINIMUM_FREE_SPACE_BYTES
    objective_rule: Literal["minimum-worst-rx-p99-then-burst-occupancy-then-lowest-frequency"] = (
        OBJECTIVE_RULE
    )
    receiver_channels: tuple[Literal[0], Literal[1]] = (0, 1)
    gain_mode: Literal["manual"] = "manual"

    @model_validator(mode="before")
    @classmethod
    def bind_control_candidates(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        supplied = dict(value)
        raw_spans = supplied.get("occupied_2_4_spans_hz")
        if isinstance(raw_spans, (tuple, list)):
            spans = tuple(SurveyFrequencySpan.model_validate(item) for item in raw_spans)
            expected = _ap_eligible_candidates(spans)
            retained = supplied.get("control_candidates_hz")
            if retained is None or retained == () or retained == []:
                supplied["control_candidates_hz"] = expected
        return supplied

    @model_validator(mode="after")
    def validate_relationships(self) -> EnvironmentSurveyParameters:
        _validate_canonical_2_4_spans(self.occupied_2_4_spans_hz)
        if self.center_frequencies_hz != SURVEY_CENTER_FREQUENCIES_HZ:
            raise ValueError("survey centers must be the exact frozen 2.400-2.490 GHz grid")
        expected_candidates = _ap_eligible_candidates(self.occupied_2_4_spans_hz)
        if not expected_candidates:
            raise ValueError("occupied AP exclusion leaves no control candidate")
        if self.control_candidates_hz != expected_candidates:
            raise ValueError("control candidates disagree with the frozen AP exclusion rule")
        if self.receiver_channels != (0, 1):
            raise ValueError("survey must retain both receivers in RX0/RX1 order")
        if self.authorizing_baseline_frequencies_hz != AUTHORIZING_BASELINE_FREQUENCIES_HZ:
            raise ValueError("survey authorizing baseline centers and order are frozen")
        frozen_values = (
            (self.sample_rate_hz, SAMPLE_RATE_HZ),
            (self.rf_bandwidth_hz, RF_BANDWIDTH_HZ),
            (self.manual_gain_db, MANUAL_GAIN_DB),
            (self.samples_per_window, SAMPLES_PER_WINDOW),
            (self.windows_per_center, WINDOWS_PER_CENTER),
            (self.settle_buffers, SETTLE_BUFFERS),
            (self.fft_size, FFT_SIZE),
            (self.stft_hop_samples, STFT_HOP_SAMPLES),
            (self.stft_frames_per_window, STFT_FRAMES_PER_WINDOW),
            (self.anchor_center_frequency_hz, ANCHOR_CENTER_FREQUENCY_HZ),
            (self.anchor_windows, WINDOWS_PER_CENTER),
            (self.objective_half_width_hz, OBJECTIVE_HALF_WIDTH_HZ),
            (self.ap_exclusion_guard_hz, AP_EXCLUSION_GUARD_HZ),
            (self.burst_threshold_db, BURST_THRESHOLD_DB),
            (self.p99_drift_limit_db, P99_DRIFT_LIMIT_DB),
            (self.occupancy_drift_limit, OCCUPANCY_DRIFT_LIMIT),
            (self.adc_full_scale, ADC_FULL_SCALE),
            (self.adc_clip_threshold, ADC_CLIP_THRESHOLD),
            (self.raw_payload_bytes, RAW_PAYLOAD_BYTES),
            (self.spectral_payload_bytes, SPECTRAL_PAYLOAD_BYTES),
            (self.capture_payload_bytes, CAPTURE_PAYLOAD_BYTES),
            (self.failure_reserve_bytes, FAILURE_RESERVE_BYTES),
            (self.manifest_allowance_bytes, MANIFEST_ALLOWANCE_BYTES),
            (self.minimum_free_space_bytes, MINIMUM_FREE_SPACE_BYTES),
        )
        if any(actual != expected for actual, expected in frozen_values):
            raise ValueError(
                "survey acquisition, analysis, drift, and storage constants are frozen"
            )
        return self


class EnvironmentSurveyPlan(ApiModel):
    schema_id: Literal["pluto-plus-utils.environment-survey-plan.v1"] = Field(
        SURVEY_PLAN_SCHEMA, alias="schema"
    )
    schema_version: Literal[1] = 1
    survey_id: Identifier
    created_at: datetime
    tool_repository: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")]
    tool_version: Annotated[str, Field(min_length=1, max_length=128)]
    tool_source_commit: SourceCommit
    target: EnvironmentSurveyTarget
    emitter_inventory_file: FileIdentity
    emitter_inventory: EnvironmentSurveyEmitterInventory
    parameters: EnvironmentSurveyParameters
    result_directory: Path
    confirmation_phrase: str
    ensure_mute_authorized: Literal[True] = True
    hardware_accessed: Literal[False] = False
    ssh_authorized: Literal[False] = False
    route_mutation_authorized: Literal[False] = False
    firmware_mutation_authorized: Literal[False] = False
    qspi_write_authorized: Literal[False] = False
    pluto_tx_authorized: Literal[False] = False

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
            raise ValueError("survey plan creation time must be expressed in UTC")
        return value

    @field_validator("result_directory")
    @classmethod
    def validate_result_directory(cls, value: Path) -> Path:
        if not value.is_absolute() or ".." in value.parts:
            raise ValueError("survey result directory must be absolute and normalized")
        return value

    @model_validator(mode="after")
    def validate_relationships(self) -> EnvironmentSurveyPlan:
        expected = f"EXECUTE RX ENVIRONMENT SURVEY {self.target.serial} {self.survey_id}"
        if self.confirmation_phrase != expected:
            raise ValueError(f"survey confirmation phrase must be exactly {expected!r}")
        if self.result_directory.name != self.survey_id:
            raise ValueError("survey result directory must end in the survey id")
        inventory_payload = canonical_json_bytes(self.emitter_inventory)
        if (
            self.emitter_inventory_file.bytes != len(inventory_payload)
            or self.emitter_inventory_file.sha256 != hashlib.sha256(inventory_payload).hexdigest()
        ):
            raise ValueError("emitter inventory file identity disagrees with embedded bytes")
        if self.parameters.occupied_2_4_spans_hz != project_occupied_2_4_spans(
            self.emitter_inventory
        ):
            raise ValueError("survey parameters disagree with emitter inventory projection")
        return self


class TxStateObservation(ApiModel):
    observed_at: datetime
    tx_gain_db: tuple[float, float]
    tx_buffer_enabled: bool
    tx_data_available: int = Field(ge=0)
    tx_scan_enabled: tuple[bool, bool, bool, bool]
    dds_raw: tuple[int, int, int, int, int, int, int, int]
    dds_scale: tuple[float, float, float, float, float, float, float, float]
    dac_selectors: tuple[int, int, int, int]
    tandem_state: int = Field(ge=0)
    fifo_level: int = Field(ge=0)
    fault_flags: int = Field(ge=0)
    overflow_count: int = Field(ge=0)
    safe: bool

    @field_validator("observed_at")
    @classmethod
    def validate_observed_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
            raise ValueError("TX observation time must be expressed in UTC")
        return value

    @model_validator(mode="after")
    def validate_safe_verdict(self) -> TxStateObservation:
        expected = tx_state_is_safe(self)
        if self.safe != expected:
            raise ValueError("TX safe verdict disagrees with the complete observation")
        return self


class SurveyRuntimeIdentity(ApiModel):
    serial: Serial
    usb_uri: UsbUri
    usb_path: Path
    hardware_model: str = Field(min_length=1, max_length=256)
    firmware_version: str = Field(min_length=1, max_length=256)
    metadata_abi: str | None = Field(default=None, max_length=64)


class SurveyArtifactIdentity(ApiModel):
    relative_path: Path
    bytes: int = Field(gt=0)
    sha256: Sha256

    @field_validator("relative_path")
    @classmethod
    def validate_relative_path(cls, value: Path) -> Path:
        if value.is_absolute() or not value.parts or ".." in value.parts or "." in value.parts:
            raise ValueError("survey artifact path must be normalized and relative")
        return value


class SurveyArtifactFile(ApiModel):
    identity: SurveyArtifactIdentity
    dtype: Literal["ci16_le", "float32_le"]
    shape: tuple[int, ...]

    @field_validator("shape")
    @classmethod
    def validate_shape(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        if not value or any(item <= 0 for item in value):
            raise ValueError("survey artifact shape must contain positive dimensions")
        return value


class SurveyRxSettingsReadback(ApiModel):
    center_frequency_hz: float
    sample_rate_hz: float
    rf_bandwidth_hz: float
    receiver_channels: tuple[int, ...]
    receiver_gain_modes: tuple[GainMode, ...]
    receiver_gain_db: tuple[float, ...]
    sample_rate_source_channels: tuple[Literal[0, 1], ...]
    sample_rate_source_values_hz: tuple[float, ...]
    rf_bandwidth_source_channels: tuple[Literal[0, 1], ...]
    rf_bandwidth_source_values_hz: tuple[float, ...]
    shared_phy_provenance: Literal["ad9361-phy-rx-exposed-attributes"] = (
        "ad9361-phy-rx-exposed-attributes"
    )

    @model_validator(mode="after")
    def validate_finite(self) -> SurveyRxSettingsReadback:
        if (
            not self.receiver_channels
            or tuple(sorted(set(self.receiver_channels))) != self.receiver_channels
            or any(channel not in (0, 1) for channel in self.receiver_channels)
            or len(self.receiver_gain_modes) != len(self.receiver_channels)
            or len(self.receiver_gain_db) != len(self.receiver_channels)
        ):
            raise ValueError(
                "survey RX settings must bind a canonical nonempty RX0/RX1 subset "
                "with one mode and gain readback per channel"
            )
        numeric = (
            self.center_frequency_hz,
            self.sample_rate_hz,
            self.rf_bandwidth_hz,
            *self.receiver_gain_db,
            *self.sample_rate_source_values_hz,
            *self.rf_bandwidth_source_values_hz,
        )
        if not all(math.isfinite(value) for value in numeric):
            raise ValueError("survey RX settings readback must be finite")
        for channels, values, scalar, label in (
            (
                self.sample_rate_source_channels,
                self.sample_rate_source_values_hz,
                self.sample_rate_hz,
                "sample rate",
            ),
            (
                self.rf_bandwidth_source_channels,
                self.rf_bandwidth_source_values_hz,
                self.rf_bandwidth_hz,
                "RF bandwidth",
            ),
        ):
            if (
                not channels
                or tuple(sorted(set(channels))) != channels
                or len(channels) != len(values)
            ):
                raise ValueError(f"survey {label} provenance must enumerate exposed RX channels")
            if any(value != scalar for value in values):
                raise ValueError(f"survey shared-PHY {label} differs across exposed RX attributes")
        return self


class SurveyTemperatureReadback(ApiModel):
    millidegrees_c: int = Field(ge=-40_000, le=125_000)
    source_device: Literal["ad9361-phy"] = "ad9361-phy"
    source_channel: Literal["temp0"] = "temp0"
    source_attribute: Literal["input"] = "input"
    shared_phy_reading: Literal[True] = True


class SurveyWindowEvidence(ApiModel):
    window_index: int = Field(ge=0)
    utc_ns: int = Field(gt=0)
    raw_ci16: SurveyArtifactFile
    psd_density_dbfs_per_hz: SurveyArtifactFile
    stft_density_dbfs_per_hz: SurveyArtifactFile
    stft_frames: int = STFT_FRAMES_PER_WINDOW
    bin_width_hz: float = SAMPLE_RATE_HZ / FFT_SIZE
    frequency_offset_start_hz: float = -SAMPLE_RATE_HZ / 2
    receiver_integrated_power_fs: tuple[float, float]
    receiver_integrated_power_dbfs: tuple[float, float]
    receiver_clip_count: tuple[int, int]
    receiver_burst: tuple[bool, bool]

    @model_validator(mode="after")
    def validate_relationships(self) -> SurveyWindowEvidence:
        expected = (
            (self.raw_ci16, "ci16_le", (SAMPLES_PER_WINDOW, 2, 2), RAW_BYTES_PER_WINDOW),
            (
                self.psd_density_dbfs_per_hz,
                "float32_le",
                (2, FFT_SIZE),
                2 * FFT_SIZE * 4,
            ),
            (
                self.stft_density_dbfs_per_hz,
                "float32_le",
                (2, STFT_FRAMES_PER_WINDOW, FFT_SIZE),
                2 * STFT_FRAMES_PER_WINDOW * FFT_SIZE * 4,
            ),
        )
        for artifact, dtype, shape, byte_count in expected:
            if (
                artifact.dtype != dtype
                or artifact.shape != shape
                or artifact.identity.bytes != byte_count
            ):
                raise ValueError("survey artifact type, shape, or byte count is not frozen")
        if not all(
            math.isfinite(value) and value > 0.0 for value in self.receiver_integrated_power_fs
        ) or not all(math.isfinite(value) for value in self.receiver_integrated_power_dbfs):
            raise ValueError("survey integrated linear power must be finite and strictly positive")
        expected_dbfs = tuple(
            _linear_power_to_dbfs(value) for value in self.receiver_integrated_power_fs
        )
        if not all(
            math.isclose(actual, expected, rel_tol=0.0, abs_tol=1e-12)
            for actual, expected in zip(
                self.receiver_integrated_power_dbfs, expected_dbfs, strict=True
            )
        ):
            raise ValueError("survey integrated dBFS does not derive from retained linear power")
        if any(value < 0 for value in self.receiver_clip_count):
            raise ValueError("survey clip counts cannot be negative")
        if (
            self.stft_frames != STFT_FRAMES_PER_WINDOW
            or self.bin_width_hz != SAMPLE_RATE_HZ / FFT_SIZE
            or self.frequency_offset_start_hz != -SAMPLE_RATE_HZ / 2
        ):
            raise ValueError("survey STFT frame or frequency-axis contract is not frozen")
        return self


class SurveyCenterEvidence(ApiModel):
    capture_role: Literal["pre_sweep_anchor", "sweep", "authorizing_baseline", "post_sweep_anchor"]
    center_index: int | None = Field(default=None, ge=0)
    center_frequency_hz: int = Field(gt=0)
    requested_settings: RadioSettings
    actual_settings: SurveyRxSettingsReadback
    pre_capture_temperature: SurveyTemperatureReadback
    post_capture_settings: SurveyRxSettingsReadback
    post_capture_temperature: SurveyTemperatureReadback
    windows: tuple[SurveyWindowEvidence, ...]
    receiver_p50_power_fs: tuple[float, float]
    receiver_p95_power_fs: tuple[float, float]
    receiver_p99_power_fs: tuple[float, float]
    receiver_p50_dbfs: tuple[float, float]
    receiver_p95_dbfs: tuple[float, float]
    receiver_p99_dbfs: tuple[float, float]
    receiver_clip_count: tuple[int, int]
    receiver_burst_occupancy: tuple[float, float]
    worst_rx_p99_dbfs: float
    worst_rx_burst_occupancy: float

    @model_validator(mode="after")
    def validate_relationships(self) -> SurveyCenterEvidence:
        if len(self.windows) != WINDOWS_PER_CENTER:
            raise ValueError("every retained center must contain exactly 32 windows")
        if tuple(item.window_index for item in self.windows) != tuple(range(WINDOWS_PER_CENTER)):
            raise ValueError("survey window indexes must be contiguous")
        if self.capture_role == "sweep":
            if self.center_index is None or self.center_index >= len(SURVEY_CENTER_FREQUENCIES_HZ):
                raise ValueError("sweep center index is unavailable or outside the frozen grid")
            if self.center_frequency_hz != SURVEY_CENTER_FREQUENCIES_HZ[self.center_index]:
                raise ValueError("sweep center index and frequency disagree")
        elif self.capture_role == "authorizing_baseline":
            if (
                self.center_index is None
                or self.center_index >= len(AUTHORIZING_BASELINE_FREQUENCIES_HZ)
                or self.center_frequency_hz
                != AUTHORIZING_BASELINE_FREQUENCIES_HZ[self.center_index]
            ):
                raise ValueError("authorizing baseline index and frequency disagree")
        elif (
            self.center_index is not None or self.center_frequency_hz != ANCHOR_CENTER_FREQUENCY_HZ
        ):
            raise ValueError("anchor role requires the fixed 2.445 GHz center and no grid index")
        if self.requested_settings.center_frequency_hz != self.center_frequency_hz:
            raise ValueError("survey requested LO disagrees with the retained center")
        _validate_survey_readback(self.requested_settings, self.actual_settings)
        _validate_survey_readback(self.requested_settings, self.post_capture_settings)
        if self.capture_role == "sweep":
            assert self.center_index is not None
            base = Path("sweep") / f"{self.center_index:03d}-{self.center_frequency_hz}"
        elif self.capture_role == "authorizing_baseline":
            assert self.center_index is not None
            base = Path("baselines") / f"{self.center_index:03d}-{self.center_frequency_hz}"
        else:
            base = Path("anchors") / ("pre" if self.capture_role == "pre_sweep_anchor" else "post")
        for window in self.windows:
            window_root = base / f"window-{window.window_index:03d}"
            expected_paths = (
                window_root / "raw.ci16",
                window_root / "psd-density-dbfs-per-hz.f32le",
                window_root / "stft-density-dbfs-per-hz.f32le",
            )
            actual_paths = (
                window.raw_ci16.identity.relative_path,
                window.psd_density_dbfs_per_hz.identity.relative_path,
                window.stft_density_dbfs_per_hz.identity.relative_path,
            )
            if actual_paths != expected_paths:
                raise ValueError("survey artifact paths disagree with center/window chronology")
        p50_linear, p95_linear, p99_linear, p50, p95, p99, clips, occupancy, bursts = (
            _summarize_windows(self.windows)
        )
        for actual, expected in (
            (self.receiver_p50_power_fs, p50_linear),
            (self.receiver_p95_power_fs, p95_linear),
            (self.receiver_p99_power_fs, p99_linear),
            (self.receiver_p50_dbfs, p50),
            (self.receiver_p95_dbfs, p95),
            (self.receiver_p99_dbfs, p99),
            (self.receiver_burst_occupancy, occupancy),
        ):
            if not all(
                math.isclose(a, e, rel_tol=0.0, abs_tol=1e-12)
                for a, e in zip(actual, expected, strict=True)
            ):
                raise ValueError("survey center statistics disagree with retained windows")
        if self.receiver_clip_count != clips:
            raise ValueError("survey center clip counts disagree with retained windows")
        if tuple(window.receiver_burst for window in self.windows) != bursts:
            raise ValueError("survey burst flags disagree with the strict median+6 dB rule")
        if not math.isclose(self.worst_rx_p99_dbfs, max(p99), rel_tol=0.0, abs_tol=1e-12):
            raise ValueError("survey worst-RX p99 disagrees with receiver statistics")
        if not math.isclose(
            self.worst_rx_burst_occupancy, max(occupancy), rel_tol=0.0, abs_tol=1e-12
        ):
            raise ValueError("survey worst-RX burst occupancy disagrees with receiver statistics")
        return self


class SurveyAnchorDrift(ApiModel):
    p99_delta_db: tuple[float, float]
    occupancy_delta: tuple[float, float]
    maximum_absolute_p99_delta_db: float = Field(ge=0)
    maximum_absolute_occupancy_delta: float = Field(ge=0)
    anchor_clipping_detected: bool
    p99_limit_db: float = P99_DRIFT_LIMIT_DB
    occupancy_limit: float = OCCUPANCY_DRIFT_LIMIT
    passed: bool

    @model_validator(mode="after")
    def validate_verdict(self) -> SurveyAnchorDrift:
        if self.p99_limit_db != P99_DRIFT_LIMIT_DB or self.occupancy_limit != OCCUPANCY_DRIFT_LIMIT:
            raise ValueError("survey anchor drift limits are frozen")
        maximum_p99 = max(abs(value) for value in self.p99_delta_db)
        maximum_occupancy = max(abs(value) for value in self.occupancy_delta)
        if not math.isclose(
            self.maximum_absolute_p99_delta_db, maximum_p99, rel_tol=0.0, abs_tol=1e-12
        ) or not math.isclose(
            self.maximum_absolute_occupancy_delta,
            maximum_occupancy,
            rel_tol=0.0,
            abs_tol=1e-12,
        ):
            raise ValueError("survey anchor drift maxima disagree with per-RX deltas")
        expected = bool(
            not self.anchor_clipping_detected
            and maximum_p99 <= self.p99_limit_db
            and maximum_occupancy <= self.occupancy_limit
        )
        if self.passed != expected:
            raise ValueError("survey anchor drift verdict disagrees with frozen limits")
        return self


class SurveySelectedControlBaseline(ApiModel):
    center_frequency_hz: int = Field(gt=0)
    receiver_p50_power_fs: tuple[float, float]
    receiver_p95_power_fs: tuple[float, float]
    receiver_p99_power_fs: tuple[float, float]
    receiver_p50_dbfs: tuple[float, float]
    receiver_p95_dbfs: tuple[float, float]
    receiver_p99_dbfs: tuple[float, float]
    receiver_clip_count: tuple[int, int]
    receiver_burst_occupancy: tuple[float, float]


def _selected_control_baseline(center: SurveyCenterEvidence) -> SurveySelectedControlBaseline:
    if center.capture_role != "sweep":
        raise ValueError("selected control baseline must derive from a sweep center")
    return SurveySelectedControlBaseline(
        center_frequency_hz=center.center_frequency_hz,
        receiver_p50_power_fs=center.receiver_p50_power_fs,
        receiver_p95_power_fs=center.receiver_p95_power_fs,
        receiver_p99_power_fs=center.receiver_p99_power_fs,
        receiver_p50_dbfs=center.receiver_p50_dbfs,
        receiver_p95_dbfs=center.receiver_p95_dbfs,
        receiver_p99_dbfs=center.receiver_p99_dbfs,
        receiver_clip_count=center.receiver_clip_count,
        receiver_burst_occupancy=center.receiver_burst_occupancy,
    )


class EnvironmentSurveyManifest(ApiModel):
    schema_id: Literal["pluto-plus-utils.environment-survey-manifest.v1"] = Field(
        SURVEY_MANIFEST_SCHEMA, alias="schema"
    )
    schema_version: Literal[1] = 1
    survey_id: Identifier
    capture_complete: bool
    qualified: bool
    runtime: SurveyRuntimeIdentity | None
    parameters: EnvironmentSurveyParameters
    free_space_bytes_before_hardware: int = Field(ge=MINIMUM_FREE_SPACE_BYTES)
    spectrum_algorithm: Literal["ci16-adc12-periodic-hann-fftshift-density-dbfs-per-hz-v1"] = (
        "ci16-adc12-periodic-hann-fftshift-density-dbfs-per-hz-v1"
    )
    pre_sweep_anchor: SurveyCenterEvidence | None
    centers: tuple[SurveyCenterEvidence, ...]
    authorizing_baselines: tuple[SurveyCenterEvidence, ...]
    post_sweep_anchor: SurveyCenterEvidence | None
    anchor_drift: SurveyAnchorDrift | None
    clipped_control_candidates_hz: tuple[int, ...]
    selected_control_frequency_hz: int | None
    selected_control_baseline: SurveySelectedControlBaseline | None
    objective_ranking_hz: tuple[int, ...]

    @model_validator(mode="after")
    def validate_relationships(self) -> EnvironmentSurveyManifest:
        observed = tuple(center.center_frequency_hz for center in self.centers)
        expected_prefix = self.parameters.center_frequencies_hz[: len(observed)]
        if observed != expected_prefix:
            raise ValueError("manifest centers must be the planned contiguous prefix")
        if any(center.capture_role != "sweep" for center in self.centers):
            raise ValueError("manifest sweep list contains an anchor role")
        observed_baselines = tuple(
            center.center_frequency_hz for center in self.authorizing_baselines
        )
        if observed_baselines != AUTHORIZING_BASELINE_FREQUENCIES_HZ[
            : len(observed_baselines)
        ] or any(
            center.capture_role != "authorizing_baseline" for center in self.authorizing_baselines
        ):
            raise ValueError("manifest authorizing baselines are not the frozen prefix")
        if (
            self.pre_sweep_anchor is not None
            and self.pre_sweep_anchor.capture_role != "pre_sweep_anchor"
        ):
            raise ValueError("manifest pre-sweep anchor role is invalid")
        if (
            self.post_sweep_anchor is not None
            and self.post_sweep_anchor.capture_role != "post_sweep_anchor"
        ):
            raise ValueError("manifest post-sweep anchor role is invalid")
        if self.capture_complete:
            if (
                observed != self.parameters.center_frequencies_hz
                or self.runtime is None
                or self.pre_sweep_anchor is None
                or observed_baselines != AUTHORIZING_BASELINE_FREQUENCIES_HZ
                or self.post_sweep_anchor is None
                or self.anchor_drift is None
            ):
                raise ValueError("complete survey capture lacks runtime, anchors, drift, or grid")
            expected_ranking = _objective_ranking(self.parameters, self.centers)
            expected_clipped = _clipped_control_candidates(self.parameters, self.centers)
            if self.objective_ranking_hz != expected_ranking:
                raise ValueError("complete survey objective ranking disagrees with retained data")
            if self.clipped_control_candidates_hz != expected_clipped:
                raise ValueError("complete survey clipped candidate set disagrees with data")
        elif (
            self.post_sweep_anchor is not None
            or self.anchor_drift is not None
            or self.clipped_control_candidates_hz
            or self.objective_ranking_hz
        ):
            raise ValueError("incomplete capture cannot publish post-anchor or objective verdicts")
        if self.qualified:
            if (
                not self.capture_complete
                or self.anchor_drift is None
                or not self.anchor_drift.passed
                or any(any(center.receiver_clip_count) for center in self.authorizing_baselines)
                or not self.objective_ranking_hz
                or self.selected_control_frequency_hz != self.objective_ranking_hz[0]
                or self.selected_control_baseline
                != _selected_control_baseline(
                    self.centers[
                        self.parameters.center_frequencies_hz.index(
                            self.selected_control_frequency_hz
                        )
                    ]
                )
            ):
                raise ValueError("qualified survey lacks a passing drift and selected objective")
        elif (
            self.selected_control_frequency_hz is not None
            or self.selected_control_baseline is not None
        ):
            raise ValueError("unqualified survey cannot authorize a control frequency")
        return self


class SurveyCleanup(ApiModel):
    verified: bool
    rx_settings_restored: bool
    tx_safe: bool
    errors: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_verdict(self) -> SurveyCleanup:
        expected = self.rx_settings_restored and self.tx_safe and not self.errors
        if self.verified != expected:
            raise ValueError("survey cleanup verdict disagrees with its evidence")
        return self


class EnvironmentSurveyReceipt(ApiModel):
    schema_id: Literal["pluto-plus-utils.environment-survey-receipt.v1"] = Field(
        SURVEY_RECEIPT_SCHEMA, alias="schema"
    )
    schema_version: Literal[1] = 1
    survey_id: Identifier
    outcome: Literal["pass", "failed"]
    started_at: datetime
    completed_at: datetime
    tool_repository: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")]
    tool_version: Annotated[str, Field(min_length=1, max_length=128)]
    tool_source_commit: SourceCommit
    plan: FileIdentity
    manifest: FileIdentity
    target: EnvironmentSurveyTarget
    emitter_inventory_file: FileIdentity
    runtime: SurveyRuntimeIdentity | None
    free_space_bytes_before_hardware: int = Field(ge=MINIMUM_FREE_SPACE_BYTES)
    pre_mutation_tx: TxStateObservation | None
    ensured_mute_tx: TxStateObservation | None
    post_open_tx: TxStateObservation | None
    post_cleanup_tx: TxStateObservation | None
    original_rx_settings: SurveyRxSettingsReadback | None
    restored_rx_settings: SurveyRxSettingsReadback | None
    anchor_drift: SurveyAnchorDrift | None
    selected_control_frequency_hz: int | None
    cleanup: SurveyCleanup
    failure_phase: str | None = Field(default=None, max_length=128)
    error: str | None = Field(default=None, max_length=2048)
    ssh_used: Literal[False] = False
    route_mutated: Literal[False] = False
    dfu_used: Literal[False] = False
    qspi_written: Literal[False] = False
    pluto_tx_enabled: Literal[False] = False

    @field_validator("started_at", "completed_at")
    @classmethod
    def validate_timestamps(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
            raise ValueError("survey receipt timestamps must be expressed in UTC")
        return value

    @model_validator(mode="after")
    def validate_relationships(self) -> EnvironmentSurveyReceipt:
        if self.completed_at < self.started_at:
            raise ValueError("survey completion precedes its start")
        if self.runtime is not None and (
            self.runtime.serial != self.target.serial
            or self.runtime.usb_uri != self.target.usb_uri
            or self.runtime.usb_path != self.target.usb_path
        ):
            raise ValueError("survey runtime identity disagrees with the exact target")
        if self.outcome == "pass":
            if (
                self.runtime is None
                or self.pre_mutation_tx is None
                or self.ensured_mute_tx is None
                or self.post_open_tx is None
                or self.post_cleanup_tx is None
                or not self.ensured_mute_tx.safe
                or not self.post_open_tx.safe
                or not self.post_cleanup_tx.safe
                or self.original_rx_settings is None
                or not _rx_settings_restored(self.original_rx_settings, self.restored_rx_settings)
                or self.anchor_drift is None
                or not self.anchor_drift.passed
                or self.selected_control_frequency_hz is None
                or not self.cleanup.verified
                or self.failure_phase is not None
                or self.error is not None
            ):
                raise ValueError("passing survey receipt lacks complete safety evidence")
        elif self.failure_phase is None or self.error is None:
            raise ValueError("failed survey receipt must identify its failure")
        return self


class FleetSurveyReference(ApiModel):
    serial: Serial
    survey_id: Identifier
    plan: FileIdentity
    manifest: FileIdentity
    receipt: FileIdentity
    runtime: SurveyRuntimeIdentity

    @model_validator(mode="after")
    def validate_relationships(self) -> FleetSurveyReference:
        if self.runtime.serial != self.serial:
            raise ValueError("fleet survey reference runtime serial disagrees")
        return self


class FleetCandidateRadioEvidence(ApiModel):
    serial: Serial
    receiver_p99_dbfs: tuple[float, float]
    receiver_burst_occupancy: tuple[float, float]
    receiver_clip_count: tuple[int, int]

    @model_validator(mode="after")
    def validate_metrics(self) -> FleetCandidateRadioEvidence:
        if not all(math.isfinite(value) for value in self.receiver_p99_dbfs):
            raise ValueError("fleet p99 values must be finite")
        if not all(
            math.isfinite(value) and 0.0 <= value <= 1.0 for value in self.receiver_burst_occupancy
        ):
            raise ValueError("fleet occupancy values must be finite probabilities")
        if any(value < 0 for value in self.receiver_clip_count):
            raise ValueError("fleet clip counts cannot be negative")
        return self


class FleetCandidateEvidence(ApiModel):
    center_frequency_hz: int = Field(gt=0)
    radios: tuple[FleetCandidateRadioEvidence, ...]
    ap_eligible: bool
    unclipped_on_all_radios: bool
    eligible: bool
    exclusion_reasons: tuple[Literal["occupied-emitter-span", "clipping"], ...]
    worst_radio_rx_p99_dbfs: float
    worst_radio_rx_burst_occupancy: float

    @model_validator(mode="after")
    def validate_relationships(self) -> FleetCandidateEvidence:
        serials = tuple(radio.serial for radio in self.radios)
        if serials != RESERVED_SURVEY_SERIALS:
            raise ValueError("fleet candidate radios must use the reserved canonical order")
        expected_unclipped = not any(any(radio.receiver_clip_count) for radio in self.radios)
        if self.unclipped_on_all_radios != expected_unclipped:
            raise ValueError("fleet candidate clipping verdict disagrees with per-radio evidence")
        expected_eligible = self.ap_eligible and expected_unclipped
        if self.eligible != expected_eligible:
            raise ValueError("fleet candidate eligibility disagrees with its gates")
        expected_reasons: list[Literal["occupied-emitter-span", "clipping"]] = []
        if not self.ap_eligible:
            expected_reasons.append("occupied-emitter-span")
        if not expected_unclipped:
            expected_reasons.append("clipping")
        if self.exclusion_reasons != tuple(expected_reasons):
            raise ValueError("fleet candidate exclusion reasons are not canonical")
        expected_p99 = max(max(radio.receiver_p99_dbfs) for radio in self.radios)
        expected_occupancy = max(max(radio.receiver_burst_occupancy) for radio in self.radios)
        if not math.isclose(
            self.worst_radio_rx_p99_dbfs, expected_p99, rel_tol=0.0, abs_tol=1e-12
        ) or not math.isclose(
            self.worst_radio_rx_burst_occupancy,
            expected_occupancy,
            rel_tol=0.0,
            abs_tol=1e-12,
        ):
            raise ValueError("fleet candidate worst-case metrics disagree with radio/RX evidence")
        return self


class FleetSelectedRadioBaseline(ApiModel):
    serial: Serial
    baseline: SurveySelectedControlBaseline


class EnvironmentSurveyFleetSelection(ApiModel):
    schema_id: Literal["pluto-plus-utils.environment-survey-fleet-selection.v1"] = Field(
        SURVEY_FLEET_SELECTION_SCHEMA, alias="schema"
    )
    schema_version: Literal[1] = 1
    created_at: datetime
    tool_repository: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")]
    tool_version: Annotated[str, Field(min_length=1, max_length=128)]
    tool_source_commit: SourceCommit
    emitter_inventory_file: FileIdentity
    emitter_inventory: EnvironmentSurveyEmitterInventory
    occupied_2_4_spans_hz: tuple[SurveyFrequencySpan, ...]
    surveys: tuple[FleetSurveyReference, ...]
    candidates: tuple[FleetCandidateEvidence, ...]
    objective_rule: Literal[
        "minimum-global-worst-rx-p99-then-burst-occupancy-then-lowest-frequency"
    ] = FLEET_OBJECTIVE_RULE
    objective_ranking_hz: tuple[int, ...]
    selected_control_frequency_hz: int
    selected_radio_baselines: tuple[FleetSelectedRadioBaseline, ...]
    receipts_and_artifacts_verified: Literal[True] = True

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
            raise ValueError("fleet selection creation time must be expressed in UTC")
        return value

    @model_validator(mode="after")
    def validate_relationships(self) -> EnvironmentSurveyFleetSelection:
        payload = canonical_json_bytes(self.emitter_inventory)
        if (
            self.emitter_inventory_file.bytes != len(payload)
            or self.emitter_inventory_file.sha256 != hashlib.sha256(payload).hexdigest()
            or self.occupied_2_4_spans_hz != project_occupied_2_4_spans(self.emitter_inventory)
        ):
            raise ValueError("fleet emitter inventory identity or projection disagrees")
        if tuple(reference.serial for reference in self.surveys) != RESERVED_SURVEY_SERIALS:
            raise ValueError("fleet survey references must use the reserved canonical order")
        if tuple(candidate.center_frequency_hz for candidate in self.candidates) != (
            SURVEY_CENTER_FREQUENCIES_HZ
        ):
            raise ValueError("fleet candidates must contain the exact frozen grid")
        ap_candidates = set(_ap_eligible_candidates(self.occupied_2_4_spans_hz))
        for candidate in self.candidates:
            if candidate.ap_eligible != (candidate.center_frequency_hz in ap_candidates):
                raise ValueError("fleet candidate AP eligibility disagrees with emitter spans")
        ranked = tuple(
            candidate.center_frequency_hz
            for candidate in sorted(
                (candidate for candidate in self.candidates if candidate.eligible),
                key=lambda candidate: (
                    candidate.worst_radio_rx_p99_dbfs,
                    candidate.worst_radio_rx_burst_occupancy,
                    candidate.center_frequency_hz,
                ),
            )
        )
        if not ranked:
            raise ValueError("fleet has no AP-eligible unclipped control candidate")
        if self.objective_ranking_hz != ranked or self.selected_control_frequency_hz != ranked[0]:
            raise ValueError("fleet selection disagrees with the frozen global objective")
        if tuple(item.serial for item in self.selected_radio_baselines) != RESERVED_SURVEY_SERIALS:
            raise ValueError("fleet selected baselines must use the reserved canonical order")
        selected = self.candidates[SURVEY_CENTER_FREQUENCIES_HZ.index(ranked[0])]
        for retained, radio in zip(self.selected_radio_baselines, selected.radios, strict=True):
            baseline = retained.baseline
            if (
                retained.serial != radio.serial
                or baseline.center_frequency_hz != ranked[0]
                or baseline.receiver_p99_dbfs != radio.receiver_p99_dbfs
                or baseline.receiver_burst_occupancy != radio.receiver_burst_occupancy
                or baseline.receiver_clip_count != radio.receiver_clip_count
            ):
                raise ValueError("fleet selected baseline disagrees with selected candidate")
        return self


class SurveySession(Protocol):
    @property
    def runtime(self) -> SurveyRuntimeIdentity: ...

    def observe_tx_state(self) -> TxStateObservation: ...

    def ensure_tx_safe(self) -> TxStateObservation: ...

    def open_rx(self) -> TxStateObservation: ...

    def read_rx_settings(self) -> SurveyRxSettingsReadback: ...

    def apply_rx_settings(self, settings: RadioSettings) -> SurveyRxSettingsReadback: ...

    def read_survey_rx_settings(self) -> SurveyRxSettingsReadback: ...

    def read_temperature(self) -> SurveyTemperatureReadback: ...

    def read_rx_block(self, sample_count: int) -> SampleBlock: ...

    def reset_rx_buffer(self) -> None: ...

    def restore_rx_settings(
        self, settings: SurveyRxSettingsReadback
    ) -> SurveyRxSettingsReadback: ...


class SurveyBackend(Protocol):
    def locked_session(
        self, target: EnvironmentSurveyTarget
    ) -> AbstractContextManager[SurveySession]: ...


def tx_state_is_safe(observation: TxStateObservation) -> bool:
    """Apply the complete, fail-closed local TX safety predicate."""

    return bool(
        all(math.isfinite(value) and value <= -80.0 for value in observation.tx_gain_db)
        and observation.tx_buffer_enabled is False
        and observation.tx_data_available == 0
        and not any(observation.tx_scan_enabled)
        and not any(observation.dds_raw)
        and all(math.isfinite(value) and value == 0.0 for value in observation.dds_scale)
        and observation.dac_selectors == (3, 3, 3, 3)
        and observation.tandem_state == 0
        and observation.fifo_level == 0
        and observation.fault_flags == 0
        and observation.overflow_count == 0
    )


def make_tx_state_observation(**values: Any) -> TxStateObservation:
    """Build one observation with a verdict derived from, never supplied beside, its values."""

    required = ("tx_buffer_enabled", "tx_data_available", "tx_scan_enabled")
    if any(values.get(name) is None for name in required):
        raise EnvironmentSurveyError(
            "complete TX observation requires affirmative buffer/data/scan readback"
        )
    provisional = TxStateObservation.model_construct(_fields_set=None, **values, safe=False)
    return TxStateObservation.model_validate({**values, "safe": tx_state_is_safe(provisional)})


def prepare_environment_survey(
    devices: Sequence[LocalUsbPluto],
    *,
    serial: str,
    usb_path: Path,
    output_root: Path,
    emitter_inventory_file: FileIdentity,
    emitter_inventory: EnvironmentSurveyEmitterInventory,
    parameters: EnvironmentSurveyParameters,
    tool_source: ToolSourceAttestation,
    tool_version: str,
    survey_id: str | None = None,
    created_at: datetime | None = None,
) -> EnvironmentSurveyPlan:
    """Create a no-hardware plan from one passive, exact USB inventory."""

    if not usb_path.is_absolute() or ".." in usb_path.parts:
        raise EnvironmentSurveyError("survey USB path must be absolute and normalized")
    if serial not in RESERVED_SURVEY_SERIALS:
        raise EnvironmentSurveyError("survey serial is not one of the four reserved radios")
    matches = tuple(device for device in devices if device.serial == serial)
    if len(matches) != 1:
        raise EnvironmentSurveyError(
            f"survey exact serial must match one runtime USB Pluto+, found {len(matches)}"
        )
    selected = matches[0]
    if not selected.confirmed_plus:
        raise EnvironmentSurveyError("survey target is not a confirmed Pluto+")
    if Path(selected.usb_path) != usb_path:
        raise EnvironmentSurveyError("survey target USB path differs from the requested path")
    if selected.bus_number is None or selected.device_number is None:
        raise EnvironmentSurveyError("survey target lacks a usable USB bus/device address")
    if selected.interface_count is None or selected.interface_count < 7:
        raise EnvironmentSurveyError("survey target lacks the canonical Pluto+ USB functions")
    _require_private_directory(output_root, label="survey output root")
    identifier = survey_id or uuid.uuid4().hex
    target = EnvironmentSurveyTarget(
        serial=serial,
        topology=usb_path.name,
        usb_path=usb_path,
        bus_number=selected.bus_number,
        device_number=selected.device_number,
        usb_uri=f"usb:{selected.bus_number}.{selected.device_number}.5",
    )
    result_directory = output_root / identifier
    if result_directory.exists() or (output_root / f".{identifier}.partial").exists():
        raise EnvironmentSurveyError("survey result destination already exists")
    phrase = f"EXECUTE RX ENVIRONMENT SURVEY {serial} {identifier}"
    return EnvironmentSurveyPlan(
        schema=SURVEY_PLAN_SCHEMA,
        survey_id=identifier,
        created_at=created_at or datetime.now(UTC),
        tool_repository=tool_source.repository,
        tool_version=tool_version,
        tool_source_commit=tool_source.commit,
        target=target,
        emitter_inventory_file=emitter_inventory_file,
        emitter_inventory=emitter_inventory,
        parameters=parameters,
        result_directory=result_directory,
        confirmation_phrase=phrase,
    )


def execute_environment_survey(
    plan_path: Path,
    *,
    expected_plan_sha256: Sha256,
    confirmation: str,
    ensure_mute: bool,
    backend: SurveyBackend,
    tool_source: ToolSourceAttestation,
    tool_version: str,
) -> tuple[EnvironmentSurveyReceipt, str]:
    """Execute one retained plan, always attempting RX restore and full TX cleanup."""

    plan = load_private_contract(plan_path, EnvironmentSurveyPlan)
    plan_identity = model_file_identity(plan_path, plan)
    if plan_identity.sha256 != expected_plan_sha256:
        raise EnvironmentSurveyError(
            "survey plan SHA-256 differs from the explicitly approved digest"
        )
    if confirmation != plan.confirmation_phrase:
        raise EnvironmentSurveyError(
            f"survey execution requires exact confirmation {plan.confirmation_phrase!r}"
        )
    if not ensure_mute or not plan.ensure_mute_authorized:
        raise EnvironmentSurveyError("survey execution requires explicit --ensure-mute authority")
    if (
        tool_source.repository != plan.tool_repository
        or tool_source.commit != plan.tool_source_commit
        or tool_version != plan.tool_version
    ):
        raise EnvironmentSurveyError("survey tool repository, commit, or version changed from plan")
    final = plan.result_directory
    _require_private_directory(final.parent, label="survey result parent")
    partial = final.parent / f".{plan.survey_id}.partial"
    if final.exists() or partial.exists():
        raise EnvironmentSurveyError("survey plan has already been attempted")
    free_space_bytes = _available_free_space_bytes(final.parent)
    if free_space_bytes < plan.parameters.minimum_free_space_bytes:
        raise EnvironmentSurveyError(
            "survey requires at least "
            f"{plan.parameters.minimum_free_space_bytes} free bytes before hardware access; "
            f"found {free_space_bytes}"
        )
    partial.mkdir(mode=0o700)
    started_at = datetime.now(UTC)
    runtime: SurveyRuntimeIdentity | None = None
    pre_tx: TxStateObservation | None = None
    muted_tx: TxStateObservation | None = None
    post_open_tx: TxStateObservation | None = None
    post_tx: TxStateObservation | None = None
    original: SurveyRxSettingsReadback | None = None
    restored: SurveyRxSettingsReadback | None = None
    pre_anchor: SurveyCenterEvidence | None = None
    post_anchor: SurveyCenterEvidence | None = None
    anchor_drift: SurveyAnchorDrift | None = None
    centers: list[SurveyCenterEvidence] = []
    authorizing_baselines: list[SurveyCenterEvidence] = []
    capture_complete = False
    ranking: tuple[int, ...] = ()
    clipped_candidates: tuple[int, ...] = ()
    cleanup_errors: list[str] = []
    failure: BaseException | None = None
    failure_phase = "acquire_radio"
    session: SurveySession | None = None
    rx_opened = False
    try:
        with backend.locked_session(plan.target) as active:
            session = active
            runtime = session.runtime
            try:
                failure_phase = "observe_pre_mutation_tx"
                pre_tx = session.observe_tx_state()
                failure_phase = "ensure_mute_before_rx_open"
                muted_tx = session.ensure_tx_safe()
                if not muted_tx.safe:
                    raise EnvironmentSurveyError(
                        "explicit TX mute did not reach complete safe state"
                    )
                failure_phase = "open_rx"
                post_open_tx = session.open_rx()
                rx_opened = True
                if not post_open_tx.safe:
                    raise EnvironmentSurveyError("RX open did not retain complete TX safe state")
                failure_phase = "snapshot_rx_settings"
                original = session.read_rx_settings()
                failure_phase = "capture_pre_sweep_anchor"
                _require_remaining_capture_space(
                    final.parent,
                    remaining_payload_bytes=plan.parameters.capture_payload_bytes,
                    failure_reserve_bytes=plan.parameters.failure_reserve_bytes,
                    manifest_allowance_bytes=plan.parameters.manifest_allowance_bytes,
                )
                pre_anchor = _capture_center(
                    session,
                    plan,
                    partial,
                    capture_role="pre_sweep_anchor",
                    center_index=None,
                    center_frequency_hz=plan.parameters.anchor_center_frequency_hz,
                )
                for center_index, center_hz in enumerate(plan.parameters.center_frequencies_hz):
                    failure_phase = f"capture_center_{center_index}"
                    remaining_centers = (
                        len(plan.parameters.center_frequencies_hz)
                        - center_index
                        + len(plan.parameters.authorizing_baseline_frequencies_hz)
                        + 1
                    )
                    _require_remaining_capture_space(
                        final.parent,
                        remaining_payload_bytes=(
                            remaining_centers
                            * plan.parameters.windows_per_center
                            * (RAW_BYTES_PER_WINDOW + SPECTRAL_BYTES_PER_WINDOW)
                        ),
                        failure_reserve_bytes=plan.parameters.failure_reserve_bytes,
                        manifest_allowance_bytes=plan.parameters.manifest_allowance_bytes,
                    )
                    centers.append(
                        _capture_center(
                            session,
                            plan,
                            partial,
                            capture_role="sweep",
                            center_index=center_index,
                            center_frequency_hz=center_hz,
                        )
                    )
                for baseline_index, baseline_hz in enumerate(
                    plan.parameters.authorizing_baseline_frequencies_hz
                ):
                    failure_phase = f"capture_authorizing_baseline_{baseline_index}"
                    remaining_centers = (
                        len(plan.parameters.authorizing_baseline_frequencies_hz)
                        - baseline_index
                        + 1
                    )
                    _require_remaining_capture_space(
                        final.parent,
                        remaining_payload_bytes=(
                            remaining_centers
                            * plan.parameters.windows_per_center
                            * (RAW_BYTES_PER_WINDOW + SPECTRAL_BYTES_PER_WINDOW)
                        ),
                        failure_reserve_bytes=plan.parameters.failure_reserve_bytes,
                        manifest_allowance_bytes=plan.parameters.manifest_allowance_bytes,
                    )
                    authorizing_baselines.append(
                        _capture_center(
                            session,
                            plan,
                            partial,
                            capture_role="authorizing_baseline",
                            center_index=baseline_index,
                            center_frequency_hz=baseline_hz,
                        )
                    )
                failure_phase = "capture_post_sweep_anchor"
                _require_remaining_capture_space(
                    final.parent,
                    remaining_payload_bytes=(
                        plan.parameters.anchor_windows
                        * (RAW_BYTES_PER_WINDOW + SPECTRAL_BYTES_PER_WINDOW)
                    ),
                    failure_reserve_bytes=plan.parameters.failure_reserve_bytes,
                    manifest_allowance_bytes=plan.parameters.manifest_allowance_bytes,
                )
                post_anchor = _capture_center(
                    session,
                    plan,
                    partial,
                    capture_role="post_sweep_anchor",
                    center_index=None,
                    center_frequency_hz=plan.parameters.anchor_center_frequency_hz,
                )
                capture_complete = True
                anchor_drift = _measure_anchor_drift(pre_anchor, post_anchor)
                ranking = _objective_ranking(plan.parameters, centers)
                clipped_candidates = _clipped_control_candidates(plan.parameters, centers)
                failure_phase = "validate_authorizing_baselines"
                if any(any(baseline.receiver_clip_count) for baseline in authorizing_baselines):
                    raise EnvironmentSurveyError(
                        "an authorizing TX-muted baseline clipped on at least one RX path"
                    )
                failure_phase = "validate_anchor_drift"
                if not anchor_drift.passed:
                    raise EnvironmentSurveyError(
                        "pre/post 2.445 GHz anchor drift or clipping exceeded the frozen gate"
                    )
                failure_phase = "select_control_frequency"
                if not ranking:
                    raise EnvironmentSurveyError(
                        "every AP-eligible control candidate clipped; no control is authorized"
                    )
            except BaseException as error:
                failure = error
            finally:
                if rx_opened:
                    try:
                        session.reset_rx_buffer()
                    except BaseException as error:
                        cleanup_errors.append(f"RX buffer reset: {type(error).__name__}: {error}")
                if original is not None and rx_opened:
                    try:
                        restored = session.restore_rx_settings(original)
                    except BaseException as error:
                        cleanup_errors.append(
                            f"RX settings restore: {type(error).__name__}: {error}"
                        )
                try:
                    post_tx = session.ensure_tx_safe()
                    if not post_tx.safe:
                        cleanup_errors.append("post-cleanup complete TX state is unsafe")
                except BaseException as error:
                    cleanup_errors.append(f"TX cleanup: {type(error).__name__}: {error}")
    except BaseException as error:
        if session is not None:
            cleanup_errors.append(f"radio session release: {type(error).__name__}: {error}")
            if failure is None:
                failure = error
                failure_phase = "release_radio_session"
        elif failure is None:
            failure = error
    rx_restored = _rx_settings_restored(original, restored)
    tx_safe = post_tx is not None and post_tx.safe
    cleanup = SurveyCleanup(
        verified=rx_restored and tx_safe and not cleanup_errors,
        rx_settings_restored=rx_restored,
        tx_safe=tx_safe,
        errors=tuple(cleanup_errors),
    )
    if failure is None and not cleanup.verified:
        failure = EnvironmentSurveyError("survey cleanup could not be verified")
        failure_phase = "cleanup"
    qualified = failure is None
    selected_control = ranking[0] if qualified and ranking else None
    selected_baseline = (
        None
        if selected_control is None
        else _selected_control_baseline(
            centers[plan.parameters.center_frequencies_hz.index(selected_control)]
        )
    )
    manifest = EnvironmentSurveyManifest(
        schema=SURVEY_MANIFEST_SCHEMA,
        survey_id=plan.survey_id,
        capture_complete=capture_complete,
        qualified=qualified,
        runtime=runtime,
        parameters=plan.parameters,
        free_space_bytes_before_hardware=free_space_bytes,
        pre_sweep_anchor=pre_anchor,
        centers=tuple(centers),
        authorizing_baselines=tuple(authorizing_baselines),
        post_sweep_anchor=post_anchor,
        anchor_drift=anchor_drift,
        clipped_control_candidates_hz=clipped_candidates,
        selected_control_frequency_hz=selected_control,
        selected_control_baseline=selected_baseline,
        objective_ranking_hz=ranking if capture_complete else (),
    )
    manifest_final_path = final / "manifest.json"
    manifest_payload = canonical_json_bytes(manifest)
    manifest_identity = model_file_identity(manifest_final_path, manifest)
    outcome: Literal["pass", "failed"] = "pass" if qualified else "failed"
    receipt = EnvironmentSurveyReceipt(
        schema=SURVEY_RECEIPT_SCHEMA,
        survey_id=plan.survey_id,
        outcome=outcome,
        started_at=started_at,
        completed_at=datetime.now(UTC),
        tool_repository=tool_source.repository,
        tool_version=tool_version,
        tool_source_commit=tool_source.commit,
        plan=plan_identity,
        manifest=manifest_identity,
        target=plan.target,
        emitter_inventory_file=plan.emitter_inventory_file,
        runtime=runtime,
        free_space_bytes_before_hardware=free_space_bytes,
        pre_mutation_tx=pre_tx,
        ensured_mute_tx=muted_tx,
        post_open_tx=post_open_tx,
        post_cleanup_tx=post_tx,
        original_rx_settings=original,
        restored_rx_settings=restored,
        anchor_drift=anchor_drift,
        selected_control_frequency_hz=selected_control,
        cleanup=cleanup,
        failure_phase=None if qualified else failure_phase,
        error=(None if qualified else f"{type(failure).__name__}: {failure}"[:2048]),
    )
    receipt_payload = canonical_json_bytes(receipt)
    if len(manifest_payload) + len(receipt_payload) > plan.parameters.failure_reserve_bytes:
        raise EnvironmentSurveyError("survey manifest and receipt exceed the 64 MiB failure cap")
    _write_private_bytes(partial / "manifest.json", manifest_payload)
    receipt_partial_path = partial / "receipt.json"
    _write_private_bytes(receipt_partial_path, receipt_payload)
    receipt_final_path = final / "receipt.json"
    receipt_digest = hashlib.sha256(receipt_payload).hexdigest()
    os.replace(partial, final)
    _fsync_directory(final.parent)
    if failure is not None:
        raise EnvironmentSurveyExecutionError(
            str(failure), receipt_path=receipt_final_path, receipt_sha256=receipt_digest
        ) from failure
    return receipt, receipt_digest


def verify_environment_survey_receipt(path: Path) -> EnvironmentSurveyReceipt:
    """Verify canonical contracts and every retained raw/spectral artifact digest."""

    receipt = load_private_contract(path, EnvironmentSurveyReceipt)
    plan = load_private_contract(receipt.plan.path, EnvironmentSurveyPlan)
    if model_file_identity(receipt.plan.path, plan) != receipt.plan:
        raise EnvironmentSurveyError("survey plan identity differs from the receipt")
    manifest = load_private_contract(receipt.manifest.path, EnvironmentSurveyManifest)
    if model_file_identity(receipt.manifest.path, manifest) != receipt.manifest:
        raise EnvironmentSurveyError("survey manifest identity differs from the receipt")
    if (
        path != plan.result_directory / "receipt.json"
        or receipt.manifest.path != plan.result_directory / "manifest.json"
        or receipt.survey_id != plan.survey_id
        or receipt.survey_id != manifest.survey_id
        or receipt.target != plan.target
        or receipt.emitter_inventory_file != plan.emitter_inventory_file
        or receipt.runtime != manifest.runtime
        or receipt.tool_repository != plan.tool_repository
        or receipt.tool_version != plan.tool_version
        or receipt.tool_source_commit != plan.tool_source_commit
        or manifest.parameters != plan.parameters
        or receipt.free_space_bytes_before_hardware != manifest.free_space_bytes_before_hardware
        or receipt.anchor_drift != manifest.anchor_drift
        or receipt.selected_control_frequency_hz != manifest.selected_control_frequency_hz
    ):
        raise EnvironmentSurveyError("survey plan, manifest, and receipt disagree")
    retained_centers = (
        (() if manifest.pre_sweep_anchor is None else (manifest.pre_sweep_anchor,))
        + manifest.centers
        + manifest.authorizing_baselines
        + (() if manifest.post_sweep_anchor is None else (manifest.post_sweep_anchor,))
    )
    result_root = receipt.manifest.path.parent
    _require_private_directory(result_root, label="survey result directory")
    for center in retained_centers:
        for window in center.windows:
            raw_payload = _read_private_artifact(result_root, window.raw_ci16.identity)
            psd_payload = _read_private_artifact(
                result_root, window.psd_density_dbfs_per_hz.identity
            )
            stft_payload = _read_private_artifact(
                result_root, window.stft_density_dbfs_per_hz.identity
            )
            _verify_window_derivation(
                window,
                manifest.parameters,
                raw_payload=raw_payload,
                psd_payload=psd_payload,
                stft_payload=stft_payload,
            )
    declared_files = {Path("manifest.json"), Path("receipt.json")}
    for center in retained_centers:
        for window in center.windows:
            declared_files.update(
                (
                    window.raw_ci16.identity.relative_path,
                    window.psd_density_dbfs_per_hz.identity.relative_path,
                    window.stft_density_dbfs_per_hz.identity.relative_path,
                )
            )
    _verify_exact_result_tree(result_root, declared_files)
    if receipt.outcome == "pass" and not manifest.qualified:
        raise EnvironmentSurveyError("passing receipt references an unqualified manifest")
    if receipt.outcome == "failed" and manifest.qualified:
        raise EnvironmentSurveyError("failed receipt references a qualified manifest")
    return receipt


def build_environment_survey_fleet_selection(
    manifest_paths: Sequence[Path],
    receipt_paths: Sequence[Path],
    *,
    emitter_inventory_file: FileIdentity,
    emitter_inventory: EnvironmentSurveyEmitterInventory,
    tool_source: ToolSourceAttestation,
    tool_version: str,
    created_at: datetime | None = None,
) -> EnvironmentSurveyFleetSelection:
    """Deep-verify four PASS surveys and select one global 2.4 GHz control."""

    if len(manifest_paths) != len(RESERVED_SURVEY_SERIALS) or len(receipt_paths) != len(
        RESERVED_SURVEY_SERIALS
    ):
        raise EnvironmentSurveyError("fleet selection requires exactly four manifests and receipts")
    inventory_payload = canonical_json_bytes(emitter_inventory)
    if (
        emitter_inventory_file.bytes != len(inventory_payload)
        or emitter_inventory_file.sha256 != hashlib.sha256(inventory_payload).hexdigest()
    ):
        raise EnvironmentSurveyError("fleet emitter inventory file identity disagrees")

    references: list[FleetSurveyReference] = []
    manifests: list[EnvironmentSurveyManifest] = []
    common_parameters: EnvironmentSurveyParameters | None = None
    for expected_serial, manifest_path, receipt_path in zip(
        RESERVED_SURVEY_SERIALS, manifest_paths, receipt_paths, strict=True
    ):
        receipt = verify_environment_survey_receipt(receipt_path)
        if receipt.outcome != "pass" or not receipt.cleanup.verified:
            raise EnvironmentSurveyError("fleet selection requires four verified PASS receipts")
        if receipt.manifest.path != manifest_path:
            raise EnvironmentSurveyError("explicit fleet manifest does not match its receipt")
        manifest = load_private_contract(manifest_path, EnvironmentSurveyManifest)
        plan = load_private_contract(receipt.plan.path, EnvironmentSurveyPlan)
        if (
            model_file_identity(manifest_path, manifest) != receipt.manifest
            or model_file_identity(receipt.plan.path, plan) != receipt.plan
        ):
            raise EnvironmentSurveyError(
                "fleet plan or manifest identity changed after verification"
            )
        if receipt.target.serial != expected_serial or receipt.runtime is None:
            raise EnvironmentSurveyError("fleet inputs are not in reserved canonical serial order")
        if not manifest.capture_complete or not manifest.qualified:
            raise EnvironmentSurveyError("fleet manifest is not complete and qualified")
        if (
            receipt.tool_repository != tool_source.repository
            or receipt.tool_source_commit != tool_source.commit
            or receipt.tool_version != tool_version
        ):
            raise EnvironmentSurveyError("fleet survey tool source differs from selector source")
        if (
            plan.emitter_inventory != emitter_inventory
            or plan.emitter_inventory_file.bytes != emitter_inventory_file.bytes
            or plan.emitter_inventory_file.sha256 != emitter_inventory_file.sha256
        ):
            raise EnvironmentSurveyError("fleet survey emitter inventory bytes/hash differ")
        if common_parameters is None:
            common_parameters = manifest.parameters
        elif manifest.parameters != common_parameters:
            raise EnvironmentSurveyError("fleet surveys do not share one frozen parameter contract")
        references.append(
            FleetSurveyReference(
                serial=expected_serial,
                survey_id=receipt.survey_id,
                plan=receipt.plan,
                manifest=receipt.manifest,
                receipt=model_file_identity(receipt_path, receipt),
                runtime=receipt.runtime,
            )
        )
        manifests.append(manifest)

    assert common_parameters is not None
    spans = project_occupied_2_4_spans(emitter_inventory)
    if common_parameters.occupied_2_4_spans_hz != spans:
        raise EnvironmentSurveyError("fleet survey parameters differ from emitter projection")
    candidates = _fleet_candidates(tuple(manifests), common_parameters)
    ranking = tuple(
        candidate.center_frequency_hz
        for candidate in sorted(
            (candidate for candidate in candidates if candidate.eligible),
            key=lambda candidate: (
                candidate.worst_radio_rx_p99_dbfs,
                candidate.worst_radio_rx_burst_occupancy,
                candidate.center_frequency_hz,
            ),
        )
    )
    if not ranking:
        raise EnvironmentSurveyError(
            "no 2.4 GHz candidate is AP-eligible and unclipped across all four radios"
        )
    selected_hz = ranking[0]
    selected_baselines = tuple(
        FleetSelectedRadioBaseline(
            serial=serial,
            baseline=_selected_control_baseline(
                manifest.centers[SURVEY_CENTER_FREQUENCIES_HZ.index(selected_hz)]
            ),
        )
        for serial, manifest in zip(RESERVED_SURVEY_SERIALS, manifests, strict=True)
    )
    return EnvironmentSurveyFleetSelection(
        schema=SURVEY_FLEET_SELECTION_SCHEMA,
        created_at=created_at or datetime.now(UTC),
        tool_repository=tool_source.repository,
        tool_version=tool_version,
        tool_source_commit=tool_source.commit,
        emitter_inventory_file=emitter_inventory_file,
        emitter_inventory=emitter_inventory,
        occupied_2_4_spans_hz=spans,
        surveys=tuple(references),
        candidates=candidates,
        objective_ranking_hz=ranking,
        selected_control_frequency_hz=selected_hz,
        selected_radio_baselines=selected_baselines,
    )


def verify_environment_survey_fleet_selection(
    path: Path,
    *,
    tool_source: ToolSourceAttestation,
    tool_version: str,
) -> EnvironmentSurveyFleetSelection:
    """Rebuild one fleet selection from its exact inventory, PASS receipts, and artifacts."""

    retained = load_private_contract(path, EnvironmentSurveyFleetSelection)
    if (
        retained.tool_repository != tool_source.repository
        or retained.tool_source_commit != tool_source.commit
        or retained.tool_version != tool_version
    ):
        raise EnvironmentSurveyError("fleet selection tool source differs from verifier source")
    inventory = load_private_contract(
        retained.emitter_inventory_file.path, EnvironmentSurveyEmitterInventory
    )
    if model_file_identity(retained.emitter_inventory_file.path, inventory) != (
        retained.emitter_inventory_file
    ):
        raise EnvironmentSurveyError("fleet emitter inventory identity changed")
    rebuilt = build_environment_survey_fleet_selection(
        tuple(reference.manifest.path for reference in retained.surveys),
        tuple(reference.receipt.path for reference in retained.surveys),
        emitter_inventory_file=retained.emitter_inventory_file,
        emitter_inventory=inventory,
        tool_source=tool_source,
        tool_version=tool_version,
        created_at=retained.created_at,
    )
    if rebuilt != retained:
        raise EnvironmentSurveyError(
            "fleet selection does not derive from verified source evidence"
        )
    return retained


def _fleet_candidates(
    manifests: tuple[EnvironmentSurveyManifest, ...],
    parameters: EnvironmentSurveyParameters,
) -> tuple[FleetCandidateEvidence, ...]:
    if len(manifests) != len(RESERVED_SURVEY_SERIALS):
        raise ValueError("fleet candidate derivation requires exactly four manifests")
    eligible_hz = set(parameters.control_candidates_hz)
    retained: list[FleetCandidateEvidence] = []
    for center_index, center_hz in enumerate(SURVEY_CENTER_FREQUENCIES_HZ):
        radios = tuple(
            FleetCandidateRadioEvidence(
                serial=serial,
                receiver_p99_dbfs=manifest.centers[center_index].receiver_p99_dbfs,
                receiver_burst_occupancy=manifest.centers[center_index].receiver_burst_occupancy,
                receiver_clip_count=manifest.centers[center_index].receiver_clip_count,
            )
            for serial, manifest in zip(RESERVED_SURVEY_SERIALS, manifests, strict=True)
        )
        ap_eligible = center_hz in eligible_hz
        unclipped = not any(any(radio.receiver_clip_count) for radio in radios)
        reasons: list[Literal["occupied-emitter-span", "clipping"]] = []
        if not ap_eligible:
            reasons.append("occupied-emitter-span")
        if not unclipped:
            reasons.append("clipping")
        retained.append(
            FleetCandidateEvidence(
                center_frequency_hz=center_hz,
                radios=radios,
                ap_eligible=ap_eligible,
                unclipped_on_all_radios=unclipped,
                eligible=ap_eligible and unclipped,
                exclusion_reasons=tuple(reasons),
                worst_radio_rx_p99_dbfs=max(max(radio.receiver_p99_dbfs) for radio in radios),
                worst_radio_rx_burst_occupancy=max(
                    max(radio.receiver_burst_occupancy) for radio in radios
                ),
            )
        )
    return tuple(retained)


@dataclass(frozen=True)
class SpectrumProducts:
    psd_density_dbfs_per_hz: np.ndarray
    stft_density_dbfs_per_hz: np.ndarray
    receiver_integrated_power_fs: tuple[float, float]
    receiver_integrated_power_dbfs: tuple[float, float]
    receiver_clip_count: tuple[int, int]


@dataclass(frozen=True)
class _RetainedWindow:
    window_index: int
    utc_ns: int
    raw_ci16: SurveyArtifactFile
    psd_density_dbfs_per_hz: SurveyArtifactFile
    stft_density_dbfs_per_hz: SurveyArtifactFile
    receiver_integrated_power_fs: tuple[float, float]
    receiver_integrated_power_dbfs: tuple[float, float]
    receiver_clip_count: tuple[int, int]


def _capture_center(
    session: SurveySession,
    plan: EnvironmentSurveyPlan,
    partial: Path,
    *,
    capture_role: Literal["pre_sweep_anchor", "sweep", "authorizing_baseline", "post_sweep_anchor"],
    center_index: int | None,
    center_frequency_hz: int,
) -> SurveyCenterEvidence:
    parameters = plan.parameters
    requested = RadioSettings(
        center_frequency_hz=float(center_frequency_hz),
        sample_rate_hz=float(parameters.sample_rate_hz),
        bandwidth_hz=float(parameters.rf_bandwidth_hz),
        gain_mode=GainMode.MANUAL,
        gain_db=parameters.manual_gain_db,
        channels=(0, 1),
    )
    actual = session.apply_rx_settings(requested)
    _validate_survey_readback(requested, actual)
    pre_temperature = session.read_temperature()
    for _ in range(parameters.settle_buffers):
        session.read_rx_block(parameters.samples_per_window)
    relative_center = _center_relative_path(capture_role, center_index, center_frequency_hz)
    staging = partial / ".center-in-progress"
    destination = partial / relative_center
    published = False
    if staging.exists():
        raise EnvironmentSurveyError("survey center staging directory already exists")
    staging.mkdir(mode=0o700)
    try:
        retained_windows: list[_RetainedWindow] = []
        for window_index in range(parameters.windows_per_center):
            block = session.read_rx_block(parameters.samples_per_window)
            retained_windows.append(
                _retain_window(
                    block,
                    plan,
                    staging,
                    capture_role=capture_role,
                    center_index=center_index,
                    center_frequency_hz=center_frequency_hz,
                    window_index=window_index,
                )
            )
        post_capture = session.read_survey_rx_settings()
        _validate_survey_readback(requested, post_capture)
        post_temperature = session.read_temperature()
        powers = np.asarray(
            [window.receiver_integrated_power_fs for window in retained_windows],
            dtype=np.float64,
        )
        p50_linear = tuple(
            float(value) for value in np.percentile(powers, 50, axis=0, method="linear")
        )
        burst_multiplier = 10.0 ** (parameters.burst_threshold_db / 10.0)
        windows = tuple(
            SurveyWindowEvidence(
                window_index=window.window_index,
                utc_ns=window.utc_ns,
                raw_ci16=window.raw_ci16,
                psd_density_dbfs_per_hz=window.psd_density_dbfs_per_hz,
                stft_density_dbfs_per_hz=window.stft_density_dbfs_per_hz,
                receiver_integrated_power_fs=window.receiver_integrated_power_fs,
                receiver_integrated_power_dbfs=window.receiver_integrated_power_dbfs,
                receiver_clip_count=window.receiver_clip_count,
                receiver_burst=(
                    window.receiver_integrated_power_fs[0] > p50_linear[0] * burst_multiplier,
                    window.receiver_integrated_power_fs[1] > p50_linear[1] * burst_multiplier,
                ),
            )
            for window in retained_windows
        )
        p50_linear, p95_linear, p99_linear, p50, p95, p99, clips, occupancy, _ = _summarize_windows(
            windows
        )
        evidence = SurveyCenterEvidence(
            capture_role=capture_role,
            center_index=center_index,
            center_frequency_hz=center_frequency_hz,
            requested_settings=requested,
            actual_settings=actual,
            pre_capture_temperature=pre_temperature,
            post_capture_settings=post_capture,
            post_capture_temperature=post_temperature,
            windows=windows,
            receiver_p50_power_fs=p50_linear,
            receiver_p95_power_fs=p95_linear,
            receiver_p99_power_fs=p99_linear,
            receiver_p50_dbfs=p50,
            receiver_p95_dbfs=p95,
            receiver_p99_dbfs=p99,
            receiver_clip_count=clips,
            receiver_burst_occupancy=occupancy,
            worst_rx_p99_dbfs=max(p99),
            worst_rx_burst_occupancy=max(occupancy),
        )
        staged_center = staging / relative_center
        _make_private_tree(partial, relative_center.parent)
        if destination.exists():
            raise EnvironmentSurveyError("survey center destination already exists")
        os.replace(staged_center, destination)
        published = True
        _fsync_directory(destination.parent)
        shutil.rmtree(staging)
        _fsync_directory(partial)
        return evidence
    except BaseException as error:
        staging_cleanup_errors: list[BaseException] = []
        if published and destination.exists():
            destination_removed = False
            try:
                shutil.rmtree(destination)
                destination_removed = True
            except BaseException as cleanup_error:
                staging_cleanup_errors.append(cleanup_error)
            if destination_removed:
                try:
                    _fsync_directory(destination.parent)
                except BaseException as cleanup_error:
                    staging_cleanup_errors.append(cleanup_error)
                try:
                    _prune_empty_private_parents(destination.parent, partial)
                except BaseException as cleanup_error:
                    staging_cleanup_errors.append(cleanup_error)
        if staging.exists():
            try:
                shutil.rmtree(staging)
                _fsync_directory(partial)
            except BaseException as cleanup_error:
                staging_cleanup_errors.append(cleanup_error)
        for cleanup_failure in staging_cleanup_errors:
            error.add_note(f"survey center staging cleanup also failed: {cleanup_failure!r}")
        raise


def _center_relative_path(
    capture_role: Literal["pre_sweep_anchor", "sweep", "authorizing_baseline", "post_sweep_anchor"],
    center_index: int | None,
    center_frequency_hz: int,
) -> Path:
    if capture_role == "sweep":
        if center_index is None:
            raise ValueError("sweep center requires an index")
        return Path("sweep") / f"{center_index:03d}-{center_frequency_hz}"
    if capture_role == "authorizing_baseline":
        if center_index is None:
            raise ValueError("authorizing baseline requires an index")
        return Path("baselines") / f"{center_index:03d}-{center_frequency_hz}"
    return Path("anchors") / ("pre" if capture_role == "pre_sweep_anchor" else "post")


def _prune_empty_private_parents(path: Path, stop: Path) -> None:
    current = path
    while current != stop:
        try:
            current.rmdir()
        except OSError as error:
            if error.errno in {errno.ENOTEMPTY, errno.EEXIST}:
                return
            raise
        parent = current.parent
        _fsync_directory(parent)
        current = parent


def _retain_window(
    block: SampleBlock,
    plan: EnvironmentSurveyPlan,
    partial: Path,
    *,
    capture_role: Literal["pre_sweep_anchor", "sweep", "authorizing_baseline", "post_sweep_anchor"],
    center_index: int | None,
    center_frequency_hz: int,
    window_index: int,
) -> _RetainedWindow:
    parameters = plan.parameters
    if block.samples.shape != (2, parameters.samples_per_window):
        raise EnvironmentSurveyError(
            f"dual-RX survey returned {block.samples.shape}, expected "
            f"(2, {parameters.samples_per_window})"
        )
    encoded = complex_to_ci16(block.samples)
    products = deterministic_spectrum(encoded, parameters)
    relative = _center_relative_path(capture_role, center_index, center_frequency_hz)
    relative /= f"window-{window_index:03d}"
    raw_payload = encoded.tobytes(order="C")
    psd_payload = products.psd_density_dbfs_per_hz.tobytes(order="C")
    stft_payload = products.stft_density_dbfs_per_hz.tobytes(order="C")
    raw = _retain_artifact(
        partial,
        relative / "raw.ci16",
        raw_payload,
        dtype="ci16_le",
        shape=tuple(int(value) for value in encoded.shape),
    )
    psd_file = _retain_artifact(
        partial,
        relative / "psd-density-dbfs-per-hz.f32le",
        psd_payload,
        dtype="float32_le",
        shape=tuple(int(value) for value in products.psd_density_dbfs_per_hz.shape),
    )
    stft_file = _retain_artifact(
        partial,
        relative / "stft-density-dbfs-per-hz.f32le",
        stft_payload,
        dtype="float32_le",
        shape=tuple(int(value) for value in products.stft_density_dbfs_per_hz.shape),
    )
    return _RetainedWindow(
        window_index=window_index,
        utc_ns=block.utc_ns,
        raw_ci16=raw,
        psd_density_dbfs_per_hz=psd_file,
        stft_density_dbfs_per_hz=stft_file,
        receiver_integrated_power_fs=products.receiver_integrated_power_fs,
        receiver_integrated_power_dbfs=products.receiver_integrated_power_dbfs,
        receiver_clip_count=products.receiver_clip_count,
    )


def deterministic_spectrum(
    encoded: np.ndarray, parameters: EnvironmentSurveyParameters
) -> SpectrumProducts:
    """Derive full PSD/STFT solely from the retained dual-RX CI16 bytes."""

    values = np.asarray(encoded)
    expected = (parameters.samples_per_window, 2, 2)
    if values.shape != expected or values.dtype != np.dtype("<i2"):
        raise ValueError(f"encoded survey window must be {expected} little-endian int16")
    samples = values[:, :, 0].astype(np.float64) + 1j * values[:, :, 1].astype(np.float64)
    samples = samples.T
    frame_starts = tuple(
        range(
            0,
            parameters.samples_per_window - parameters.fft_size + 1,
            parameters.stft_hop_samples,
        )
    )
    if not frame_starts:
        raise ValueError("survey STFT parameters produce no complete frame")
    indexes = np.arange(parameters.fft_size, dtype=np.float64)
    taper = 0.5 - 0.5 * np.cos(2.0 * np.pi * indexes / parameters.fft_size)
    normalization = (
        parameters.sample_rate_hz
        * float(np.sum(taper * taper, dtype=np.float64))
        * parameters.adc_full_scale**2
    )
    linear = np.empty((2, len(frame_starts), parameters.fft_size), dtype=np.float64)
    for receiver in range(2):
        for frame_index, start in enumerate(frame_starts):
            frame = samples[receiver, start : start + parameters.fft_size]
            transformed = np.fft.fftshift(np.fft.fft(frame * taper))
            linear[receiver, frame_index] = np.abs(transformed) ** 2 / normalization
    with np.errstate(divide="ignore"):
        stft = 10.0 * np.log10(linear)
    psd_linear = np.mean(linear, axis=1)
    with np.errstate(divide="ignore"):
        psd = 10.0 * np.log10(psd_linear)
    offsets = np.fft.fftshift(np.fft.fftfreq(parameters.fft_size, 1 / parameters.sample_rate_hz))
    selected = np.abs(offsets) <= parameters.objective_half_width_hz
    if not np.any(selected):
        raise ValueError("survey objective window contains no FFT bin")
    bin_width_hz = parameters.sample_rate_hz / parameters.fft_size
    integrated_linear = np.sum(psd_linear[:, selected], axis=1) * bin_width_hz
    integrated_power_fs = (float(integrated_linear[0]), float(integrated_linear[1]))
    if not all(math.isfinite(value) and value > 0.0 for value in integrated_power_fs):
        raise ValueError("integrated survey power must be finite and strictly positive")
    integrated = tuple(_linear_power_to_dbfs(value) for value in integrated_power_fs)
    integer_values = values.astype(np.int32, copy=False)
    clipped = (np.abs(integer_values[:, :, 0]) >= parameters.adc_clip_threshold) | (
        np.abs(integer_values[:, :, 1]) >= parameters.adc_clip_threshold
    )
    clip_count = tuple(int(value) for value in np.count_nonzero(clipped, axis=0))
    return SpectrumProducts(
        psd_density_dbfs_per_hz=psd.astype("<f4"),
        stft_density_dbfs_per_hz=stft.astype("<f4"),
        receiver_integrated_power_fs=integrated_power_fs,
        receiver_integrated_power_dbfs=(integrated[0], integrated[1]),
        receiver_clip_count=(clip_count[0], clip_count[1]),
    )


def _verify_window_derivation(
    window: SurveyWindowEvidence,
    parameters: EnvironmentSurveyParameters,
    *,
    raw_payload: bytes,
    psd_payload: bytes,
    stft_payload: bytes,
) -> None:
    encoded = np.frombuffer(raw_payload, dtype="<i2").reshape(SAMPLES_PER_WINDOW, 2, 2)
    products = deterministic_spectrum(encoded, parameters)
    if (
        products.psd_density_dbfs_per_hz.tobytes(order="C") != psd_payload
        or products.stft_density_dbfs_per_hz.tobytes(order="C") != stft_payload
    ):
        raise EnvironmentSurveyError("survey spectral artifacts do not derive from retained CI16")
    linear_matches = all(
        math.isclose(actual, expected, rel_tol=0.0, abs_tol=1e-15)
        for actual, expected in zip(
            products.receiver_integrated_power_fs,
            window.receiver_integrated_power_fs,
            strict=True,
        )
    )
    dbfs_matches = all(
        math.isclose(actual, expected, rel_tol=0.0, abs_tol=1e-12)
        for actual, expected in zip(
            products.receiver_integrated_power_dbfs,
            window.receiver_integrated_power_dbfs,
            strict=True,
        )
    )
    if products.receiver_clip_count != window.receiver_clip_count or not (
        linear_matches and dbfs_matches
    ):
        raise EnvironmentSurveyError("survey window statistics do not derive from retained CI16")


def _summarize_windows(
    windows: Sequence[SurveyWindowEvidence],
) -> tuple[
    tuple[float, float],
    tuple[float, float],
    tuple[float, float],
    tuple[float, float],
    tuple[float, float],
    tuple[float, float],
    tuple[int, int],
    tuple[float, float],
    tuple[tuple[bool, bool], ...],
]:
    if len(windows) != WINDOWS_PER_CENTER:
        raise ValueError("frozen center summary requires exactly 32 windows")
    powers = np.asarray(
        [window.receiver_integrated_power_fs for window in windows], dtype=np.float64
    )
    if not np.all(np.isfinite(powers)) or np.any(powers <= 0.0):
        raise ValueError("survey window powers must be finite and strictly positive")
    p50_linear = tuple(float(value) for value in np.percentile(powers, 50, axis=0, method="linear"))
    p95_linear = tuple(float(value) for value in np.percentile(powers, 95, axis=0, method="linear"))
    p99_linear = tuple(float(value) for value in np.percentile(powers, 99, axis=0, method="linear"))
    p50 = tuple(_linear_power_to_dbfs(value) for value in p50_linear)
    p95 = tuple(_linear_power_to_dbfs(value) for value in p95_linear)
    p99 = tuple(_linear_power_to_dbfs(value) for value in p99_linear)
    clips = tuple(
        sum(window.receiver_clip_count[receiver] for window in windows) for receiver in range(2)
    )
    burst_array = powers > (
        np.asarray(p50_linear, dtype=np.float64) * (10.0 ** (BURST_THRESHOLD_DB / 10.0))
    )
    occupancy_values = np.mean(burst_array, axis=0)
    occupancy = (float(occupancy_values[0]), float(occupancy_values[1]))
    bursts = tuple((bool(value[0]), bool(value[1])) for value in burst_array)
    return (
        (p50_linear[0], p50_linear[1]),
        (p95_linear[0], p95_linear[1]),
        (p99_linear[0], p99_linear[1]),
        (p50[0], p50[1]),
        (p95[0], p95[1]),
        (p99[0], p99[1]),
        (clips[0], clips[1]),
        occupancy,
        bursts,
    )


def _measure_anchor_drift(
    pre: SurveyCenterEvidence, post: SurveyCenterEvidence
) -> SurveyAnchorDrift:
    if pre.capture_role != "pre_sweep_anchor" or post.capture_role != "post_sweep_anchor":
        raise EnvironmentSurveyError("survey drift requires the exact pre/post anchor roles")
    p99_delta = tuple(
        post.receiver_p99_dbfs[index] - pre.receiver_p99_dbfs[index] for index in range(2)
    )
    occupancy_delta = tuple(
        post.receiver_burst_occupancy[index] - pre.receiver_burst_occupancy[index]
        for index in range(2)
    )
    maximum_p99 = max(abs(value) for value in p99_delta)
    maximum_occupancy = max(abs(value) for value in occupancy_delta)
    clipping = any(pre.receiver_clip_count) or any(post.receiver_clip_count)
    passed = bool(
        not clipping
        and maximum_p99 <= P99_DRIFT_LIMIT_DB
        and maximum_occupancy <= OCCUPANCY_DRIFT_LIMIT
    )
    return SurveyAnchorDrift(
        p99_delta_db=(p99_delta[0], p99_delta[1]),
        occupancy_delta=(occupancy_delta[0], occupancy_delta[1]),
        maximum_absolute_p99_delta_db=maximum_p99,
        maximum_absolute_occupancy_delta=maximum_occupancy,
        anchor_clipping_detected=clipping,
        passed=passed,
    )


def _objective_ranking(
    parameters: EnvironmentSurveyParameters,
    centers: Sequence[SurveyCenterEvidence],
) -> tuple[int, ...]:
    by_frequency = {center.center_frequency_hz: center for center in centers}
    candidates = [
        by_frequency[value]
        for value in parameters.control_candidates_hz
        if value in by_frequency and not any(by_frequency[value].receiver_clip_count)
    ]
    ranked = sorted(
        candidates,
        key=lambda value: (
            value.worst_rx_p99_dbfs,
            value.worst_rx_burst_occupancy,
            value.center_frequency_hz,
        ),
    )
    return tuple(value.center_frequency_hz for value in ranked)


def _clipped_control_candidates(
    parameters: EnvironmentSurveyParameters,
    centers: Sequence[SurveyCenterEvidence],
) -> tuple[int, ...]:
    by_frequency = {center.center_frequency_hz: center for center in centers}
    return tuple(
        value
        for value in parameters.control_candidates_hz
        if value in by_frequency and any(by_frequency[value].receiver_clip_count)
    )


def _validate_survey_readback(requested: RadioSettings, actual: SurveyRxSettingsReadback) -> None:
    if (
        requested.sample_rate_hz != SAMPLE_RATE_HZ
        or requested.bandwidth_hz != RF_BANDWIDTH_HZ
        or requested.gain_mode is not GainMode.MANUAL
        or requested.gain_db != MANUAL_GAIN_DB
        or requested.channels != (0, 1)
        or abs(actual.center_frequency_hz - requested.center_frequency_hz) > 2
        or actual.sample_rate_hz != SAMPLE_RATE_HZ
        or actual.rf_bandwidth_hz != RF_BANDWIDTH_HZ
        or actual.receiver_channels != (0, 1)
        or actual.receiver_gain_modes != (GainMode.MANUAL, GainMode.MANUAL)
        or any(abs(gain - MANUAL_GAIN_DB) > 0.26 for gain in actual.receiver_gain_db)
    ):
        raise ValueError(f"survey RX settings readback differs from the fixed request: {actual}")


def _rx_settings_restored(
    original: SurveyRxSettingsReadback | None,
    restored: SurveyRxSettingsReadback | None,
) -> bool:
    """Require exact restoration of every restorable field in the RX snapshot."""

    if original is None or restored is None:
        return False
    if (
        restored.center_frequency_hz != original.center_frequency_hz
        or restored.sample_rate_hz != original.sample_rate_hz
        or restored.rf_bandwidth_hz != original.rf_bandwidth_hz
        or restored.receiver_channels != original.receiver_channels
        or restored.receiver_gain_modes != original.receiver_gain_modes
        or restored.sample_rate_source_channels != original.sample_rate_source_channels
        or restored.sample_rate_source_values_hz != original.sample_rate_source_values_hz
        or restored.rf_bandwidth_source_channels != original.rf_bandwidth_source_channels
        or restored.rf_bandwidth_source_values_hz != original.rf_bandwidth_source_values_hz
        or restored.shared_phy_provenance != original.shared_phy_provenance
    ):
        return False
    return all(
        mode is not GainMode.MANUAL or actual == expected
        for mode, actual, expected in zip(
            original.receiver_gain_modes,
            restored.receiver_gain_db,
            original.receiver_gain_db,
            strict=True,
        )
    )


def _retain_artifact(
    partial_root: Path,
    relative: Path,
    payload: bytes,
    *,
    dtype: Literal["ci16_le", "float32_le"],
    shape: tuple[int, ...],
) -> SurveyArtifactFile:
    if not payload:
        raise EnvironmentSurveyError("survey artifact cannot be empty")
    partial_path = partial_root / relative
    _make_private_tree(partial_root, relative.parent)
    _write_private_bytes(partial_path, payload)
    return SurveyArtifactFile(
        identity=SurveyArtifactIdentity(
            relative_path=relative,
            bytes=len(payload),
            sha256=hashlib.sha256(payload).hexdigest(),
        ),
        dtype=dtype,
        shape=shape,
    )


def _write_private_bytes(path: Path, payload: bytes) -> None:
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    _fsync_directory(path.parent)


def _make_private_tree(root: Path, relative: Path) -> None:
    current = root
    for component in relative.parts:
        current /= component
        try:
            current.mkdir(mode=0o700)
        except FileExistsError:
            state = current.lstat()
            if (
                not stat.S_ISDIR(state.st_mode)
                or state.st_uid != os.getuid()
                or stat.S_IMODE(state.st_mode) != 0o700
            ):
                raise EnvironmentSurveyError(
                    "survey artifact parent is not one owned mode-0700 directory"
                ) from None


def _artifact_path(root: Path, identity: SurveyArtifactIdentity) -> Path:
    current = root
    for component in identity.relative_path.parent.parts:
        current /= component
        try:
            state = current.lstat()
        except OSError as error:
            raise EnvironmentSurveyError(
                f"survey artifact parent is unavailable: {error}"
            ) from error
        if (
            not stat.S_ISDIR(state.st_mode)
            or state.st_uid != os.getuid()
            or stat.S_IMODE(state.st_mode) != 0o700
        ):
            raise EnvironmentSurveyError(
                "survey artifact parent is not one owned mode-0700 directory"
            )
    return root / identity.relative_path


def _read_private_artifact(root: Path, identity: SurveyArtifactIdentity) -> bytes:
    path = _artifact_path(root, identity)
    try:
        state = path.lstat()
    except OSError as error:
        raise EnvironmentSurveyError(f"survey artifact is unavailable: {error}") from error
    if (
        not stat.S_ISREG(state.st_mode)
        or state.st_uid != os.getuid()
        or stat.S_IMODE(state.st_mode) != 0o600
        or state.st_nlink != 1
        or state.st_size != identity.bytes
    ):
        raise EnvironmentSurveyError("survey artifact is not one exact owned mode-0600 file")
    digest = hashlib.sha256()
    payload = bytearray()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise EnvironmentSurveyError(f"survey artifact cannot be opened safely: {error}") from error
    try:
        opened = os.fstat(descriptor)
        before_identity = _stable_stat_identity(state)
        if _stable_stat_identity(opened) != before_identity:
            raise EnvironmentSurveyError("survey artifact changed while it was opened")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            while chunk := stream.read(1 << 20):
                digest.update(chunk)
                payload.extend(chunk)
            if _stable_stat_identity(os.fstat(stream.fileno())) != before_identity:
                raise EnvironmentSurveyError("survey artifact changed while it was read")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if digest.hexdigest() != identity.sha256:
        raise EnvironmentSurveyError("survey artifact SHA-256 verification failed")
    return bytes(payload)


def _verify_exact_result_tree(root: Path, declared_files: set[Path]) -> None:
    """Reject undeclared files, staging remnants, links, and non-private tree entries."""

    expected_directories = {
        parent for relative in declared_files for parent in relative.parents if parent != Path(".")
    }
    observed_files: set[Path] = set()
    observed_directories: set[Path] = set()

    def walk(directory: Path, relative: Path) -> None:
        try:
            children = tuple(directory.iterdir())
        except OSError as error:
            raise EnvironmentSurveyError(
                f"survey result tree cannot be enumerated: {error}"
            ) from error
        for child in children:
            child_relative = relative / child.name
            try:
                state = child.lstat()
            except OSError as error:
                raise EnvironmentSurveyError(
                    f"survey result entry cannot be inspected: {error}"
                ) from error
            if stat.S_ISDIR(state.st_mode):
                if state.st_uid != os.getuid() or stat.S_IMODE(state.st_mode) != 0o700:
                    raise EnvironmentSurveyError(
                        "survey result subdirectories must be owned mode-0700"
                    )
                observed_directories.add(child_relative)
                walk(child, child_relative)
            elif stat.S_ISREG(state.st_mode):
                if (
                    state.st_uid != os.getuid()
                    or stat.S_IMODE(state.st_mode) != 0o600
                    or state.st_nlink != 1
                ):
                    raise EnvironmentSurveyError(
                        "survey result files must be owned mode-0600 regular files with one link"
                    )
                observed_files.add(child_relative)
            else:
                raise EnvironmentSurveyError("survey result tree contains a link or special entry")

    walk(root, Path())
    if observed_files != declared_files or observed_directories != expected_directories:
        raise EnvironmentSurveyError("survey result tree contains missing or undeclared entries")


def _stable_stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _available_free_space_bytes(path: Path) -> int:
    return int(shutil.disk_usage(path).free)


def _require_remaining_capture_space(
    path: Path,
    *,
    remaining_payload_bytes: int,
    failure_reserve_bytes: int,
    manifest_allowance_bytes: int,
) -> None:
    required = remaining_payload_bytes + failure_reserve_bytes + manifest_allowance_bytes
    available = _available_free_space_bytes(path)
    if available < required:
        raise EnvironmentSurveyError(
            "survey free space fell below remaining fixed payload, failure reserve, and "
            "manifest allowance: "
            f"required={required} available={available}"
        )


def _require_private_directory(path: Path, *, label: str) -> None:
    if not path.is_absolute() or ".." in path.parts:
        raise EnvironmentSurveyError(f"{label} must be absolute and normalized")
    try:
        state = path.lstat()
    except OSError as error:
        raise EnvironmentSurveyError(f"{label} is unavailable: {error}") from error
    if (
        not stat.S_ISDIR(state.st_mode)
        or state.st_uid != os.getuid()
        or stat.S_IMODE(state.st_mode) != 0o700
    ):
        raise EnvironmentSurveyError(f"{label} must be one owned mode-0700 directory")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
