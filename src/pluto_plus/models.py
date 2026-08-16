"""Public, versioned application contracts."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

PositiveFrequency = Annotated[float, Field(gt=0)]


def utc_now() -> datetime:
    return datetime.now(UTC)


class ApiModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class RadioState(StrEnum):
    OFFLINE = "offline"
    READY = "ready"
    CONFIGURING = "configuring"
    STREAMING = "streaming"
    SCANNING = "scanning"
    FLASHING = "flashing"
    VERIFYING = "verifying"
    RECOVERING = "recovering"
    ERROR = "error"


class GainMode(StrEnum):
    MANUAL = "manual"
    SLOW_ATTACK = "slow_attack"
    FAST_ATTACK = "fast_attack"


class Transport(StrEnum):
    IIO_USB = "iio_usb"
    IIO_IP = "iio_ip"
    DIRECT_USB = "direct_usb"
    DIRECT_IP = "direct_ip"
    FAKE = "fake"


class JobState(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"
    CANCELED = "canceled"


class RadioSettings(ApiModel):
    center_frequency_hz: PositiveFrequency = 915_000_000
    sample_rate_hz: PositiveFrequency = 2_500_000
    bandwidth_hz: PositiveFrequency = 2_500_000
    gain_mode: GainMode = GainMode.MANUAL
    gain_db: float | None = Field(default=40.0, ge=-10, le=80)
    channels: tuple[int, ...] = (0, 1)

    @model_validator(mode="after")
    def validate_relationships(self) -> RadioSettings:
        if self.bandwidth_hz > self.sample_rate_hz:
            raise ValueError("bandwidth_hz cannot exceed sample_rate_hz")
        if not self.channels or len(set(self.channels)) != len(self.channels):
            raise ValueError("channels must be non-empty and unique")
        if any(channel not in (0, 1) for channel in self.channels):
            raise ValueError("Pluto+ receiver channels must be 0 or 1")
        if self.gain_mode is GainMode.MANUAL and self.gain_db is None:
            raise ValueError("manual gain mode requires gain_db")
        if self.gain_mode is not GainMode.MANUAL and self.gain_db is not None:
            raise ValueError("automatic gain modes cannot specify gain_db")
        return self


class SettingsPatch(ApiModel):
    expected_revision: int = Field(ge=0)
    center_frequency_hz: PositiveFrequency | None = None
    sample_rate_hz: PositiveFrequency | None = None
    bandwidth_hz: PositiveFrequency | None = None
    gain_mode: GainMode | None = None
    gain_db: float | None = Field(default=None, ge=-10, le=80)
    channels: tuple[int, ...] | None = None


class RadioIdentity(ApiModel):
    radio_id: str = Field(min_length=1)
    serial: str = Field(min_length=1)
    uri: str = Field(min_length=1)
    transport: Transport
    model: str = "Pluto+"
    firmware_version: str | None = None
    usb_path: str | None = None


class RadioCapabilities(ApiModel):
    receiver_channels: tuple[int, ...] = (0, 1)
    supports_live_tuning: bool = True
    supports_direct_capture: bool = False
    supports_volatile_firmware: bool = False
    supports_persistent_firmware: bool = False
    minimum_sample_rate_hz: float | None = None
    maximum_sample_rate_hz: float | None = None


class RadioSnapshot(ApiModel):
    identity: RadioIdentity
    capabilities: RadioCapabilities
    managed: bool = True
    state: RadioState
    revision: int = Field(ge=0)
    requested_settings: RadioSettings
    actual_settings: RadioSettings
    activity_id: str | None = None
    last_error: str | None = None
    updated_at: datetime = Field(default_factory=utc_now)


class StreamRequest(ApiModel):
    duration_s: float | None = Field(default=None, gt=0)
    sample_count: int | None = Field(default=None, gt=0)
    block_size: int = Field(default=65_536, ge=1_024, le=1_048_576)
    fft_size: int = Field(default=4_096, ge=256, le=65_536)
    persist: bool = False
    label: str | None = Field(default=None, max_length=120)

    @model_validator(mode="after")
    def validate_fft(self) -> StreamRequest:
        if self.fft_size > self.block_size:
            raise ValueError("fft_size cannot exceed block_size")
        if self.fft_size & (self.fft_size - 1):
            raise ValueError("fft_size must be a power of two")
        if self.duration_s is not None and self.sample_count is not None:
            raise ValueError("duration_s and sample_count are mutually exclusive")
        if self.persist and self.duration_s is None and self.sample_count is None:
            raise ValueError("persistent captures must be bounded")
        return self


class StreamJob(ApiModel):
    job_id: str
    radio_id: str
    state: JobState
    persist: bool
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    artifact_id: str | None = None
    error: str | None = None


class ArtifactSummary(ApiModel):
    artifact_id: str
    radio_id: str
    created_at: datetime
    path: str
    sample_count: int = Field(ge=0)
    receiver_count: int = Field(gt=0)
    sample_rate_hz: PositiveFrequency
    center_frequency_hz: PositiveFrequency
    sha256: str
    label: str | None = None


class AnalysisRequest(ApiModel):
    artifact_id: str
    analyzer: str = "spectrum"
    parameters: dict[str, Any] = Field(default_factory=dict)


class AnalysisResult(ApiModel):
    analysis_id: str
    artifact_id: str
    analyzer: str
    analyzer_version: str
    created_at: datetime
    result: dict[str, Any]
    path: str


class SpectrumFrame(ApiModel):
    schema_version: int = 1
    radio_id: str
    activity_id: str
    sequence: int = Field(ge=0)
    utc_ns: int = Field(gt=0)
    configuration_revision: int = Field(ge=0)
    center_frequency_hz: PositiveFrequency
    sample_rate_hz: PositiveFrequency
    bin_width_hz: PositiveFrequency
    receiver_power_db: tuple[tuple[float, ...], ...]


class ScanRequest(ApiModel):
    start_frequency_hz: PositiveFrequency
    stop_frequency_hz: PositiveFrequency
    step_hz: PositiveFrequency
    sample_rate_hz: PositiveFrequency = 2_500_000
    bandwidth_hz: PositiveFrequency = 2_500_000
    gain_mode: GainMode = GainMode.MANUAL
    gain_db: float | None = Field(default=40.0, ge=-10, le=80)
    channels: tuple[int, ...] = (0, 1)
    samples_per_frequency: int = Field(default=16_384, ge=1_024, le=1_048_576)
    fft_size: int = Field(default=4_096, ge=256, le=65_536)
    settle_buffers: int = Field(default=1, ge=0, le=16)

    @model_validator(mode="after")
    def validate_scan(self) -> ScanRequest:
        if self.stop_frequency_hz < self.start_frequency_hz:
            raise ValueError("stop_frequency_hz cannot be below start_frequency_hz")
        point_count = int(
            (self.stop_frequency_hz - self.start_frequency_hz) // self.step_hz
        ) + 1
        if point_count > 4096:
            raise ValueError("scan cannot exceed 4096 frequency points")
        RadioSettings(
            center_frequency_hz=self.start_frequency_hz,
            sample_rate_hz=self.sample_rate_hz,
            bandwidth_hz=self.bandwidth_hz,
            gain_mode=self.gain_mode,
            gain_db=self.gain_db,
            channels=self.channels,
        )
        if self.fft_size > self.samples_per_frequency:
            raise ValueError("fft_size cannot exceed samples_per_frequency")
        if self.fft_size & (self.fft_size - 1):
            raise ValueError("fft_size must be a power of two")
        return self


class ScanPoint(ApiModel):
    center_frequency_hz: PositiveFrequency
    utc_ns: int = Field(gt=0)
    receiver_mean_power_db: tuple[float, ...]
    receiver_peak_power_db: tuple[float, ...]
    receiver_peak_offset_hz: tuple[float, ...]


class ScanResult(ApiModel):
    scan_id: str
    radio_id: str
    created_at: datetime
    finished_at: datetime
    request: ScanRequest
    points: tuple[ScanPoint, ...]
    path: str


class ScanJob(ApiModel):
    job_id: str
    radio_id: str
    state: JobState
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    scan_id: str | None = None
    error: str | None = None


class FirmwareImageSummary(ApiModel):
    image_id: str
    original_name: str
    sha256: str
    size: int = Field(gt=0)


class FirmwarePlanRequest(ApiModel):
    image_id: str
    mode: str
    transport: str = "usb"
    expected_firmware_version: str | None = Field(default=None, min_length=1, max_length=120)


class FirmwareExecuteRequest(ApiModel):
    plan_id: str
    confirmation_token: str = Field(min_length=1)
    operator_confirmation: str | None = Field(default=None, min_length=1, max_length=240)


class DoctorStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    UNKNOWN = "unknown"


class DoctorRemediation(ApiModel):
    remediation_id: str
    title: str
    description: str
    automatable: bool = False
    mutation: bool = False
    requires_privileged_helper: bool = False
    cli_hint: str | None = None


class DoctorFinding(ApiModel):
    code: str
    status: DoctorStatus
    summary: str
    actual: Any = None
    expected: Any = None
    evidence: str
    remediation: DoctorRemediation | None = None


class FirmwarePolicy(ApiModel):
    profile_id: str
    release_tag: str
    device_firmware: str
    asset_name: str
    asset_sha256: str
    release_url: str
    source_commit: str
    fit_body_sha256: str
    fit_body_size: int = Field(gt=0)
    hardware_qualified: bool
    published_at: datetime


class DoctorReport(ApiModel):
    radio_id: str
    checked_at: datetime = Field(default_factory=utc_now)
    canonical_policy: FirmwarePolicy
    healthy: bool
    findings: tuple[DoctorFinding, ...]
