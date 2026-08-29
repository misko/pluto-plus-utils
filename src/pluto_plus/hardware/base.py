"""Narrow hardware port owned by the radio controller."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, Self

import numpy as np

from pluto_plus.errors import RadioConfigurationError
from pluto_plus.models import RadioCapabilities, RadioIdentity, RadioSettings

if TYPE_CHECKING:
    from pluto_plus.tandem import RadioMetadataV5

DEFAULT_RESTORE_LO_SEARCH_HZ = 16


@dataclass(frozen=True, slots=True)
class SampleBlock:
    """Legacy IQ block with host time only.

    This contract cannot make a continuity claim.  New capture code which
    needs an exact sample timeline must use :class:`SampleBlockV2`.
    """

    utc_ns: int
    samples: np.ndarray

    def __post_init__(self) -> None:
        if self.utc_ns <= 0:
            raise ValueError("utc_ns must be positive")
        if self.samples.ndim != 2 or not self.samples.shape[0] or not self.samples.shape[1]:
            raise ValueError("samples must have receiver and sample dimensions")
        if not np.iscomplexobj(self.samples):
            raise ValueError("samples must be complex")


@dataclass(frozen=True, slots=True)
class SettingsRestorationAttempt:
    """One bounded RX-LO request and its independent settings readback."""

    requested_center_frequency_hz: int
    readback: RadioSettings | None
    error: str | None = None


@dataclass(frozen=True, slots=True)
class SettingsRestoration:
    """Evidence that a prior hardware settings snapshot was exactly restored."""

    snapshot: RadioSettings
    restored: RadioSettings
    attempts: tuple[SettingsRestorationAttempt, ...]


@dataclass(frozen=True, slots=True)
class ExactSettingsApplication:
    """Evidence that requested settings were applied with an exact readback."""

    requested: RadioSettings
    applied: RadioSettings
    attempts: tuple[SettingsRestorationAttempt, ...]


class SettingsRestorationError(RadioConfigurationError):
    """A bounded exact restoration attempt failed closed."""

    def __init__(self, message: str, attempts: tuple[SettingsRestorationAttempt, ...]) -> None:
        super().__init__(message)
        self.attempts = attempts


class ExactSettingsApplicationError(SettingsRestorationError):
    """A bounded exact settings application failed closed."""


@dataclass(frozen=True, slots=True)
class SampleBlockV2:
    """One metadata-attested IQ refill on the FPGA sample-counter timeline."""

    utc_ns: int
    samples: np.ndarray
    stream_id: int
    buffer_sequence: int
    first_sample_sequence: int
    metadata_flags: int
    metadata_abi: int
    missing_samples_before: int = 0
    sample_time_realtime_start_ns: int | None = None
    sample_time_realtime_end_ns: int | None = None
    sample_time_monotonic_start_ns: int | None = None
    sample_time_monotonic_end_ns: int | None = None
    sample_time_uncertainty_ns: int | None = None
    tandem_metadata: RadioMetadataV5 | None = None

    def __post_init__(self) -> None:
        if self.utc_ns <= 0:
            raise ValueError("utc_ns must be positive")
        if self.samples.ndim != 2 or not self.samples.shape[0] or not self.samples.shape[1]:
            raise ValueError("samples must have receiver and sample dimensions")
        if not np.iscomplexobj(self.samples):
            raise ValueError("samples must be complex")
        for name in ("stream_id", "buffer_sequence", "first_sample_sequence"):
            value = getattr(self, name)
            if not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        if self.stream_id == 0:
            raise ValueError("stream_id must be non-zero")
        if self.metadata_flags < 0:
            raise ValueError("metadata_flags must be non-negative")
        if self.metadata_abi <= 0:
            raise ValueError("metadata_abi must be positive")
        if self.missing_samples_before < 0:
            raise ValueError("missing_samples_before must be non-negative")
        times = (
            self.sample_time_realtime_start_ns,
            self.sample_time_realtime_end_ns,
            self.sample_time_monotonic_start_ns,
            self.sample_time_monotonic_end_ns,
        )
        if any(value is not None and value < 0 for value in times):
            raise ValueError("sample times must be non-negative")
        if (self.sample_time_realtime_start_ns is None) != (
            self.sample_time_realtime_end_ns is None
        ):
            raise ValueError("realtime sample interval must be wholly present or absent")
        if (self.sample_time_monotonic_start_ns is None) != (
            self.sample_time_monotonic_end_ns is None
        ):
            raise ValueError("monotonic sample interval must be wholly present or absent")
        if (
            self.sample_time_realtime_start_ns is not None
            and self.sample_time_realtime_end_ns is not None
            and self.sample_time_realtime_end_ns <= self.sample_time_realtime_start_ns
        ):
            raise ValueError("realtime sample interval must increase")
        if (
            self.sample_time_monotonic_start_ns is not None
            and self.sample_time_monotonic_end_ns is not None
            and self.sample_time_monotonic_end_ns <= self.sample_time_monotonic_start_ns
        ):
            raise ValueError("monotonic sample interval must increase")
        if self.sample_time_uncertainty_ns is not None and self.sample_time_uncertainty_ns < 0:
            raise ValueError("sample time uncertainty must be non-negative")

    @property
    def sample_count(self) -> int:
        return int(self.samples.shape[1])

    @property
    def last_sample_sequence_exclusive(self) -> int:
        return self.first_sample_sequence + self.sample_count

    @property
    def stream_generation(self) -> int:
        """Alias documenting that a stream ID names one capture generation."""

        return self.stream_id

    @property
    def overflow_observed(self) -> bool:
        """Whether firmware reported an IIO overflow for this refill."""

        return bool(self.metadata_flags & (1 << 11))


class MetadataCapture(Protocol):
    """An explicitly armed, reset-bounded metadata capture generation."""

    @property
    def kernel_buffers(self) -> int: ...

    @property
    def ddr_burst_enabled(self) -> bool: ...

    @property
    def ddr_burst_requested_bytes(self) -> int: ...

    @property
    def ddr_burst_admitted_bytes(self) -> int: ...

    @property
    def ddr_burst_frames(self) -> int: ...

    @property
    def ddr_ring_enabled(self) -> bool: ...

    @property
    def ddr_ring_requested_bytes(self) -> int: ...

    @property
    def ddr_ring_admitted_bytes(self) -> int: ...

    @property
    def ddr_ring_capacity_frames(self) -> int: ...

    @property
    def ddr_ring_capture_frames(self) -> int: ...

    @property
    def ddr_ring_continuous(self) -> bool: ...

    def ddr_ring_status(self) -> Mapping[str, object]: ...

    def read_block(self) -> SampleBlockV2: ...

    def close(self) -> None: ...

    def __enter__(self) -> Self: ...

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None: ...


class RadioDevice(Protocol):
    @property
    def identity(self) -> RadioIdentity: ...

    @property
    def capabilities(self) -> RadioCapabilities: ...

    def open(self) -> None: ...

    def close(self) -> None: ...

    def read_settings(self) -> RadioSettings: ...

    def apply_settings(self, settings: RadioSettings) -> RadioSettings: ...

    def read_block(self, sample_count: int) -> SampleBlock: ...


def restore_settings_exact(
    device: RadioDevice,
    snapshot: RadioSettings,
    *,
    maximum_lo_offset_hz: int = DEFAULT_RESTORE_LO_SEARCH_HZ,
) -> SettingsRestoration:
    """Restore an exact readback despite a non-idempotent AD9361 RX-LO mapping.

    AD9361/pyadi LO quantization can expose a value which cannot be reproduced by
    requesting that same value. Restoration therefore searches a tightly bounded,
    deterministic set of nearby integer requests. Every attempt independently
    reads all settings back; only the RX-LO request may vary, and success still
    requires an exact match to the complete original snapshot.
    """

    try:
        application = apply_settings_exact(
            device,
            snapshot,
            maximum_lo_offset_hz=maximum_lo_offset_hz,
        )
    except ExactSettingsApplicationError as error:
        raise SettingsRestorationError(
            str(error).replace("application", "restoration"),
            error.attempts,
        ) from error
    return SettingsRestoration(
        snapshot=snapshot,
        restored=application.applied,
        attempts=application.attempts,
    )


def apply_settings_exact(
    device: RadioDevice,
    requested: RadioSettings,
    *,
    maximum_lo_offset_hz: int = DEFAULT_RESTORE_LO_SEARCH_HZ,
) -> ExactSettingsApplication:
    """Apply settings whose independent hardware readback exactly matches the request.

    The AD9361 RX synthesizer may map an integer request to a nearby readback and
    may not reproduce that readback when it is requested directly.  Search a
    tightly bounded, deterministic sequence of nearby low-level LO requests.
    Every attempt reapplies and independently reads all settings; only the LO
    request may differ from the caller's desired settings.
    """

    _validate_maximum_lo_offset(maximum_lo_offset_hz)
    requested_center = round(requested.center_frequency_hz)
    offsets = [0]
    for delta in range(1, maximum_lo_offset_hz + 1):
        offsets.extend((delta, -delta))

    attempts: list[SettingsRestorationAttempt] = []
    for offset in offsets:
        candidate_center = requested_center + offset
        if candidate_center <= 0:
            continue
        candidate = requested.model_copy(update={"center_frequency_hz": float(candidate_center)})
        try:
            device.apply_settings(candidate)
            actual = device.read_settings()
        except Exception as error:
            attempt = SettingsRestorationAttempt(
                requested_center_frequency_hz=candidate_center,
                readback=None,
                error=f"{type(error).__name__}: {error}",
            )
            attempts.append(attempt)
            raise ExactSettingsApplicationError(
                "exact settings application failed during apply/readback",
                tuple(attempts),
            ) from error

        attempts.append(
            SettingsRestorationAttempt(
                requested_center_frequency_hz=candidate_center,
                readback=actual,
            )
        )
        if _settings_without_center(actual) != _settings_without_center(requested):
            raise ExactSettingsApplicationError(
                "exact settings application changed a non-LO field",
                tuple(attempts),
            )
        if actual == requested:
            return ExactSettingsApplication(
                requested=requested,
                applied=actual,
                attempts=tuple(attempts),
            )

    summary = ", ".join(
        f"{attempt.requested_center_frequency_hz}->"
        f"{None if attempt.readback is None else attempt.readback.center_frequency_hz:g}"
        for attempt in attempts
    )
    raise ExactSettingsApplicationError(
        "exact settings application could not reproduce RX LO "
        f"{requested.center_frequency_hz:g} Hz within +/-{maximum_lo_offset_hz} Hz "
        f"({summary})",
        tuple(attempts),
    )


def _validate_maximum_lo_offset(maximum_lo_offset_hz: int) -> None:
    if not isinstance(maximum_lo_offset_hz, int) or isinstance(maximum_lo_offset_hz, bool):
        raise ValueError("maximum_lo_offset_hz must be a non-negative integer")
    if maximum_lo_offset_hz < 0:
        raise ValueError("maximum_lo_offset_hz must be a non-negative integer")
    if maximum_lo_offset_hz > 1024:
        raise ValueError("maximum_lo_offset_hz cannot exceed 1024 Hz")


def _settings_without_center(settings: RadioSettings) -> tuple[object, ...]:
    return (
        settings.sample_rate_hz,
        settings.bandwidth_hz,
        settings.gain_mode,
        settings.gain_db,
        settings.channels,
    )


class MetadataRadioDevice(RadioDevice, Protocol):
    """Additive V2 port for continuity-observable radio capture."""

    def reset_receive_buffer(self) -> None: ...

    def configure_kernel_buffers(self, count: int) -> int: ...

    def read_kernel_buffers_count(self) -> int: ...

    def tune_center_frequency(self, center_frequency_hz: float) -> float: ...

    def begin_metadata_capture(
        self, sample_count: int, *, kernel_buffers: int, ddr_burst_bytes: int = 0
    ) -> MetadataCapture: ...
