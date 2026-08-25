"""Narrow hardware port owned by the radio controller."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, Self

import numpy as np

from pluto_plus.models import RadioCapabilities, RadioIdentity, RadioSettings


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


class MetadataRadioDevice(RadioDevice, Protocol):
    """Additive V2 port for continuity-observable radio capture."""

    def reset_receive_buffer(self) -> None: ...

    def configure_kernel_buffers(self, count: int) -> int: ...

    def read_kernel_buffers_count(self) -> int: ...

    def tune_center_frequency(self, center_frequency_hz: float) -> float: ...

    def begin_metadata_capture(
        self, sample_count: int, *, kernel_buffers: int
    ) -> MetadataCapture: ...
