"""Fail-closed metadata-enabled libiio capture session."""

from __future__ import annotations

import errno
import gc
import struct
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import TracebackType
from typing import Any

import numpy as np
from pydantic import ValidationError

from pluto_plus.ddr_ring import DdrRingStatusSnapshot
from pluto_plus.direct_radio.usb import (
    MetadataFlags,
    RadioMetadataV3,
    TimeAnchorFlags,
    TimeAnchorV1,
)
from pluto_plus.errors import RadioConfigurationError
from pluto_plus.hardware.base import SampleBlockV2
from pluto_plus.hardware.iio_iq_decode import (
    IioIqDecoder,
    read_interleaved_complex64,
    validate_iq_decoder,
)
from pluto_plus.hardware.sample_clock import (
    DEFAULT_SAMPLE_CLOCK_RATE_TOLERANCE_PPM,
    HostTimeAnchorMeasurement,
    capture_host_realtime_mapping,
    fit_sample_clock,
)
from pluto_plus.tandem import (
    MetadataTransportKind,
    RadioMetadataV5,
    RadioMetadataV6,
    RadioMetadataV7,
    TandemEventDirection,
    TandemSessionRequestV1,
    pack_metadata_provider_request_v1,
)

ADC_SAMPLE_COUNTER_LOW_REG = 0x800000B8
DEFAULT_METADATA_CAPACITY = 64 * 1024
DIRECT_ASYNC_FRAME_TARGET_MAX = 4_096
METADATA_BATCH_FRAMES_MAX = 64
# A 262,144-sample dual-RX refill spans about 105 ms at 2.5 MS/s. Five
# seconds leaves more than 47 refill intervals for transport jitter. Larger
# safe buffers receive eight native frame intervals, capped at 30 seconds, so
# a disconnected USB or IP context still cannot block a campaign forever.
IIO_CONTEXT_TIMEOUT_MS = 5_000
IIO_CONTEXT_TIMEOUT_FRAME_MULTIPLIER = 8
IIO_CONTEXT_TIMEOUT_MAX_MS = 30_000
IIO_DDR_BURST_TIMEOUT_MAX_MS = 300_000
INITIAL_TIME_ANCHOR_COUNT = 8
MAX_TIME_ANCHORS = 32
TIME_ANCHOR_WINDOW_NS = 10_000_000_000
MAX_STARTUP_FRAME_DISCARDS = 64
# The ABI-4 provider extends an 8-bit FPGA transition counter into the
# per-capture ledger and admits at most one complete 64-entry FIFO window
# between committed frames.  This bound makes modular deltas unambiguous.
ABI4_MAX_HIDDEN_GAIN_EVENTS = 64
_OPEN_MAX_ATTEMPTS = 3
_OPEN_RETRY_DELAY_SECONDS = 0.05
# The ordinary pyadi read establishes the scan layout that MetadataBuffer must
# inherit.  It only needs a minimal producer/consumer queue.  Priming with the
# final, potentially CMA-sized queue and immediately reopening that same queue
# can transiently require twice the requested contiguous DMA memory while the
# kernel's deferred block-release work completes.
_PRIME_KERNEL_BUFFERS = 2


@dataclass(frozen=True, slots=True)
class MetadataLayoutCapability:
    scan_mask: int
    receiver_count: int
    iq_bytes_per_sample: int
    sample_count_multiple: int


@dataclass(frozen=True, slots=True)
class _PendingMetadataSequence:
    stream_id: int
    buffer_sequence: int
    sample_end: int
    missing_samples_before: int


@dataclass(frozen=True, slots=True)
class IioRawSidecarBlock:
    """One exact ABI-3 header/sidecar/IQ generation from MetadataBuffer."""

    metadata_header: bytes
    sidecar: bytes
    iq_payload: bytes


@dataclass(frozen=True, slots=True)
class IioBufferOpenClockBracket:
    """Host clocks immediately bracketing the metadata-buffer OPEN."""

    before_realtime_ns: int
    before_monotonic_ns: int
    after_realtime_ns: int
    after_monotonic_ns: int

    def __post_init__(self) -> None:
        if min(
            self.before_realtime_ns,
            self.before_monotonic_ns,
            self.after_realtime_ns,
            self.after_monotonic_ns,
        ) <= 0:
            raise ValueError("metadata-buffer OPEN clocks must be positive")
        if self.after_monotonic_ns < self.before_monotonic_ns:
            raise ValueError("metadata-buffer OPEN monotonic bracket regressed")


ABI3_METADATA_LAYOUTS = (
    MetadataLayoutCapability(0x03, 1, 4, 2),
    MetadataLayoutCapability(0x0C, 1, 4, 2),
    MetadataLayoutCapability(0x0F, 2, 8, 1),
)
ABI3_METADATA_LAYOUTS_TEXT = "00000003:1:4:2,0000000c:1:4:2,0000000f:2:8:1"
# ABI 4 changes metadata authority and request negotiation, not the canonical
# RX scan layouts inherited from ABI 3.
ABI4_METADATA_LAYOUTS = ABI3_METADATA_LAYOUTS
ABI4_METADATA_LAYOUTS_TEXT = ABI3_METADATA_LAYOUTS_TEXT
ABI4_METADATA_RECORD = 7
ABI4_METADATA_FEATURES_TEXT = (
    "fpga-gain-timeline,exact-event-sequence,optional-rssi-telemetry,typed-capture-errors"
)
SUPPORTED_METADATA_ABIS = (1, 2, 3, 4)
SUPPORTED_METADATA_STATUS_VERSIONS = (1, 2)


def parse_metadata_version_capabilities(value: object) -> tuple[int, ...]:
    """Parse one canonical, strictly increasing metadata version set."""

    if not isinstance(value, str) or not value:
        raise ValueError("metadata version capability is absent")
    versions: list[int] = []
    for encoded in value.split(","):
        try:
            version = int(encoded, 10)
        except ValueError as error:
            raise ValueError("metadata version capability is not numeric") from error
        if encoded != str(version) or not 1 <= version <= 0xFFFF:
            raise ValueError("metadata version capability is not canonical")
        if versions and version <= versions[-1]:
            raise ValueError("metadata version capability is not strictly increasing")
        versions.append(version)
    return tuple(versions)


def require_metadata_abi_capability(
    attrs: Mapping[str, object], expected_abi: int
) -> int:
    """Select one release-local metadata ABI from canonical context attributes.

    ABI 4 is additive: firmware keeps the legacy scalar at ABI 3 for old hosts
    and advertises ABI 4 in the explicit version set.  Earlier ABIs retain the
    exact scalar admission rule so this helper cannot silently change their
    compatibility behavior.
    """

    if isinstance(expected_abi, bool) or expected_abi not in SUPPORTED_METADATA_ABIS:
        raise ValueError("expected metadata ABI is unsupported")
    legacy_raw = attrs.get("iio,buffer-metadata")
    if expected_abi < 4:
        if legacy_raw != str(expected_abi):
            raise ValueError(
                f"metadata ABI scalar is {legacy_raw!r}, expected {expected_abi}"
            )
        return expected_abi

    if legacy_raw != "3":
        raise ValueError(
            "metadata ABI 4 requires the compatibility-preserving legacy scalar '3'"
        )
    versions = parse_metadata_version_capabilities(
        attrs.get("iio,buffer-metadata-abi-versions")
    )
    if 3 not in versions:
        raise ValueError("metadata ABI version set is inconsistent with legacy scalar 3")
    if expected_abi not in versions:
        raise ValueError("metadata ABI version set does not advertise requested ABI 4")
    return expected_abi


def parse_metadata_layout_capabilities(value: object) -> tuple[MetadataLayoutCapability, ...]:
    """Parse the advertised ABI3 layouts without accepting aliases or duplicates."""

    if not isinstance(value, str) or not value:
        raise ValueError("metadata layout capability is absent")
    layouts: list[MetadataLayoutCapability] = []
    for encoded in value.split(","):
        fields = encoded.split(":")
        if len(fields) != 4:
            raise ValueError("metadata layout capability has the wrong field count")
        mask_text, receivers_text, iq_bytes_text, multiple_text = fields
        try:
            mask = int(mask_text, 16)
            receivers = int(receivers_text, 10)
            iq_bytes = int(iq_bytes_text, 10)
            multiple = int(multiple_text, 10)
        except ValueError as error:
            raise ValueError("metadata layout capability is not numeric") from error
        if (
            mask_text != f"{mask:08x}"
            or receivers not in {1, 2}
            or iq_bytes not in {4, 8}
            or multiple not in {1, 2}
        ):
            raise ValueError("metadata layout capability is not canonical")
        layout = MetadataLayoutCapability(mask, receivers, iq_bytes, multiple)
        if any(existing.scan_mask == mask for existing in layouts):
            raise ValueError("metadata layout capability repeats a scan mask")
        layouts.append(layout)
    return tuple(layouts)


def metadata_iio_context_timeout_ms(
    sample_rate_hz: int,
    samples_per_channel: int,
    *,
    batch_frames: int = 1,
    ddr_burst_frames: int = 0,
) -> int:
    """Return one bounded timeout with margin for the configured native-rate refill."""

    for name, value in (
        ("sample_rate_hz", sample_rate_hz),
        ("samples_per_channel", samples_per_channel),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"{name} must be a positive integer")
    if (
        isinstance(batch_frames, bool)
        or not isinstance(batch_frames, int)
        or not 1 <= batch_frames <= METADATA_BATCH_FRAMES_MAX
    ):
        raise ValueError(
            f"batch_frames must be in [1, {METADATA_BATCH_FRAMES_MAX}]"
        )
    for name, value in (("ddr_burst_frames", ddr_burst_frames),):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"{name} must be a non-negative integer")
    frame_duration_ms = (samples_per_channel * 1_000 + sample_rate_hz - 1) // sample_rate_hz
    if ddr_burst_frames:
        capture_timeout_ms = frame_duration_ms * ddr_burst_frames * 2 + IIO_CONTEXT_TIMEOUT_MS
        return min(IIO_DDR_BURST_TIMEOUT_MAX_MS, capture_timeout_ms)
    return min(
        IIO_CONTEXT_TIMEOUT_MAX_MS,
        max(
            IIO_CONTEXT_TIMEOUT_MS,
            frame_duration_ms * batch_frames * IIO_CONTEXT_TIMEOUT_FRAME_MULTIPLIER,
        ),
    )


def configure_iio_context_timeout(
    context: Any,
    *,
    timeout_ms: int = IIO_CONTEXT_TIMEOUT_MS,
) -> None:
    """Fail closed unless libiio applies the bounded metadata I/O timeout."""

    if (
        isinstance(timeout_ms, bool)
        or not isinstance(timeout_ms, int)
        or not IIO_CONTEXT_TIMEOUT_MS <= timeout_ms <= IIO_DDR_BURST_TIMEOUT_MAX_MS
    ):
        raise ValueError("IIO context timeout is outside the reviewed bounded range")

    setter = getattr(context, "set_timeout", None)
    if not callable(setter):
        raise RadioConfigurationError(
            "installed libiio binding cannot configure a finite context timeout"
        )
    try:
        setter(timeout_ms)
    except Exception as error:
        raise RadioConfigurationError(
            "failed to configure the finite IIO context timeout"
        ) from error


def _close_buffer(buffer: Any | None) -> None:
    close = getattr(buffer, "close", None)
    if callable(close):
        close()


class IioMetadataCaptureSession:
    """One reset-bounded FPGA-metadata capture generation.

    Positive counter gaps are retained in ``missing_samples_before``.  Corrupt
    headers, missing counters, stream changes, regressions, and disagreements
    between buffer and sample sequences fail the session immediately.
    """

    def __init__(
        self,
        sdr: Any,
        metadata_buffer_type: Any,
        *,
        sample_rate_hz: int,
        samples_per_channel: int,
        kernel_buffers: int,
        metadata_abi: int,
        metadata_capacity: int = DEFAULT_METADATA_CAPACITY,
        batch_frames: int = 1,
        tandem_request: TandemSessionRequestV1 | None = None,
        ddr_burst_bytes: int = 0,
        ddr_ring_bytes: int = 0,
        ddr_ring_frames: int = 0,
        ddr_ring_continuous: bool = False,
        direct_async_frames: int = 0,
        drop_backlog_on_overrun: bool = True,
        iq_decoder: IioIqDecoder = "pyadi",
    ) -> None:
        validate_iq_decoder(iq_decoder)
        if sample_rate_hz <= 0:
            raise ValueError("sample_rate_hz must be positive")
        if samples_per_channel <= 0:
            raise ValueError("samples_per_channel must be positive")
        if kernel_buffers <= 0:
            raise ValueError("kernel_buffers must be positive")
        if metadata_abi not in {1, 2, 3, 4}:
            raise ValueError("metadata_abi must be one of the supported ABIs 1, 2, 3, or 4")
        if metadata_capacity <= 0:
            raise ValueError("metadata_capacity must be positive")
        if (
            isinstance(batch_frames, bool)
            or not isinstance(batch_frames, int)
            or not 1 <= batch_frames <= METADATA_BATCH_FRAMES_MAX
        ):
            raise ValueError(
                f"batch_frames must be in [1, {METADATA_BATCH_FRAMES_MAX}]"
            )
        if isinstance(ddr_burst_bytes, bool) or not isinstance(ddr_burst_bytes, int):
            raise TypeError("ddr_burst_bytes must be an integer")
        if ddr_burst_bytes < 0:
            raise ValueError("ddr_burst_bytes must not be negative")
        if isinstance(ddr_ring_bytes, bool) or not isinstance(ddr_ring_bytes, int):
            raise TypeError("ddr_ring_bytes must be an integer")
        if isinstance(ddr_ring_frames, bool) or not isinstance(ddr_ring_frames, int):
            raise TypeError("ddr_ring_frames must be an integer")
        if not isinstance(ddr_ring_continuous, bool):
            raise TypeError("ddr_ring_continuous must be a bool")
        if isinstance(direct_async_frames, bool) or not isinstance(
            direct_async_frames, int
        ):
            raise TypeError("direct_async_frames must be an integer")
        if not 0 <= direct_async_frames <= DIRECT_ASYNC_FRAME_TARGET_MAX:
            raise ValueError(
                f"direct_async_frames must be in [0, {DIRECT_ASYNC_FRAME_TARGET_MAX}]"
            )
        if not isinstance(drop_backlog_on_overrun, bool):
            raise TypeError("drop_backlog_on_overrun must be a bool")
        if direct_async_frames and kernel_buffers < 2:
            raise ValueError("direct async capture requires at least two kernel buffers")
        if direct_async_frames and ddr_ring_bytes and kernel_buffers < 3:
            raise ValueError(
                "direct async RAM extension requires at least three kernel buffers"
            )
        if ddr_ring_bytes < 0 or ddr_ring_frames < 0:
            raise ValueError("DDR ring values must not be negative")
        if ddr_burst_bytes and ddr_ring_bytes:
            raise ValueError("device DDR burst and DDR ring are mutually exclusive")
        if direct_async_frames and ddr_burst_bytes:
            raise ValueError("direct async capture cannot use the sealed DDR burst")
        if batch_frames > 1 and (ddr_burst_bytes or ddr_ring_bytes or direct_async_frames):
            raise ValueError(
                "metadata refill batching is only supported by ordinary capture"
            )
        if ddr_ring_bytes:
            if direct_async_frames and (ddr_ring_frames or ddr_ring_continuous):
                raise ValueError(
                    "direct async RAM extension owns the finite frame target"
                )
            if ddr_ring_continuous and ddr_ring_frames:
                raise ValueError("continuous DDR ring must not specify a frame target")
            if not direct_async_frames and not ddr_ring_continuous and not ddr_ring_frames:
                raise ValueError("finite DDR ring requires a positive frame target")
        elif ddr_ring_frames or ddr_ring_continuous:
            raise ValueError("DDR ring mode requires a positive byte budget")
        self._sdr = sdr
        self._iq_decoder = iq_decoder
        self._metadata_buffer_type = metadata_buffer_type
        self._sample_rate_hz = int(sample_rate_hz)
        self._samples_per_channel = int(samples_per_channel)
        self._kernel_buffers = int(kernel_buffers)
        self._allocated_kernel_buffers = 0
        self._metadata_abi = metadata_abi
        self._metadata_capacity = int(metadata_capacity)
        self._batch_frames = batch_frames
        self._ddr_burst_requested_bytes = ddr_burst_bytes
        self._ddr_ring_requested_bytes = ddr_ring_bytes
        self._ddr_ring_capture_frames = ddr_ring_frames
        self._ddr_ring_continuous = ddr_ring_continuous
        self._direct_async_frames = direct_async_frames
        self._drop_backlog_on_overrun = bool(
            direct_async_frames and drop_backlog_on_overrun
        )
        self._tandem_request = tandem_request or TandemSessionRequestV1.auto_for_sample_count(
            samples_per_channel,
            retention_frames=(kernel_buffers + 1 if metadata_abi == 4 else 2),
        )
        self._channels = tuple(int(item) for item in sdr.rx_enabled_channels)
        if self._channels not in {(0,), (1,), (0, 1)}:
            raise ValueError("metadata capture receiver selection is not canonical")
        if metadata_abi in {1, 2} and self._channels != (0, 1):
            raise ValueError("metadata ABI 1 and 2 require paired RX channels")
        if metadata_abi in {3, 4} and len(self._channels) == 1 and samples_per_channel & 1:
            raise ValueError("metadata ABI 3/4 single-RX sample count must be even")
        if ddr_burst_bytes and (metadata_abi not in {3, 4} or len(self._channels) != 1):
            raise ValueError("device DDR burst v1 requires metadata ABI 3/4 and one receiver")
        if ddr_ring_bytes and (metadata_abi not in {3, 4} or len(self._channels) != 1):
            raise ValueError("device DDR ring v1 requires metadata ABI 3/4 and one receiver")
        frame_iq_bytes = samples_per_channel * len(self._channels) * 4
        self._ddr_burst_frames = 0 if not ddr_burst_bytes else ddr_burst_bytes // frame_iq_bytes
        self._ddr_burst_admitted_bytes = self._ddr_burst_frames * frame_iq_bytes
        if ddr_burst_bytes and not self._ddr_burst_frames:
            raise ValueError("device DDR burst byte budget cannot hold one complete frame")
        self._ddr_ring_capacity_frames = (
            0 if not ddr_ring_bytes else ddr_ring_bytes // frame_iq_bytes
        )
        self._ddr_ring_admitted_bytes = self._ddr_ring_capacity_frames * frame_iq_bytes
        if ddr_ring_bytes and not self._ddr_ring_capacity_frames:
            raise ValueError("device DDR ring byte budget cannot hold one complete frame")
        self._buffer: Any | None = None
        self._time_anchors: list[HostTimeAnchorMeasurement] = []
        self._next_anchor_request_id = 1
        self._stream_id: int | None = None
        self._previous_buffer_sequence: int | None = None
        self._previous_sample_end: int | None = None
        self._previous_v7_metadata: RadioMetadataV7 | None = None
        self._terminal_ddr_ring_status: dict[str, object] | None = None
        self._terminal_ddr_ring_status_error: str | None = None

    @property
    def kernel_buffers(self) -> int:
        return self._kernel_buffers

    @property
    def allocated_kernel_buffers(self) -> int:
        """DMA blocks attested by successful exact direct-async admission."""

        return self._allocated_kernel_buffers

    @property
    def batch_frames(self) -> int:
        """Number of ordinary metadata refills prequeued as one transport batch."""

        return self._batch_frames

    @property
    def direct_async_frames(self) -> int:
        return self._direct_async_frames

    @property
    def direct_async_ring_extension(self) -> bool:
        return bool(self._direct_async_frames and self._ddr_ring_capacity_frames)

    @property
    def drop_backlog_on_overrun(self) -> bool:
        return self._drop_backlog_on_overrun

    @property
    def is_open(self) -> bool:
        return self._buffer is not None

    @property
    def ddr_burst_enabled(self) -> bool:
        return self._ddr_burst_frames > 0

    @property
    def ddr_burst_requested_bytes(self) -> int:
        return self._ddr_burst_requested_bytes

    @property
    def ddr_burst_admitted_bytes(self) -> int:
        return self._ddr_burst_admitted_bytes

    @property
    def ddr_burst_frames(self) -> int:
        return self._ddr_burst_frames

    @property
    def ddr_ring_enabled(self) -> bool:
        return self._ddr_ring_capacity_frames > 0

    @property
    def ddr_ring_requested_bytes(self) -> int:
        return self._ddr_ring_requested_bytes

    @property
    def ddr_ring_admitted_bytes(self) -> int:
        return self._ddr_ring_admitted_bytes

    @property
    def ddr_ring_capacity_frames(self) -> int:
        return self._ddr_ring_capacity_frames

    @property
    def ddr_ring_capture_frames(self) -> int:
        return self._ddr_ring_capture_frames

    @property
    def ddr_ring_continuous(self) -> bool:
        return self._ddr_ring_continuous

    def ddr_ring_status(self) -> Mapping[str, object]:
        if not self.ddr_ring_enabled:
            raise ValueError("this capture does not use the device DDR ring")
        if self._buffer is None:
            if self._terminal_ddr_ring_status is not None:
                return dict(self._terminal_ddr_ring_status)
            detail = (
                ""
                if self._terminal_ddr_ring_status_error is None
                else f": {self._terminal_ddr_ring_status_error}"
            )
            raise RuntimeError(f"IIO metadata capture is not open{detail}")
        return self._read_live_ddr_ring_status()

    def _read_live_ddr_ring_status(self) -> dict[str, object]:
        status = getattr(self._buffer, "ddr_ring_status", None)
        if not callable(status):
            raise RuntimeError("installed pylibiio cannot read DDR ring status")
        result = status()
        if not isinstance(result, Mapping):
            raise RuntimeError("pylibiio returned malformed DDR ring status")
        try:
            typed = DdrRingStatusSnapshot.model_validate(result)
        except ValidationError as error:
            raise RuntimeError("pylibiio returned malformed DDR ring status") from error
        return typed.model_dump(mode="python")

    def _cache_failed_ddr_ring_status(self) -> None:
        if not self.ddr_ring_enabled or self._buffer is None:
            return
        try:
            self._terminal_ddr_ring_status = self._read_live_ddr_ring_status()
        except Exception as error:
            self._terminal_ddr_ring_status_error = f"{type(error).__name__}: {error}"

    def open(self) -> None:
        if self._buffer is not None:
            raise RuntimeError("IIO metadata capture is already open")
        self._terminal_ddr_ring_status = None
        self._terminal_ddr_ring_status_error = None
        self._prime_ordinary_rx()
        self._verify_kernel_buffers()
        try:
            if self.ddr_burst_enabled:
                self._refresh_time_anchors(initial=True)
            self._buffer = self._open_metadata_buffer()
            if self._direct_async_frames:
                # The matched server starts direct capture only when its local
                # allocation equals the request. Reaching this point is the
                # session-scoped allocation attestation.
                self._allocated_kernel_buffers = self._kernel_buffers
            self._sdr._rxbuf = self._buffer
            if not self.ddr_burst_enabled:
                self._refresh_time_anchors(initial=True)
        except BaseException:
            self.close()
            raise

    def _prime_ordinary_rx(self) -> None:
        self._sdr.rx_destroy_buffer()
        self._sdr.rx_buffer_size = self._samples_per_channel
        prime_kernel_buffers = min(self._kernel_buffers, _PRIME_KERNEL_BUFFERS)
        if prime_kernel_buffers != self._kernel_buffers:
            self._set_kernel_buffers_exact(prime_kernel_buffers)
        ordinary_buffer = None
        try:
            if tuple(int(item) for item in self._sdr.rx_enabled_channels) != self._channels:
                raise RuntimeError("RX channel selection changed while metadata capture was armed")
            signal = np.asarray(self._sdr.rx())
            expected = (len(self._channels), self._samples_per_channel)
            if expected[0] == 1 and signal.ndim == 1:
                signal = signal[np.newaxis, :]
            if signal.shape != expected or not np.iscomplexobj(signal):
                raise RuntimeError(
                    "ordinary IIO prime did not establish the requested complex scan layout"
                )
            ordinary_buffer = getattr(self._sdr, "_rxbuf", None)
        finally:
            self._sdr.rx_destroy_buffer()
            try:
                _close_buffer(ordinary_buffer)
            finally:
                del ordinary_buffer
                gc.collect()
                if prime_kernel_buffers != self._kernel_buffers:
                    self._set_kernel_buffers_exact(self._kernel_buffers)

    def _set_kernel_buffers_exact(self, count: int) -> None:
        setter = getattr(self._sdr._rxadc, "set_kernel_buffers_count", None)
        if not callable(setter):
            raise RuntimeError("RX kernel-buffer count does not support configuration")
        result = setter(count)
        if isinstance(result, int) and result < 0:
            raise RuntimeError(
                f"libiio rejected RX kernel-buffer count {count}: error {result}"
            )
        actual = getattr(self._sdr._rxadc, "kernel_buffers_count", None)
        if actual is None:
            raise RuntimeError("RX kernel-buffer count does not support readback")
        if int(actual) != count:
            raise RuntimeError(
                f"RX kernel-buffer readback is {actual}, expected {count}"
            )

    def _verify_kernel_buffers(self) -> None:
        actual = getattr(self._sdr._rxadc, "kernel_buffers_count", None)
        if actual is None:
            raise RuntimeError("RX kernel-buffer count does not support readback")
        if int(actual) != self._kernel_buffers:
            raise RuntimeError(
                f"RX kernel-buffer readback is {actual}, expected {self._kernel_buffers}"
            )

    def _open_metadata_buffer(self) -> Any:
        request: bytes | None
        if self._metadata_abi == 1:
            request = None
        elif self._metadata_abi in {2, 3}:
            request = self._tandem_request.pack(self._samples_per_channel)
        else:
            transport_kind = (
                MetadataTransportKind.DDR_BURST
                if self.ddr_burst_enabled
                else MetadataTransportKind.DDR_RING
                if self.ddr_ring_enabled
                else MetadataTransportKind.ORDINARY
            )
            request = pack_metadata_provider_request_v1(
                self._tandem_request,
                self._samples_per_channel,
                transport_kind=transport_kind,
                retention_frames=self._kernel_buffers + 1,
            )
        for attempt in range(1, _OPEN_MAX_ATTEMPTS + 1):
            try:
                if self._metadata_abi == 1:
                    if self._batch_frames == 1:
                        return self._metadata_buffer_type(
                            self._sdr._rxadc,
                            self._samples_per_channel,
                            self._metadata_capacity,
                        )
                    return self._metadata_buffer_type(
                        self._sdr._rxadc,
                        self._samples_per_channel,
                        self._metadata_capacity,
                        batch_frames=self._batch_frames,
                    )
                if self.ddr_burst_enabled:
                    return self._metadata_buffer_type(
                        self._sdr._rxadc,
                        self._samples_per_channel,
                        request,
                        self._metadata_capacity,
                        batch_frames=1,
                        ddr_burst_bytes=self._ddr_burst_requested_bytes,
                    )
                if self.ddr_ring_enabled:
                    if self._direct_async_frames:
                        return self._metadata_buffer_type(
                            self._sdr._rxadc,
                            self._samples_per_channel,
                            request,
                            self._metadata_capacity,
                            batch_frames=1,
                            ddr_ring_bytes=self._ddr_ring_requested_bytes,
                            ddr_ring_frames=self._ddr_ring_capture_frames,
                            ddr_ring_continuous=self._ddr_ring_continuous,
                            direct_async_frames=self._direct_async_frames,
                            drop_backlog_on_overrun=self._drop_backlog_on_overrun,
                        )
                    return self._metadata_buffer_type(
                        self._sdr._rxadc,
                        self._samples_per_channel,
                        request,
                        self._metadata_capacity,
                        batch_frames=1,
                        ddr_ring_bytes=self._ddr_ring_requested_bytes,
                        ddr_ring_frames=self._ddr_ring_capture_frames,
                        ddr_ring_continuous=self._ddr_ring_continuous,
                    )
                if self._direct_async_frames:
                    return self._metadata_buffer_type(
                        self._sdr._rxadc,
                        self._samples_per_channel,
                        request,
                        self._metadata_capacity,
                        batch_frames=1,
                        direct_async_frames=self._direct_async_frames,
                        drop_backlog_on_overrun=self._drop_backlog_on_overrun,
                    )
                if self._batch_frames == 1:
                    return self._metadata_buffer_type(
                        self._sdr._rxadc,
                        self._samples_per_channel,
                        request,
                        self._metadata_capacity,
                    )
                return self._metadata_buffer_type(
                    self._sdr._rxadc,
                    self._samples_per_channel,
                    request,
                    self._metadata_capacity,
                    batch_frames=self._batch_frames,
                )
            except OSError as error:
                if error.errno != errno.EBUSY or attempt == _OPEN_MAX_ATTEMPTS:
                    raise
                time.sleep(_OPEN_RETRY_DELAY_SECONDS)
        raise RuntimeError("metadata IIO open attempts were not exhausted")

    def read_block(self) -> SampleBlockV2:
        """Read one atomic IQ/metadata refill, poisoning on any failure."""

        try:
            return self._read_block()
        except BaseException:
            self._cache_failed_ddr_ring_status()
            self.close()
            raise

    def _read_block(self) -> SampleBlockV2:
        if self._buffer is None:
            raise RuntimeError("IIO metadata capture is not open")
        host_before_ns = time.time_ns()
        for startup_discard in range(MAX_STARTUP_FRAME_DISCARDS + 1):
            try:
                raw_signal = (
                    read_interleaved_complex64(
                        self._sdr,
                        samples_per_channel=self._samples_per_channel,
                        channels=self._channels,
                    )
                    if self._iq_decoder == "raw-complex64"
                    else self._sdr.rx()
                )
                break
            except OSError as error:
                if error.errno != errno.EAGAIN or startup_discard == MAX_STARTUP_FRAME_DISCARDS:
                    raise
        host_after_ns = time.time_ns()
        signal = np.asarray(raw_signal)
        if tuple(int(item) for item in self._sdr.rx_enabled_channels) != self._channels:
            raise RuntimeError("RX channel selection changed during metadata capture")
        expected_receivers = len(self._channels)
        if expected_receivers == 1 and signal.ndim == 1:
            signal = signal[np.newaxis, :]
        if signal.ndim != 2 or signal.shape != (
            expected_receivers,
            self._samples_per_channel,
        ):
            raise RuntimeError(
                f"metadata IIO read returned {signal.shape}, expected "
                f"({expected_receivers}, {self._samples_per_channel})"
            )
        raw_metadata = self._buffer.metadata
        if raw_metadata is None:
            raise RuntimeError("metadata buffer refill returned no metadata header")
        declared_missing: int | None = None
        tandem_metadata: RadioMetadataV5 | RadioMetadataV7 | None = None
        parsed_v7: RadioMetadataV7 | None = None
        metadata: Any
        if self._metadata_abi == 1:
            metadata = RadioMetadataV3.unpack(raw_metadata)
        elif self._metadata_abi == 2:
            parsed = RadioMetadataV5.unpack(raw_metadata)
            metadata = parsed.base
            tandem_metadata = parsed
            if len(raw_metadata) != parsed.header_bytes:
                raise RuntimeError("metadata refill returned trailing bytes")
        elif self._metadata_abi == 3:
            parsed_v6 = RadioMetadataV6.unpack(raw_metadata)
            metadata = parsed_v6.base
            tandem_metadata = parsed_v6.tandem
            declared_missing = parsed_v6.missing_samples_before
            if len(raw_metadata) != parsed_v6.header_bytes:
                raise RuntimeError("metadata refill returned trailing bytes")
        else:
            parsed_v7 = RadioMetadataV7.unpack(raw_metadata)
            metadata = parsed_v7
            tandem_metadata = parsed_v7
            declared_missing = parsed_v7.missing_samples_before
            if len(raw_metadata) != parsed_v7.header_bytes:
                raise RuntimeError("metadata refill returned trailing bytes")
        self._validate_header(metadata)
        pending_sequence = self._validate_sequence(
            metadata, declared_missing=declared_missing
        )
        if parsed_v7 is not None:
            self._validate_v7_ledger(parsed_v7)
        # A finite standalone ring can finish capture and restore the FPGA
        # timestamp-control register before the host drains its cached frames.
        # Register samples taken after that point are not live counter anchors;
        # retain the initial in-capture anchors instead.  Direct+ring remains a
        # streaming transport and continues refreshing normally.
        if not (self.ddr_ring_enabled and not self._direct_async_frames):
            self._refresh_time_anchors(initial=False)
        timing = self._capture_time(metadata.first_sample_sequence)
        utc_ns = (
            timing["sample_time_realtime_start_ns"]
            if timing is not None
            else (host_before_ns + host_after_ns) // 2
        )
        self._commit_sequence(pending_sequence, v7_metadata=parsed_v7)
        return SampleBlockV2(
            utc_ns=int(utc_ns),
            samples=signal.astype(np.complex64, copy=False),
            stream_id=int(metadata.stream_id),
            buffer_sequence=int(metadata.buffer_sequence),
            first_sample_sequence=int(metadata.first_sample_sequence),
            metadata_flags=int(metadata.flags),
            metadata_abi=self._metadata_abi,
            missing_samples_before=pending_sequence.missing_samples_before,
            sample_time_realtime_start_ns=(
                None if timing is None else timing["sample_time_realtime_start_ns"]
            ),
            sample_time_realtime_end_ns=(
                None if timing is None else timing["sample_time_realtime_end_ns"]
            ),
            sample_time_monotonic_start_ns=(
                None if timing is None else timing["sample_time_monotonic_start_ns"]
            ),
            sample_time_monotonic_end_ns=(
                None if timing is None else timing["sample_time_monotonic_end_ns"]
            ),
            sample_time_uncertainty_ns=(
                None if timing is None else timing["sample_time_uncertainty_ns"]
            ),
            tandem_metadata=tandem_metadata,
        )

    def _validate_header(self, metadata: Any) -> None:
        if metadata.samples_per_channel != self._samples_per_channel:
            raise RuntimeError("metadata sample count does not match the IIO buffer")
        expected_mask, expected_receivers, expected_bytes = {
            (0,): (0x03, 1, 4),
            (1,): (0x0C, 1, 4),
            (0, 1): (0x0F, 2, 8),
        }[self._channels]
        if metadata.iq_payload_bytes != self._samples_per_channel * expected_bytes:
            raise RuntimeError("metadata IQ byte count does not match the selected CI16 layout")
        if (
            metadata.enabled_scan_mask != expected_mask
            or metadata.channel_count != expected_receivers
        ):
            raise RuntimeError("metadata scan layout does not match the selected receivers")
        if not metadata.flags & MetadataFlags.HARDWARE_SAMPLE_COUNTER_VALID:
            raise RuntimeError("IIO metadata lacks a valid FPGA sample counter")

    def _validate_sequence(
        self, metadata: Any, *, declared_missing: int | None
    ) -> _PendingMetadataSequence:
        stream_id = int(metadata.stream_id)
        buffer_sequence = int(metadata.buffer_sequence)
        first_sample = int(metadata.first_sample_sequence)
        if self._stream_id is None:
            if buffer_sequence != 0:
                raise RuntimeError("new metadata capture did not begin at buffer sequence zero")
            if (
                declared_missing not in {None, 0}
                or metadata.flags & MetadataFlags.SAMPLE_GAP_BEFORE
            ):
                raise RuntimeError("new metadata capture declared a preceding gap")
            return _PendingMetadataSequence(
                stream_id=stream_id,
                buffer_sequence=buffer_sequence,
                sample_end=first_sample + self._samples_per_channel,
                missing_samples_before=0,
            )
        if stream_id != self._stream_id:
            raise RuntimeError("metadata stream changed without a capture reset")
        assert self._previous_buffer_sequence is not None
        assert self._previous_sample_end is not None
        buffer_delta = buffer_sequence - self._previous_buffer_sequence
        if buffer_delta <= 0:
            raise RuntimeError("metadata buffer sequence repeated or regressed")
        missing = first_sample - self._previous_sample_end
        if missing < 0:
            raise RuntimeError("FPGA sample counter repeated or regressed")
        skipped_buffers = buffer_delta - 1
        if self._metadata_abi in {3, 4}:
            if declared_missing != missing:
                raise RuntimeError("metadata exact gap count disagrees with the FPGA counter")
            if bool(metadata.flags & MetadataFlags.SAMPLE_GAP_BEFORE) != bool(missing):
                raise RuntimeError("metadata gap flag disagrees with the FPGA counter")
            if skipped_buffers != missing // self._samples_per_channel:
                raise RuntimeError("metadata buffer and FPGA sample sequences disagree")
        elif missing != skipped_buffers * self._samples_per_channel:
            raise RuntimeError("metadata buffer and FPGA sample sequences disagree")
        return _PendingMetadataSequence(
            stream_id=stream_id,
            buffer_sequence=buffer_sequence,
            sample_end=first_sample + self._samples_per_channel,
            missing_samples_before=missing,
        )

    def _commit_sequence(
        self,
        pending: _PendingMetadataSequence,
        *,
        v7_metadata: RadioMetadataV7 | None,
    ) -> None:
        if self._metadata_abi == 4 and v7_metadata is None:  # pragma: no cover
            raise RuntimeError("ABI4 sequence commit lacks V7 metadata")
        self._stream_id = pending.stream_id
        self._previous_buffer_sequence = pending.buffer_sequence
        self._previous_sample_end = pending.sample_end
        if self._metadata_abi == 4:
            assert v7_metadata is not None
            self._previous_v7_metadata = v7_metadata

    def _validate_v7_ledger(self, metadata: RadioMetadataV7) -> None:
        previous = self._previous_v7_metadata
        if previous is None:
            if metadata.tandem_transition_count_start != 0 or metadata.event_sequence_start != 0:
                raise RuntimeError("ABI4 capture did not begin with a zero-seeded gain ledger")
            return
        stable_contract = (
            "ownership_epoch",
            "tandem_state",
            "gain_table_id",
            "threshold_provenance",
            "minimum_gain_db",
            "maximum_gain_db",
            "initial_gain_db",
            "minimum_gain_index",
            "maximum_gain_index",
            "gain_observation_interval_samples",
            "gain_observation_capacity",
            "gain_event_capacity",
        )
        if any(getattr(metadata, name) != getattr(previous, name) for name in stable_contract):
            raise RuntimeError("ABI4 gain-ledger contract changed within one capture")
        expected_event_sequence = (
            previous.event_sequence_start + len(previous.gain_events)
        ) & 0xFFFFFFFF
        if not metadata.missing_samples_before:
            if metadata.tandem_transition_count_start != previous.tandem_transition_count:
                raise RuntimeError("ABI4 gain-ledger transition sequence is discontinuous")
            if metadata.event_sequence_start != expected_event_sequence:
                raise RuntimeError("ABI4 gain-ledger event sequence is discontinuous")
            hidden_transition_count = 0
        else:
            hidden_transition_count = (
                metadata.tandem_transition_count_start
                - previous.tandem_transition_count
            ) & 0xFFFFFFFF
            hidden_event_count = (
                metadata.event_sequence_start - expected_event_sequence
            ) & 0xFFFFFFFF
            if hidden_transition_count > ABI4_MAX_HIDDEN_GAIN_EVENTS:
                raise RuntimeError(
                    "ABI4 gain-ledger transition sequence exceeds the provider window"
                )
            if hidden_event_count != hidden_transition_count:
                raise RuntimeError(
                    "ABI4 gain-ledger event sequence does not account for hidden transitions"
                )
        # With no hidden transition, the preceding endpoint is still the
        # authoritative baseline even across an IQ gap.  If transitions did
        # occur in the missing IQ interval, their exact count and event ledger
        # are proven above, while this frame's parser independently proves the
        # new authoritative start and every visible in-frame transition.
        if hidden_transition_count:
            return
        boundary_events = tuple(
            event
            for event in metadata.gain_events
            if event.sample_sequence == metadata.first_sample_sequence
        )
        previous_index = previous.rx1_gain_index
        if boundary_events:
            current_index = previous_index
            for event in boundary_events:
                if event.direction is TandemEventDirection.INCREASE:
                    direction_matches = event.rx1_gain_index > current_index
                else:
                    direction_matches = event.rx1_gain_index < current_index
                if not direction_matches:
                    raise RuntimeError(
                        "ABI4 frame-boundary gain event contradicts its direction"
                    )
                current_index = event.rx1_gain_index
            if current_index != metadata.rx1_gain_index_start:
                raise RuntimeError(
                    "ABI4 frame-boundary gain events disagree with the start index"
                )
            index_delta = metadata.rx1_gain_index_start - previous_index
            db_delta = metadata.rx1_gain_db_start - previous.rx1_gain_db_end
            if (
                (index_delta > 0 and db_delta < 0)
                or (index_delta < 0 and db_delta > 0)
                or (index_delta == 0 and db_delta != 0)
            ):
                raise RuntimeError(
                    "ABI4 frame-boundary gain index and dB direction disagree"
                )
        elif (
            metadata.rx1_gain_index_start,
            metadata.rx2_gain_index_start,
        ) != (previous.rx1_gain_index, previous.rx2_gain_index):
            raise RuntimeError("ABI4 gain-ledger index endpoints are discontinuous")
        elif (
            metadata.rx1_gain_db_start,
            metadata.rx2_gain_db_start,
        ) != (previous.rx1_gain_db_end, previous.rx2_gain_db_end):
            raise RuntimeError("ABI4 gain-ledger dB endpoints are discontinuous")

    def _query_time_anchor(self) -> HostTimeAnchorMeasurement | None:
        reader = getattr(self._sdr._rxadc, "reg_read", None)
        if not callable(reader):
            return None
        request_id = self._next_anchor_request_id
        self._next_anchor_request_id = request_id + 1
        host_before_ns = time.monotonic_ns()
        counter = int(reader(ADC_SAMPLE_COUNTER_LOW_REG)) & 0xFFFFFFFF
        host_after_ns = time.monotonic_ns()
        anchor = TimeAnchorV1(
            flags=(
                TimeAnchorFlags.COUNTER_INTERVAL_VALID
                | TimeAnchorFlags.MONOTONIC_INTERVAL_VALID
                | TimeAnchorFlags.COUNTER_LOW32
            ),
            request_id=request_id,
            radio_monotonic_before_ns=0,
            sample_counter_before=counter,
            sample_counter_after=counter,
            radio_monotonic_after_ns=0,
        )
        return HostTimeAnchorMeasurement(
            anchor=anchor,
            host_monotonic_before_ns=host_before_ns,
            host_monotonic_after_ns=host_after_ns,
            transport="iio",
        )

    def _refresh_time_anchors(self, *, initial: bool) -> None:
        count = INITIAL_TIME_ANCHOR_COUNT if initial else 1
        for index in range(count):
            anchor = self._query_time_anchor()
            if anchor is None:
                self._time_anchors = []
                return
            self._time_anchors.append(anchor)
            if initial and index + 1 < count:
                time.sleep(0.005)
        newest = self._time_anchors[-1].host_monotonic_after_ns
        cutoff = newest - TIME_ANCHOR_WINDOW_NS
        self._time_anchors = [
            item
            for item in self._time_anchors[-MAX_TIME_ANCHORS:]
            if item.host_monotonic_after_ns >= cutoff
        ]

    def _capture_time(self, first_sample: int) -> dict[str, int] | None:
        if not self._time_anchors:
            return None
        extended = [item.extend_near(first_sample) for item in self._time_anchors]
        fit = fit_sample_clock(
            extended,
            nominal_sample_rate_hz=self._sample_rate_hz,
            maximum_rate_error_ppm=DEFAULT_SAMPLE_CLOCK_RATE_TOLERANCE_PPM,
        )
        realtime = capture_host_realtime_mapping()
        sample_end = first_sample + self._samples_per_channel
        monotonic_start = fit.host_monotonic_ns(first_sample)
        monotonic_end = fit.host_monotonic_ns(sample_end)
        return {
            "sample_time_monotonic_start_ns": monotonic_start,
            "sample_time_monotonic_end_ns": monotonic_end,
            "sample_time_realtime_start_ns": realtime.realtime_ns(monotonic_start),
            "sample_time_realtime_end_ns": realtime.realtime_ns(monotonic_end),
            "sample_time_uncertainty_ns": max(
                fit.uncertainty_ns_at(first_sample),
                fit.uncertainty_ns_at(sample_end),
            )
            + realtime.uncertainty_ns,
        }

    def close(self) -> None:
        buffer = self._buffer
        self._buffer = None
        self._time_anchors = []
        self._stream_id = None
        self._previous_buffer_sequence = None
        self._previous_sample_end = None
        self._previous_v7_metadata = None
        if getattr(self._sdr, "_rxbuf", None) is buffer:
            self._sdr._rxbuf = None
        try:
            _close_buffer(buffer)
        finally:
            del buffer
            gc.collect()

    def cancel(self) -> None:
        """Cancel a blocked refill and synchronously tear down this session."""

        buffer = self._buffer
        cancel = getattr(buffer, "cancel", None)
        if callable(cancel):
            cancel()
        self.close()

    def __enter__(self) -> IioMetadataCaptureSession:
        if not self.is_open:
            raise RuntimeError("IIO metadata capture is not open")
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


class IioRawSidecarCaptureSession:
    """Minimal raw ABI-3 session for an additive device-owned sidecar protocol.

    This path deliberately does not reinterpret IQ through pyadi or admit a
    legacy metadata record.  The caller owns the sidecar codec and supplies
    the binding-specific status and in-band cancellation operations.
    """

    def __init__(
        self,
        sdr: Any,
        metadata_buffer_type: Any,
        *,
        request: bytes,
        samples_per_channel: int,
        kernel_buffers: int,
        metadata_status_reader: Callable[[Any, int], bytes],
        metadata_canceller: Callable[[Any], None],
        status_capacity: int,
        metadata_capacity: int = DEFAULT_METADATA_CAPACITY,
    ) -> None:
        if not request:
            raise ValueError("raw sidecar metadata request must be nonempty")
        if samples_per_channel <= 0:
            raise ValueError("raw sidecar sample count must be positive")
        if not 2 <= kernel_buffers <= 64:
            raise ValueError("raw sidecar kernel buffer count must be within 2..64")
        if metadata_capacity <= 0 or status_capacity <= 0:
            raise ValueError("raw sidecar metadata/status capacities must be positive")
        self._sdr = sdr
        self._metadata_buffer_type = metadata_buffer_type
        self._request = bytes(request)
        self._samples_per_channel = samples_per_channel
        self._kernel_buffers = kernel_buffers
        self._metadata_status_reader = metadata_status_reader
        self._metadata_canceller = metadata_canceller
        self._status_capacity = status_capacity
        self._metadata_capacity = metadata_capacity
        self._buffer: Any | None = None
        self._open_clock_bracket: IioBufferOpenClockBracket | None = None

    @property
    def is_open(self) -> bool:
        return self._buffer is not None

    @property
    def open_clock_bracket(self) -> IioBufferOpenClockBracket:
        bracket = self._open_clock_bracket
        if bracket is None:
            raise RuntimeError("raw sidecar metadata capture has no OPEN clock bracket")
        return bracket

    def open(self) -> None:
        if self._buffer is not None:
            raise RuntimeError("raw sidecar metadata capture is already open")
        self._open_clock_bracket = None
        self._prime_dual_rx_layout()
        actual = getattr(self._sdr._rxadc, "kernel_buffers_count", None)
        if actual is None or int(actual) != self._kernel_buffers:
            raise RuntimeError("raw sidecar kernel-buffer readback changed before OPEN")
        try:
            before_monotonic_ns = time.monotonic_ns()
            before_realtime_ns = time.time_ns()
            self._buffer = self._metadata_buffer_type(
                self._sdr._rxadc,
                self._samples_per_channel,
                self._request,
                self._metadata_capacity,
            )
            after_realtime_ns = time.time_ns()
            after_monotonic_ns = time.monotonic_ns()
            self._open_clock_bracket = IioBufferOpenClockBracket(
                before_realtime_ns=before_realtime_ns,
                before_monotonic_ns=before_monotonic_ns,
                after_realtime_ns=after_realtime_ns,
                after_monotonic_ns=after_monotonic_ns,
            )
            self._sdr._rxbuf = self._buffer
        except BaseException:
            self.close()
            raise

    def _prime_dual_rx_layout(self) -> None:
        if tuple(int(item) for item in self._sdr.rx_enabled_channels) != (0, 1):
            raise RuntimeError("raw sidecar capture requires paired RX channels")
        self._sdr.rx_destroy_buffer()
        self._sdr.rx_buffer_size = self._samples_per_channel
        setter = getattr(self._sdr._rxadc, "set_kernel_buffers_count", None)
        if not callable(setter):
            raise RuntimeError("raw sidecar kernel-buffer count is not configurable")
        prime_count = min(self._kernel_buffers, _PRIME_KERNEL_BUFFERS)
        if prime_count != self._kernel_buffers:
            result = setter(prime_count)
            if isinstance(result, int) and result < 0:
                raise RuntimeError("raw sidecar prime kernel-buffer configuration failed")
        ordinary_buffer = None
        try:
            signal = np.asarray(self._sdr.rx())
            if signal.shape != (2, self._samples_per_channel) or not np.iscomplexobj(signal):
                raise RuntimeError("raw sidecar prime did not establish paired complex RX")
            ordinary_buffer = getattr(self._sdr, "_rxbuf", None)
        finally:
            self._sdr.rx_destroy_buffer()
            try:
                _close_buffer(ordinary_buffer)
            finally:
                del ordinary_buffer
                gc.collect()
                if prime_count != self._kernel_buffers:
                    result = setter(self._kernel_buffers)
                    if isinstance(result, int) and result < 0:
                        raise RuntimeError(
                            "raw sidecar final kernel-buffer configuration failed"
                        )

    def read_block(self) -> IioRawSidecarBlock:
        buffer = self._buffer
        if buffer is None:
            raise RuntimeError("raw sidecar metadata capture is not open")
        buffer.refill()
        iq_payload = bytes(buffer.read())
        raw_metadata = buffer.metadata
        if raw_metadata is None:
            raise RuntimeError("raw sidecar refill returned no metadata")
        raw = bytes(raw_metadata)
        if len(raw) < 8:
            raise RuntimeError("raw sidecar metadata is shorter than its ABI header")
        base_bytes = struct.unpack_from("<H", raw, 6)[0]
        if not 8 <= base_bytes < len(raw):
            raise RuntimeError("raw sidecar metadata does not contain an appended record")
        parsed = RadioMetadataV6.unpack(raw[:base_bytes])
        base = parsed.base
        if (
            base.samples_per_channel != self._samples_per_channel
            or base.iq_payload_bytes != self._samples_per_channel * 8
            or base.enabled_scan_mask != 0x0F
            or base.channel_count != 2
        ):
            raise RuntimeError("raw sidecar ABI-3 geometry is not paired RX CI16")
        if not base.flags & MetadataFlags.HARDWARE_SAMPLE_COUNTER_VALID:
            raise RuntimeError("raw sidecar ABI-3 header lacks a hardware counter")
        if len(iq_payload) != base.iq_payload_bytes:
            raise RuntimeError("raw sidecar IQ bytes disagree with the ABI-3 header")
        return IioRawSidecarBlock(
            metadata_header=raw[:base_bytes],
            sidecar=raw[base_bytes:],
            iq_payload=iq_payload,
        )

    def read_status(self) -> bytes:
        if self._buffer is None:
            raise RuntimeError("raw sidecar metadata capture is not open")
        result = self._metadata_status_reader(self._buffer, self._status_capacity)
        if len(result) != self._status_capacity:
            raise RuntimeError("raw sidecar status response has the wrong size")
        return result

    def request_cancel(self) -> None:
        if self._buffer is None:
            raise RuntimeError("raw sidecar metadata capture is not open")
        self._metadata_canceller(self._buffer)

    def close(self) -> None:
        buffer = self._buffer
        self._buffer = None
        if getattr(self._sdr, "_rxbuf", None) is buffer:
            self._sdr._rxbuf = None
        try:
            _close_buffer(buffer)
        finally:
            del buffer
            gc.collect()

    def __enter__(self) -> IioRawSidecarCaptureSession:
        if not self.is_open:
            raise RuntimeError("raw sidecar metadata capture is not open")
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()
