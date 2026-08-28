"""Fail-closed metadata-enabled libiio capture session."""

from __future__ import annotations

import errno
import gc
import time
from types import TracebackType
from typing import Any

import numpy as np

from pluto_plus.direct_radio.usb import (
    MetadataFlags,
    RadioMetadataV3,
    TimeAnchorFlags,
    TimeAnchorV1,
)
from pluto_plus.errors import RadioConfigurationError
from pluto_plus.hardware.base import SampleBlockV2
from pluto_plus.hardware.sample_clock import (
    DEFAULT_SAMPLE_CLOCK_RATE_TOLERANCE_PPM,
    HostTimeAnchorMeasurement,
    capture_host_realtime_mapping,
    fit_sample_clock,
)
from pluto_plus.tandem import RadioMetadataV5, TandemMode, TandemSessionRequestV1

ADC_SAMPLE_COUNTER_LOW_REG = 0x800000B8
DEFAULT_METADATA_CAPACITY = 64 * 1024
# A 262,144-sample dual-RX refill spans about 105 ms at 2.5 MS/s. Five
# seconds leaves more than 47 refill intervals for transport jitter. Larger
# safe buffers receive eighteen native frame intervals, capped at 30 seconds.
# The largest reviewed dual-RX rung at 2.5 MS/s needs the cap to tolerate the
# kernel-queue startup latency observed on native IP without weakening the
# finite disconnect bound.
IIO_CONTEXT_TIMEOUT_MS = 5_000
IIO_CONTEXT_TIMEOUT_FRAME_MULTIPLIER = 18
IIO_CONTEXT_TIMEOUT_MAX_MS = 30_000
INITIAL_TIME_ANCHOR_COUNT = 8
MAX_TIME_ANCHORS = 32
TIME_ANCHOR_WINDOW_NS = 10_000_000_000
MAX_STARTUP_FRAME_DISCARDS = 64
_OPEN_MAX_ATTEMPTS = 3
_OPEN_RETRY_DELAY_SECONDS = 0.05


def metadata_iio_context_timeout_ms(
    sample_rate_hz: int,
    samples_per_channel: int,
) -> int:
    """Return one bounded timeout with margin for the configured native-rate refill."""

    for name, value in (
        ("sample_rate_hz", sample_rate_hz),
        ("samples_per_channel", samples_per_channel),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"{name} must be a positive integer")
    frame_duration_ms = (samples_per_channel * 1_000 + sample_rate_hz - 1) // sample_rate_hz
    return min(
        IIO_CONTEXT_TIMEOUT_MAX_MS,
        max(
            IIO_CONTEXT_TIMEOUT_MS,
            frame_duration_ms * IIO_CONTEXT_TIMEOUT_FRAME_MULTIPLIER,
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
        or not IIO_CONTEXT_TIMEOUT_MS <= timeout_ms <= IIO_CONTEXT_TIMEOUT_MAX_MS
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
        tandem_request: TandemSessionRequestV1 | None = None,
    ) -> None:
        if sample_rate_hz <= 0:
            raise ValueError("sample_rate_hz must be positive")
        if samples_per_channel <= 0:
            raise ValueError("samples_per_channel must be positive")
        if kernel_buffers <= 0:
            raise ValueError("kernel_buffers must be positive")
        if metadata_abi not in {1, 2}:
            raise ValueError("metadata_abi must be one of the supported ABIs 1 or 2")
        if metadata_capacity <= 0:
            raise ValueError("metadata_capacity must be positive")
        self._sdr = sdr
        self._metadata_buffer_type = metadata_buffer_type
        self._sample_rate_hz = int(sample_rate_hz)
        self._samples_per_channel = int(samples_per_channel)
        self._kernel_buffers = int(kernel_buffers)
        self._metadata_abi = metadata_abi
        self._metadata_capacity = int(metadata_capacity)
        self._tandem_request = tandem_request or TandemSessionRequestV1(mode=TandemMode.AUTO)
        self._buffer: Any | None = None
        self._time_anchors: list[HostTimeAnchorMeasurement] = []
        self._next_anchor_request_id = 1
        self._stream_id: int | None = None
        self._previous_buffer_sequence: int | None = None
        self._previous_sample_end: int | None = None

    @property
    def kernel_buffers(self) -> int:
        return self._kernel_buffers

    @property
    def is_open(self) -> bool:
        return self._buffer is not None

    def open(self) -> None:
        if self._buffer is not None:
            raise RuntimeError("IIO metadata capture is already open")
        self._prime_ordinary_rx()
        self._verify_kernel_buffers()
        try:
            self._buffer = self._open_metadata_buffer()
            self._sdr._rxbuf = self._buffer
            self._refresh_time_anchors(initial=True)
        except BaseException:
            self.close()
            raise

    def _prime_ordinary_rx(self) -> None:
        self._sdr.rx_destroy_buffer()
        self._sdr.rx_buffer_size = self._samples_per_channel
        ordinary_buffer = None
        try:
            signal = np.asarray(self._sdr.rx())
            expected = (len(tuple(self._sdr.rx_enabled_channels)), self._samples_per_channel)
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

    def _verify_kernel_buffers(self) -> None:
        actual = getattr(self._sdr._rxadc, "kernel_buffers_count", None)
        if actual is None:
            raise RuntimeError("RX kernel-buffer count does not support readback")
        if int(actual) != self._kernel_buffers:
            raise RuntimeError(
                f"RX kernel-buffer readback is {actual}, expected {self._kernel_buffers}"
            )

    def _open_metadata_buffer(self) -> Any:
        request = (
            None
            if self._metadata_abi == 1
            else self._tandem_request.pack(self._samples_per_channel)
        )
        for attempt in range(1, _OPEN_MAX_ATTEMPTS + 1):
            try:
                if self._metadata_abi == 1:
                    return self._metadata_buffer_type(
                        self._sdr._rxadc,
                        self._samples_per_channel,
                        self._metadata_capacity,
                    )
                return self._metadata_buffer_type(
                    self._sdr._rxadc,
                    self._samples_per_channel,
                    request,
                    self._metadata_capacity,
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
            self.close()
            raise

    def _read_block(self) -> SampleBlockV2:
        if self._buffer is None:
            raise RuntimeError("IIO metadata capture is not open")
        host_before_ns = time.time_ns()
        for startup_discard in range(MAX_STARTUP_FRAME_DISCARDS + 1):
            try:
                raw_signal = self._sdr.rx()
                break
            except OSError as error:
                if error.errno != errno.EAGAIN or startup_discard == MAX_STARTUP_FRAME_DISCARDS:
                    raise
        host_after_ns = time.time_ns()
        signal = np.asarray(raw_signal)
        expected_receivers = len(tuple(self._sdr.rx_enabled_channels))
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
        if self._metadata_abi == 1:
            metadata = RadioMetadataV3.unpack(raw_metadata)
        else:
            parsed = RadioMetadataV5.unpack(raw_metadata)
            metadata = parsed.base
            if len(raw_metadata) != parsed.header_bytes:
                raise RuntimeError("metadata refill returned trailing bytes")
        self._validate_header(metadata)
        missing = self._validate_sequence(metadata)
        self._refresh_time_anchors(initial=False)
        timing = self._capture_time(metadata.first_sample_sequence)
        utc_ns = (
            timing["sample_time_realtime_start_ns"]
            if timing is not None
            else (host_before_ns + host_after_ns) // 2
        )
        return SampleBlockV2(
            utc_ns=int(utc_ns),
            samples=signal.astype(np.complex64, copy=False),
            stream_id=int(metadata.stream_id),
            buffer_sequence=int(metadata.buffer_sequence),
            first_sample_sequence=int(metadata.first_sample_sequence),
            metadata_flags=int(metadata.flags),
            metadata_abi=self._metadata_abi,
            missing_samples_before=missing,
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
        )

    def _validate_header(self, metadata: Any) -> None:
        if metadata.samples_per_channel != self._samples_per_channel:
            raise RuntimeError("metadata sample count does not match the IIO buffer")
        if metadata.iq_payload_bytes != self._samples_per_channel * 8:
            raise RuntimeError("metadata IQ byte count does not match dual-CS16 IIO")
        if metadata.enabled_scan_mask != 0x0F or metadata.channel_count != 2:
            raise RuntimeError("metadata scan layout does not match dual-channel IIO")
        if not metadata.flags & MetadataFlags.HARDWARE_SAMPLE_COUNTER_VALID:
            raise RuntimeError("IIO metadata lacks a valid FPGA sample counter")

    def _validate_sequence(self, metadata: Any) -> int:
        stream_id = int(metadata.stream_id)
        buffer_sequence = int(metadata.buffer_sequence)
        first_sample = int(metadata.first_sample_sequence)
        if self._stream_id is None:
            if buffer_sequence != 0:
                raise RuntimeError("new metadata capture did not begin at buffer sequence zero")
            self._stream_id = stream_id
            self._previous_buffer_sequence = buffer_sequence
            self._previous_sample_end = first_sample + self._samples_per_channel
            return 0
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
        if missing != skipped_buffers * self._samples_per_channel:
            raise RuntimeError("metadata buffer and FPGA sample sequences disagree")
        self._previous_buffer_sequence = buffer_sequence
        self._previous_sample_end = first_sample + self._samples_per_channel
        return missing

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
        if getattr(self._sdr, "_rxbuf", None) is buffer:
            self._sdr._rxbuf = None
        try:
            _close_buffer(buffer)
        finally:
            del buffer
            gc.collect()

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
