"""PIL1 accounting and explicit finite IIO capture; no firmware promotion.

This experimental single-RX ABI is separate from production TAG2/HOPS. Hardware
snapshots attest an AXIS prefix, not DDR completion, disk persistence, RF signal
presence, or PSS lock. The eventual reader must retain identities, IQ hashes,
frequency/filter contracts and FPGA results alongside these snapshots.
"""

from __future__ import annotations

import hashlib
import importlib
import math
import queue
import re
import threading
import time
from dataclasses import dataclass
from fractions import Fraction
from types import TracebackType
from typing import Any, Self
from uuid import uuid4

from pluto_plus.errors import RadioConfigurationError
from pluto_plus.hardware.pss_iio import _close_iio_context

PILOT_DEVICE = "starlink-pilot-capture"
PILOT_CAPTURE_ABI = "PIL1-1.0-upper-only"
PILOT_OUTPUT_RATE_HZ = 2_500_000
PILOT_CANONICAL_RATE_HZ = 15_000_000
PILOT_SOURCE_RATES_HZ = (15_000_000, 30_000_000, 60_000_000)
PILOT_DELAY_CANONICAL_SAMPLES = 269
PILOT_FIFO_CAPACITY = 32
PILOT_MAX_FINITE_SAMPLES = 5_000_000  # Two-second envelope for a >=1s inner comparison.
PILOT_MAX_REFILL_SAMPLES = 2_500_000  # <=10 MB, below the matched DMA's 16 MiB cap.
PILOT_MAX_PROGRESS_EVENTS = 4096
_U64_MAX = (1 << 64) - 1


def _decimal(field: str, maximum: int, *, signed: bool = False) -> int:
    pattern = r"-?[0-9]+" if signed else r"[0-9]+"
    if not re.fullmatch(pattern, field, flags=re.ASCII):
        raise ValueError("PIL1 header requires decimal integers")
    value = int(field)
    if not (-maximum if signed else 0) <= value <= maximum:
        raise ValueError("PIL1 header integer is out of range")
    return value


def _count(value: int, name: str) -> int:
    if type(value) is not int or not 0 <= value <= _U64_MAX:
        raise ValueError(f"{name} must be an unsigned 64-bit integer")
    return value


@dataclass(frozen=True, slots=True)
class PilotSnapshot:
    """One immutable atomic hardware view plus contemporaneous kernel status.

    Decode retains known faults for diagnostics. Call require_complete_prefix()
    to admit a finite capture for subsequent analysis; decoding is not that gate.
    No boot/session/serial identity is carried on this wire, so callers must bind
    this record to an independently attested owner and capture session.
    """

    raw: str
    source_rate_hz: int
    generation: int
    recovery_failed: bool
    actual_source_rate_hz: int
    dma_error: int
    words: tuple[int, ...]
    first_newest_canonical_index: int
    last_newest_canonical_index: int
    admitted_samples: int
    axis_delivered_samples: int
    unsupported_samples: int
    fault_diagnostic_index: int
    ddc_accepted_samples: int
    ddc_emitted_samples: int

    @classmethod
    def decode(cls, text: str) -> Self:
        if not isinstance(text, str) or not text.isascii() or len(text) > 4096:
            raise ValueError("PIL1 snapshot must be bounded ASCII text")
        fields = text.split()
        if len(fields) != 34 or fields[:2] != ["PIL1", "00010000"]:
            raise ValueError("PIL1 snapshot envelope/version/word count is invalid")
        source, output, generation, recovery, actual = (
            _decimal(field, 0xffffffff) for field in fields[2:7]
        )
        dma_error = _decimal(fields[7], 4095, signed=True)
        if source not in PILOT_SOURCE_RATES_HZ or output != PILOT_OUTPUT_RATE_HZ:
            raise ValueError("PIL1 source/output rate is unsupported")
        if not generation or recovery not in (0, 1) or dma_error > 0:
            raise ValueError("PIL1 generation/recovery/DMA status is invalid")
        if any(not re.fullmatch(r"[0-9a-fA-F]{8}", word) for word in fields[8:]):
            raise ValueError("PIL1 payload requires exactly eight hex digits per word")
        words = tuple(int(word, 16) for word in fields[8:])
        if any(words[23:]) or words[17] >> 16 or words[18] & ~0x7f or words[19] & ~0x1f:
            raise ValueError("PIL1 reserved bits are nonzero")
        values = tuple(words[n] | (words[n+1] << 32) for n in range(0, 16, 2))
        first, last, admitted, delivered, unsupported, _, accepted, emitted = values
        queued = words[22]
        if not delivered <= admitted or admitted - delivered != queued:
            raise ValueError("PIL1 admitted/delivered/queued accounting disagrees")
        if not queued <= words[21] <= PILOT_FIFO_CAPACITY or words[17] >> 8 > 128:
            raise ValueError("PIL1 FIFO count/high water is out of bounds")
        if bool(words[19] & 2) != bool(queued) or bool(words[19] & 8) != bool(admitted):
            raise ValueError("PIL1 status disagrees with prefix/queue counters")
        if bool(words[19] & 4) != bool(words[18]):
            raise ValueError("PIL1 status disagrees with capture faults")
        if (words[19] & 1 or admitted) and (not words[19] & 16 or not words[20]):
            raise ValueError("PIL1 active/prefix state lacks an armed visit")
        if admitted:
            if first < 538 or first % 6 or last != first + 6 * (admitted - 1):
                raise ValueError("PIL1 supported prefix index/phase/span is inconsistent")
            source_last = (last - PILOT_DELAY_CANONICAL_SAMPLES) * (
                source // PILOT_CANONICAL_RATE_HZ
            )
            if source_last > _U64_MAX:
                raise ValueError("PIL1 prefix exceeds the original source counter")
        elif first or last:
            raise ValueError("PIL1 empty prefix must have zero first/last indexes")
        if emitted < admitted + unsupported or accepted < emitted:
            raise ValueError("PIL1 DDC counters cannot account for the exported prefix")
        return cls(text, source, generation, bool(recovery), actual, dma_error, words, *values)

    @property
    def active(self) -> bool:
        return bool(self.words[19] & 1)

    @property
    def visit_id(self) -> int:
        return self.words[20]

    @property
    def capture_faults(self) -> int:
        return self.words[18]

    @property
    def ddc_faults(self) -> int:
        return self.words[17] & 0xff

    @property
    def saturation_events(self) -> int:
        return self.words[16]

    def source_center(self, output_sample: int) -> int:
        """Original full-rate coordinate of an AXIS-delivered sample, not wall time."""
        _count(output_sample, "output_sample")
        if output_sample >= self.axis_delivered_samples:
            raise ValueError("sample is outside the AXIS-delivered prefix")
        # Upstream 30/60 conditioners already correct their own filter delay.
        return (self.first_newest_canonical_index + 6 * output_sample -
                PILOT_DELAY_CANONICAL_SAMPLES) * (
                    self.source_rate_hz // PILOT_CANONICAL_RATE_HZ)

    def require_complete_prefix(
        self, *, expected_visit_id: int, expected_source_rate_hz: int,
        expected_samples: int, received_bytes: int,
    ) -> None:
        """Check finite capture counts/health, NEVER claim detection or persistence.

        received_bytes must come from the actual IIO reader, not this snapshot.
        A clipped capture is retained but rejected from the initial comparison
        gate. Fault coordinates remain diagnostic, not the first missing RF beat.
        """
        if type(expected_visit_id) is not int or not 0 < expected_visit_id <= 0xffffffff:
            raise ValueError("expected_visit_id must be a nonzero u32")
        if (type(expected_source_rate_hz) is not int or
                expected_source_rate_hz not in PILOT_SOURCE_RATES_HZ):
            raise ValueError("expected source rate is unsupported")
        _count(expected_samples, "expected_samples")
        _count(received_bytes, "received_bytes")
        if not expected_samples:
            raise ValueError("expected_samples must be positive")
        if self.visit_id != expected_visit_id or self.source_rate_hz != expected_source_rate_hz:
            raise ValueError("PIL1 snapshot does not match the expected visit/source rate")
        if self.actual_source_rate_hz != self.source_rate_hz:
            raise ValueError("PIL1 actual PHY source rate changed")
        if self.active or self.words[22]:
            raise ValueError("PIL1 capture is still active or draining")
        if self.recovery_failed or self.dma_error or self.capture_faults or self.ddc_faults:
            raise ValueError("PIL1 capture has a hardware/DMA/recovery fault")
        if self.saturation_events:
            raise ValueError("PIL1 capture reports arithmetic saturation")
        if (self.admitted_samples != expected_samples or
                self.axis_delivered_samples != expected_samples):
            raise ValueError("PIL1 finite capture sample count is incomplete")
        if received_bytes != expected_samples * 4:
            raise ValueError("IIO reader byte count does not match the PIL1 prefix")
        if self.ddc_emitted_samples != self.admitted_samples + self.unsupported_samples:
            raise ValueError("PIL1 DDC emitted unaccounted samples")

    @property
    def axis_prefix_duration_seconds(self) -> Fraction:
        """N / Fs exposure, not the (N - 1) / Fs separation of endpoint centers."""
        return Fraction(self.axis_delivered_samples, PILOT_OUTPUT_RATE_HZ)


@dataclass(frozen=True, slots=True)
class PilotCapture:
    """Retained finite IQ and accounting, NOT complete paired/RF qualification.

    The session UUID is host-generated, not a radio boot identity. PIL1 does not
    expose all upstream PSS/conditioner health; this receipt cannot qualify it.
    IQ is hashed in memory, not persisted to disk by this API.
    """

    serial: str
    session_id: str
    boot_id: str | None
    visit_id: int
    source_rate_hz: int
    iq: bytes
    iq_sha256: str
    snapshot_before: PilotSnapshot
    snapshot_armed: PilotSnapshot
    snapshot_final: PilotSnapshot
    output_rate_hz: int = PILOT_OUTPUT_RATE_HZ
    upstream_health_qualified: bool = False
    live_signal_qualified: bool = False
    disk_persisted: bool = False
    snapshot_origin: PilotSnapshot | None = None


@dataclass(frozen=True, slots=True)
class PilotEventIdentity:
    """Caller-bound finite capture identity, not independent firmware attestation."""

    serial: str
    session_id: str
    boot_id: str | None
    visit_id: int
    source_rate_hz: int
    requested_samples: int
    refill_samples: int
    output_rate_hz: int = PILOT_OUTPUT_RATE_HZ


@dataclass(frozen=True, slots=True)
class PilotArmedEvent:
    """Verified DMA-before-ARM snapshot; does NOT assert any host-received IQ."""

    identity: PilotEventIdentity
    snapshot: PilotSnapshot


@dataclass(frozen=True, slots=True)
class PilotOriginEvent:
    """First actual full refill, anchored to a validated hardware prefix origin.

    An earlier ARM snapshot can supply the origin; its delivered count need not
    cover received_samples. The latter is from the reader, not that snapshot.
    This early observation remains provisional until the final capture receipt.
    """

    identity: PilotEventIdentity
    snapshot: PilotSnapshot
    received_samples: int

    @property
    def first_source_center(self) -> int:
        return self.snapshot.source_center(0)


@dataclass(frozen=True, slots=True)
class PilotIqChunkEvent:
    """Exact complete CI16 refill at an output-sample offset, not a disk receipt."""

    identity: PilotEventIdentity
    output_offset: int
    iq: bytes

    @property
    def sample_count(self) -> int:
        return len(self.iq) // 4


@dataclass(frozen=True, slots=True)
class PilotTerminalEvent:
    """Best-effort post-cleanup summary; capture() return/error is authoritative.

    published_iq_bytes counts successfully enqueued chunks, NOT consumer reads
    or durable writes. complete means only the finite reader's transport gate.
    """

    identity: PilotEventIdentity
    complete: bool
    received_bytes: int
    published_iq_bytes: int
    iq_sha256: str
    snapshots: tuple[PilotSnapshot, ...]
    failure: str | None
    cleanup_errors: tuple[str, ...]
    progress_errors: tuple[str, ...]


PilotCaptureEvent = PilotArmedEvent | PilotOriginEvent | PilotIqChunkEvent | PilotTerminalEvent


class PilotCaptureError(RadioConfigurationError):
    """Failed capture retaining received bytes and available health evidence."""

    def __init__(
        self, message: str, *, session_id: str, visit_id: int, partial_iq: bytes,
        snapshots: tuple[PilotSnapshot, ...], cleanup_errors: tuple[str, ...],
        progress_errors: tuple[str, ...] = (),
    ) -> None:
        super().__init__(message)
        self.session_id = session_id
        self.visit_id = visit_id
        self.partial_iq = partial_iq
        self.snapshots = snapshots
        self.cleanup_errors = cleanup_errors
        self.progress_errors = progress_errors


def _bounded_integer(value: int, name: str, maximum: int) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError(f"{name} must be an integer from 1 through {maximum}")
    return value


def _pilot_attr(device: Any, name: str) -> str:
    try:
        return str(device.attrs[name].value).strip()
    except (AttributeError, KeyError) as error:
        raise RadioConfigurationError(f"PIL1 lacks required attribute {name}") from error


def _destroy_pilot_buffer(iio_module: Any, buffer: Any) -> None:
    """Destroy after a bounded read returns; do NOT poison network CLOSE by cancel.

    libiio's network cancellation skips the acknowledged remote CLOSE operation.
    The caller uses cooperative cancellation and context timeouts instead, then
    verifies terminal health and direct-mode restoration after destruction.
    """
    closer = getattr(buffer, "close", None) or getattr(buffer, "destroy", None)
    if callable(closer):
        closer()
        return
    native = getattr(buffer, "_buffer", None)
    destroy = getattr(iio_module, "_buffer_destroy", None)
    if native is None or not callable(destroy):
        raise RadioConfigurationError("PIL1 buffer exposes no deterministic destroy operation")
    buffer._buffer = None
    destroy(native)


class PilotIioClient:
    """Serial-attested finite PIL1 reader, separate from persistent hopping.

    Requires a caller-owned radio lease; this class never discovers radios,
    retunes a PHY, enables TX, or configures legacy raw/dual-RX capture. The
    matched kernel arms AFTER DMA submission when Buffer is created and stops
    and drains BEFORE aborting DMA on destruction. Reusable finite captures do
    not imply the separate PSS map producer can be restarted.

    Network operations use a finite context timeout plus a capture deadline.
    cancel() is cooperative, with latency bounded by the current I/O timeout.
    The initial libiio Context constructor uses libiio's connection timeout.
    """

    def __init__(
        self, context: Any, iio_module: Any, *, expected_serial: str,
        source_rate_hz: int, io_timeout_ms: int = 1000, expected_boot_id: str | None = None,
    ) -> None:
        self._validate_connection(expected_serial, source_rate_hz, io_timeout_ms, expected_boot_id)
        self.context = context
        self._iio = iio_module
        self.serial = expected_serial
        self.source_rate_hz = source_rate_hz
        self.io_timeout_ms = io_timeout_ms
        self.session_id = str(uuid4())
        self.boot_id: str | None = None
        self._closed = False
        self._busy = False
        self._unusable = False
        self._cancel = threading.Event()
        self._timeout(io_timeout_ms)
        self._attest_identity(expected_boot_id)
        self.device = context.find_device(PILOT_DEVICE)
        if self.device is None:
            raise RadioConfigurationError(f"IIO context lacks {PILOT_DEVICE}")
        self._channels = self._require_layout()

    @staticmethod
    def _validate_connection(
        serial: str, rate: int, timeout: int, boot_id: str | None,
    ) -> None:
        if (not isinstance(serial, str) or not serial or len(serial) > 256 or
                not serial.isascii() or any(char.isspace() for char in serial)):
            raise ValueError("an exact nonempty radio serial is required")
        if type(rate) is not int or rate not in PILOT_SOURCE_RATES_HZ:
            raise ValueError("source_rate_hz must be 15000000, 30000000, or 60000000")
        _bounded_integer(timeout, "io_timeout_ms", 60_000)
        if boot_id is not None and (not isinstance(boot_id, str) or not boot_id.strip()):
            raise ValueError("expected_boot_id must be nonempty when specified")

    @classmethod
    def connect(
        cls, uri: str, *, expected_serial: str, source_rate_hz: int,
        io_timeout_ms: int = 1000, expected_boot_id: str | None = None,
        iio_module: Any | None = None,
    ) -> Self:
        cls._validate_connection(expected_serial, source_rate_hz, io_timeout_ms, expected_boot_id)
        if not isinstance(uri, str) or not uri.strip():
            raise ValueError("an explicit IIO URI is required; discovery is not supported")
        module = iio_module or importlib.import_module("iio")
        context = module.Context(uri)
        try:
            return cls(context, module, expected_serial=expected_serial,
                       source_rate_hz=source_rate_hz, io_timeout_ms=io_timeout_ms,
                       expected_boot_id=expected_boot_id)
        except BaseException as error:
            try:
                _close_iio_context(module, context)
            except BaseException as cleanup_error:
                error.add_note(f"PIL1 context cleanup failed: {cleanup_error}")
            raise

    def _timeout(self, milliseconds: int) -> None:
        setter = getattr(self.context, "set_timeout", None)
        if not callable(setter):
            raise RadioConfigurationError("PIL1 requires bounded libiio context timeouts")
        setter(milliseconds)

    def _attest_identity(self, expected_boot_id: str | None) -> None:
        attrs = {str(key): str(value) for key, value in self.context.attrs.items()}
        serials = [attrs[key] for key in ("hw_serial", "usb,serial", "serial") if attrs.get(key)]
        if not serials or any(serial != self.serial for serial in serials):
            raise RadioConfigurationError("PIL1 context serial does not match the expected radio")
        observed_boot = attrs.get("boot_id") or None
        if expected_boot_id is not None and observed_boot != expected_boot_id:
            raise RadioConfigurationError("PIL1 context cannot attest the expected boot identity")
        self.boot_id = observed_boot

    def _require_layout(self) -> tuple[Any, Any]:
        if _pilot_attr(self.device, "capture_abi") != PILOT_CAPTURE_ABI:
            raise RadioConfigurationError("unsupported PIL1 capture ABI")
        channels = sorted(
            (channel for channel in self.device.channels if channel.scan_element),
            key=lambda channel: channel.index,
        )
        if len(channels) != 2:
            raise RadioConfigurationError("PIL1 requires exactly two I/Q scan channels")
        for index, channel in enumerate(channels):
            fmt = channel.data_format
            if (channel.index != index or channel.output or
                    getattr(channel.modifier, "name", None) != ("IIO_MOD_I", "IIO_MOD_Q")[index] or
                    fmt.length != 16 or fmt.bits != 16 or fmt.shift != 0 or fmt.repeat != 1 or
                    not fmt.is_signed or fmt.is_be or not fmt.is_fully_defined):
                raise RadioConfigurationError("PIL1 requires ordered fully-defined signed LE16 I/Q")
            if _pilot_attr(channel, "sampling_frequency") != str(PILOT_OUTPUT_RATE_HZ):
                raise RadioConfigurationError("PIL1 export rate is not 2500000 samples/second")
        return channels[0], channels[1]

    def _snapshot(self) -> PilotSnapshot:
        return PilotSnapshot.decode(_pilot_attr(self.device, "capture_snapshot"))

    def _require_health(self, snapshot: PilotSnapshot) -> None:
        if (snapshot.source_rate_hz != self.source_rate_hz or
                snapshot.actual_source_rate_hz != self.source_rate_hz):
            raise RadioConfigurationError("PIL1 source/actual PHY rate differs from requested rate")
        if (snapshot.recovery_failed or snapshot.dma_error or snapshot.capture_faults or
                snapshot.ddc_faults or snapshot.saturation_events):
            raise RadioConfigurationError("PIL1 snapshot reports hardware/DMA/clipping fault")

    def cancel(self) -> None:
        """Request capture cancellation; never concurrently destroy a live buffer."""
        self._cancel.set()

    def capture(
        self, *, visit_id: int, samples: int = 300_000, refill_samples: int = 25_000,
        timeout_ms: int = 5000,
        progress_queue: queue.Queue[PilotCaptureEvent] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> PilotCapture:
        """Capture finite IQ, optionally publishing bounded, provisional events.

        Supply a standard FIFO Queue with maxsize 1..4096 and a separate consumer.
        Enqueue never waits for capacity: backpressure fails capture, preserving
        partial IQ and cleanup evidence. The caller owns the queue and must not
        mutate it or its methods/limits while capturing. No callbacks run here.
        An external Event is never cleared, including before startup; cancel()
        retains its legacy per-capture reset. Neither token calls native cancel.
        """
        _bounded_integer(visit_id, "visit_id", 0xffffffff)
        _bounded_integer(samples, "samples", PILOT_MAX_FINITE_SAMPLES)
        _bounded_integer(refill_samples, "refill_samples", PILOT_MAX_REFILL_SAMPLES)
        _bounded_integer(timeout_ms, "timeout_ms", 60_000)
        if refill_samples % 2:
            raise ValueError("PIL1 refills must align to an eight-byte paired DMA beat")
        if samples % refill_samples:
            raise ValueError("finite samples must be a whole number of IIO refills")
        if progress_queue is not None:
            if type(progress_queue) is not queue.Queue:
                raise ValueError("progress_queue must be a standard bounded FIFO queue.Queue")
            _bounded_integer(progress_queue.maxsize, "progress_queue.maxsize",
                             PILOT_MAX_PROGRESS_EVENTS)
        if cancel_event is not None and type(cancel_event) is not threading.Event:
            raise ValueError("cancel_event must be a threading.Event")
        if self._closed or self._busy or self._unusable:
            raise RadioConfigurationError("PIL1 client is closed, capturing, or needs reconnection")
        self._busy = True
        self._cancel.clear()
        deadline = time.monotonic() + timeout_ms / 1000
        payload = bytearray()
        snapshots: list[PilotSnapshot] = []
        buffer: Any | None = None
        original: tuple[str, str, tuple[bool, bool]] | None = None
        cleanup_errors: list[str] = []
        progress_errors: list[str] = []
        failure: BaseException | None = None
        io_started = False
        published_iq_bytes = 0
        origin: PilotSnapshot | None = None
        prefix_first: int | None = None
        identity = PilotEventIdentity(
            self.serial, self.session_id, self.boot_id, visit_id, self.source_rate_hz,
            samples, refill_samples,
        )

        def budget() -> None:
            nonlocal io_started
            if self._cancel.is_set() or (cancel_event is not None and cancel_event.is_set()):
                raise RadioConfigurationError("PIL1 capture cancelled")
            remaining = math.ceil((deadline - time.monotonic()) * 1000)
            if remaining <= 0:
                raise TimeoutError("PIL1 finite capture deadline expired")
            io_started = True
            self._timeout(min(self.io_timeout_ms, remaining))

        def emit(event: PilotCaptureEvent) -> None:
            assert progress_queue is not None
            try:
                progress_queue.put_nowait(event)
            except Exception as error:
                message = ("PIL1 progress queue is full" if isinstance(error, queue.Full) else
                           f"PIL1 progress event delivery failed: {error}")
                progress_errors.append(message)
                raise RadioConfigurationError(message) from error

        def check_progress_snapshot(
            snapshot: PilotSnapshot, previous: PilotSnapshot | None,
        ) -> None:
            nonlocal prefix_first
            self._attest_identity(identity.boot_id)
            if self.boot_id != identity.boot_id:
                raise RadioConfigurationError("PIL1 progress boot identity changed")
            self._require_health(snapshot)
            if previous is not None and snapshot.generation <= previous.generation:
                raise RadioConfigurationError("PIL1 progress snapshot generation did not advance")
            if snapshot.visit_id != visit_id or not snapshot.words[19] & 16:
                raise RadioConfigurationError("PIL1 progress snapshot changed the armed visit")
            if snapshot.admitted_samples > samples:
                raise RadioConfigurationError("PIL1 progress prefix exceeds the finite request")
            if prefix_first is not None and (
                not snapshot.admitted_samples or
                snapshot.first_newest_canonical_index != prefix_first
            ):
                raise RadioConfigurationError("PIL1 progress prefix origin changed")
            if snapshot.admitted_samples:
                prefix_first = snapshot.first_newest_canonical_index

        try:
            budget()
            self._attest_identity(self.boot_id)
            self._require_layout()
            before = self._snapshot()
            snapshots.append(before)
            self._require_health(before)
            if before.active or before.words[22]:
                raise RadioConfigurationError("PIL1 capture is already active or draining")
            original = (
                _pilot_attr(self.device, "capture_visit_id"),
                _pilot_attr(self.device, "capture_sample_limit"),
                (bool(self._channels[0].enabled), bool(self._channels[1].enabled)),
            )
            for name, value in (("capture_visit_id", visit_id), ("capture_sample_limit", samples)):
                budget()
                self.device.attrs[name].value = str(value)
                if _pilot_attr(self.device, name) != str(value):
                    raise RadioConfigurationError(f"PIL1 {name} readback mismatch")
            for channel in self._channels:
                channel.enabled = True
            if self.device.sample_size != 4:
                raise RadioConfigurationError("PIL1 scan stride contains padding or extra channels")
            budget()
            buffer = self._iio.Buffer(self.device, refill_samples, False)
            if buffer.step != 4 or len(buffer) != refill_samples * 4:
                raise RadioConfigurationError("PIL1 buffer stride/length differs from finite CI16")
            # pylibiio 0.25 exposes sample count privately; byte length/step are
            # public. Check the count too when supplied, never rewrite it.
            binding_count = getattr(buffer, "sample_count", getattr(buffer, "_samples_count", None))
            if binding_count is not None and binding_count != refill_samples:
                raise RadioConfigurationError(
                    "PIL1 binding sample count differs from finite request"
                )
            budget()
            armed = self._snapshot()
            snapshots.append(armed)
            self._require_health(armed)
            if armed.visit_id != visit_id or not armed.words[19] & 16:
                raise RadioConfigurationError("PIL1 DMA creation did not arm the requested visit")
            if progress_queue is not None:
                # The matched driver's preenable CLEAR resets generation to
                # zero. ARM is the NEW epoch baseline, never comparable to before.
                check_progress_snapshot(armed, None)
                emit(PilotArmedEvent(identity, armed))
            for index in range(samples // refill_samples):
                budget()
                buffer.refill()
                chunk = bytes(buffer.read())
                # Retain a malformed short buffer for diagnostics without letting
                # an oversized binding result defeat the finite memory bound.
                payload.extend(chunk[:refill_samples * 4])
                if len(chunk) != refill_samples * 4:
                    raise RadioConfigurationError(
                        "PIL1 refill is short or exceeds its finite buffer"
                    )
                if progress_queue is not None:
                    if index == 0:
                        if armed.axis_delivered_samples:
                            origin = armed
                            check_progress_snapshot(origin, None)
                        else:
                            budget()
                            origin = self._snapshot()
                            snapshots.append(origin)
                            check_progress_snapshot(origin, armed)
                            if origin.axis_delivered_samples < refill_samples:
                                raise RadioConfigurationError(
                                    "PIL1 origin snapshot cannot account for the received prefix"
                                )
                        # Only after an actual complete refill, even when the
                        # origin snapshot itself was obtained before that read.
                        emit(PilotOriginEvent(identity, origin, refill_samples))
                    emit(PilotIqChunkEvent(identity, index * refill_samples, chunk))
                    published_iq_bytes += len(chunk)
                budget()
            budget()
            captured = self._snapshot()
            snapshots.append(captured)
            captured.require_complete_prefix(
                expected_visit_id=visit_id, expected_source_rate_hz=self.source_rate_hz,
                expected_samples=samples, received_bytes=len(payload),
            )
            if captured.generation == armed.generation:
                raise RadioConfigurationError("PIL1 snapshot generation did not advance")
            if progress_queue is not None:
                check_progress_snapshot(captured, snapshots[-2])
        except BaseException as error:
            failure = error
        finally:
            # Recovery gets its own bounded I/O budget, even after cancellation.
            if io_started:
                try:
                    self._timeout(self.io_timeout_ms)
                except BaseException as error:
                    cleanup_errors.append(f"timeout: {error}")
            if buffer is not None:
                try:
                    _destroy_pilot_buffer(self._iio, buffer)
                except BaseException as error:
                    cleanup_errors.append(f"buffer stop/drain/destroy: {error}")
                try:
                    stopped = self._snapshot()
                    snapshots.append(stopped)
                    if failure is None:
                        stopped.require_complete_prefix(
                            expected_visit_id=visit_id, expected_source_rate_hz=self.source_rate_hz,
                            expected_samples=samples, received_bytes=len(payload),
                        )
                        if stopped.words != captured.words:
                            raise RadioConfigurationError("PIL1 accounting changed during cleanup")
                        if progress_queue is not None:
                            check_progress_snapshot(stopped, captured)
                except BaseException as error:
                    cleanup_errors.append(f"terminal snapshot: {error}")
            if original is not None:
                for channel, enabled in zip(self._channels, original[2], strict=True):
                    try:
                        channel.enabled = enabled
                        if bool(channel.enabled) != enabled:
                            raise RadioConfigurationError("restored scan readback mismatch")
                    except BaseException as error:
                        cleanup_errors.append(f"scan restoration: {error}")
                for name, restored_value in zip(
                    ("capture_visit_id", "capture_sample_limit"), original[:2], strict=True,
                ):
                    try:
                        self.device.attrs[name].value = restored_value
                        if _pilot_attr(self.device, name) != restored_value:
                            raise RadioConfigurationError("restored attribute readback mismatch")
                    except BaseException as error:
                        cleanup_errors.append(f"{name} restoration: {error}")
            if io_started:
                try:
                    self._attest_identity(self.boot_id)
                except BaseException as error:
                    cleanup_errors.append(f"terminal identity: {error}")
            self._busy = False
        iq = bytes(payload)
        iq_sha256 = hashlib.sha256(iq).hexdigest()
        # Finalization point: cancellation during the finite copy/hash still
        # invalidates completion; cancellation AFTER this decision cannot undo it.
        if failure is None and cancel_event is not None and cancel_event.is_set():
            failure = RadioConfigurationError("PIL1 capture cancelled")
        if progress_queue is not None:
            try:
                emit(PilotTerminalEvent(
                    identity=identity, complete=failure is None and not cleanup_errors,
                    received_bytes=len(iq), published_iq_bytes=published_iq_bytes,
                    iq_sha256=iq_sha256, snapshots=tuple(snapshots),
                    failure=str(failure) if failure is not None else None,
                    cleanup_errors=tuple(cleanup_errors), progress_errors=tuple(progress_errors),
                ))
            except BaseException as error:
                if failure is None:
                    failure = error
        if failure is not None or cleanup_errors:
            self._unusable = True
            capture_error = PilotCaptureError(
                f"PIL1 finite capture failed: {failure or '; '.join(cleanup_errors)}",
                session_id=self.session_id, visit_id=visit_id, partial_iq=iq,
                snapshots=tuple(snapshots), cleanup_errors=tuple(cleanup_errors),
                progress_errors=tuple(progress_errors),
            )
            if isinstance(failure, (KeyboardInterrupt, SystemExit)):
                failure.add_note(str(capture_error))
                raise failure
            raise capture_error from failure
        return PilotCapture(
            serial=self.serial, session_id=self.session_id, boot_id=self.boot_id,
            visit_id=visit_id, source_rate_hz=self.source_rate_hz, iq=iq,
            iq_sha256=iq_sha256, snapshot_before=snapshots[0],
            snapshot_armed=snapshots[1], snapshot_final=snapshots[-1],
            snapshot_origin=origin,
        )

    def close(self) -> None:
        if self._busy:
            raise RadioConfigurationError(
                "cancel and finish PIL1 capture before closing its context"
            )
        if not self._closed:
            self._closed = True
            _close_iio_context(self._iio, self.context)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        try:
            self.close()
        except BaseException as cleanup_error:
            if exc_value is None:
                raise
            exc_value.add_note(f"PIL1 context cleanup failed: {cleanup_error}")
