from __future__ import annotations

import dataclasses
import struct
import zlib
from types import SimpleNamespace
from typing import Any

import numpy as np
import pytest

from pluto_plus.direct_radio.usb import MetadataFlags
from pluto_plus.hardware.iio import IioReceiverSettingsReadback
from pluto_plus.hardware.iio_metadata import (
    IioBufferOpenClockBracket,
    IioRawSidecarBlock,
    IioRawSidecarCaptureSession,
)
from pluto_plus.hardware.iio_persistent_hop import (
    IioPersistentHopBackend,
    _cancel_metadata_session,
    _read_metadata_status,
)
from pluto_plus.models import GainMode, RadioIdentity, Transport
from pluto_plus.persistent_hop import (
    PERSISTENT_HOP_CAPABILITIES,
    PERSISTENT_HOP_NONE_PROFILE,
    PersistentHopClient,
    PersistentHopEvidenceV1,
    PersistentHopPlanV1,
    PersistentHopProfileV1,
    PersistentHopRequestV1,
    PersistentHopSessionState,
    PersistentHopStartClockBracketV1,
    PersistentHopStatusFlag,
    PersistentHopStatusV1,
    PersistentHopTarget,
    PersistentHopTerminalReason,
)
from pluto_plus.tandem import TandemMode, TandemSessionRequestV1

URI = "ip:192.168.1.18"
SERIAL = "1040007c4a94000211000b009186843ef2"
SESSION = 17
SAMPLES = 1_024


def _plan() -> PersistentHopPlanV1:
    profiles = tuple(
        PersistentHopProfileV1(
            target_index=int(target),
            fastlock_profile_index=int(target),
            center_hz=1_000_001_000 + int(target) * 1_000_000,
            lo_hz=1_000_000_000 + int(target) * 1_000_000,
            profile_crc32=0xA0000000 + int(target),
        )
        for target in PersistentHopTarget
    )
    return PersistentHopPlanV1(
        nominal_duration_seconds=300,
        valid_visit_ms=120,
        sample_rate_hz=2_500_000,
        rf_bandwidth_hz=2_500_000,
        transition_guard_samples=10,
        samples_per_block=SAMPLES,
        kernel_buffers=2,
        minimum_valid_duty_ppm=900_000,
        manual_gain_db=40.0,
        profiles=profiles,
    )


def _status(state: PersistentHopSessionState) -> bytes:
    terminal = state is not PersistentHopSessionState.RUNNING
    return PersistentHopStatusV1(
        state=state,
        reason=(
            PersistentHopTerminalReason.CLIENT_CLOSE
            if terminal
            else PersistentHopTerminalReason.NONE
        ),
        error_code=0,
        flags=(
            PersistentHopStatusFlag.RESTORE_REQUIRED
            | (
                PersistentHopStatusFlag.TERMINAL
                | PersistentHopStatusFlag.RESTORE_ATTEMPTED
                | PersistentHopStatusFlag.RESTORE_SUCCEEDED
                if terminal
                else PersistentHopStatusFlag(0)
            )
        ),
        session_id=SESSION,
        planned_dwells=2_500,
        visits_started=0,
        events_emitted=0,
        next_event_sequence=0,
        last_block_sequence=0,
        last_block_end_counter=124,
        first_counter=100,
        final_counter=124 if terminal else 0,
        restore_before_counter=124 if terminal else 0,
        restore_after_counter=125 if terminal else 0,
        restored_lo_frequency_hz=915_000_000 if terminal else 0,
        restore_error_code=0,
        active_profile_index=PERSISTENT_HOP_NONE_PROFILE,
        restored_profile_index=PERSISTENT_HOP_NONE_PROFILE,
        startup_invalid_start_counter=0,
        startup_invalid_end_counter_exclusive=0,
        device_dropped_events=0,
    ).pack()


def _sidecar() -> bytes:
    return PersistentHopEvidenceV1(
        flags=PersistentHopStatusFlag.RESTORE_REQUIRED,
        session_id=SESSION,
        buffer_sequence=0,
        block_first_counter=100,
        block_end_counter_exclusive=124,
        state=PersistentHopSessionState.RUNNING,
        reason=PersistentHopTerminalReason.NONE,
        error_code=0,
    ).pack()


def _base_header() -> bytes:
    raw = bytearray(44)
    struct.pack_into("<Q", raw, 16, 99)
    struct.pack_into("<Q", raw, 24, 0)
    struct.pack_into("<Q", raw, 32, 100)
    struct.pack_into("<I", raw, 40, 24)
    return bytes(raw)


class _FakeCapture:
    def __init__(self) -> None:
        self.cancelled = False
        self.closed = False
        self._blocks = [
            IioRawSidecarBlock(
                metadata_header=_base_header(),
                sidecar=_sidecar(),
                iq_payload=bytes(24 * 8),
            )
        ]
        self.statuses = [_status(PersistentHopSessionState.RUNNING)]
        self.open_clock_bracket = IioBufferOpenClockBracket(
            before_realtime_ns=1_000_000_000,
            before_monotonic_ns=100_000_000,
            after_realtime_ns=1_002_000_000,
            after_monotonic_ns=102_000_000,
        )

    @property
    def is_open(self) -> bool:
        return not self.closed

    def read_block(self) -> IioRawSidecarBlock:
        return self._blocks.pop(0)

    def read_status(self) -> bytes:
        return self.statuses.pop(0)

    def request_cancel(self) -> None:
        self.cancelled = True
        self.statuses.append(_status(PersistentHopSessionState.CANCELLED))

    def close(self) -> None:
        self.closed = True


class _FakeRadio:
    def __init__(self) -> None:
        self.identity = RadioIdentity(
            radio_id=SERIAL,
            serial=SERIAL,
            uri=URI,
            transport=Transport.IIO_IP,
        )
        self.opened = False
        self.closed = False
        self.active_profile: int | None = None
        self.lo_hz = 915_000_000
        self.original = IioReceiverSettingsReadback(
            center_frequency_hz=float(self.lo_hz),
            sample_rate_hz=1_000_000.0,
            bandwidth_hz=1_000_000.0,
            channels=(0, 1),
            gain_modes=(GainMode.SLOW_ATTACK, GainMode.SLOW_ATTACK),
            gain_db=(11.0, 12.0),
        )
        self.geometry: tuple[int, int, tuple[int, ...], float] | None = None
        self.restored: IioReceiverSettingsReadback | None = None
        self.capture = _FakeCapture()
        self.open_request: bytes | None = None
        self.open_shape: tuple[int, int] | None = None

    def open(self) -> None:
        self.opened = True

    def close(self) -> None:
        self.closed = True

    def iio_context_attributes(self) -> dict[str, str]:
        return {
            "hw_serial": SERIAL,
            "iio,buffer-metadata": "3",
            **{name: "1" for name in PERSISTENT_HOP_CAPABILITIES},
        }

    def read_receiver_settings_readback(self) -> IioReceiverSettingsReadback:
        return self.original

    def read_active_rx_fastlock_profile(self) -> int | None:
        return self.active_profile

    def configure_source_locked_receiver_geometry(
        self,
        *,
        sample_rate_hz: int,
        rf_bandwidth_hz: int,
        channels: tuple[int, ...],
        manual_gain_db: float,
    ) -> IioReceiverSettingsReadback:
        self.geometry = (sample_rate_hz, rf_bandwidth_hz, channels, manual_gain_db)
        return dataclasses.replace(
            self.original,
            sample_rate_hz=float(sample_rate_hz),
            bandwidth_hz=float(rf_bandwidth_hz),
            channels=channels,
            gain_modes=(GainMode.MANUAL, GainMode.MANUAL),
            gain_db=(manual_gain_db, manual_gain_db),
        )

    def write_center_frequency_bufferless(self, center_frequency_hz: float) -> None:
        self.lo_hz = round(center_frequency_hz)
        self.active_profile = None

    def read_center_frequency(self) -> float:
        return float(self.lo_hz)

    def store_rx_fastlock_profile(self, profile: int) -> tuple[int, ...]:
        return tuple((profile + index) & 0xFF for index in range(16))

    def save_rx_fastlock_profile(self, profile: int) -> tuple[int, ...]:
        return self.store_rx_fastlock_profile(profile)

    def recall_rx_fastlock_profile(self, profile: int) -> None:
        self.active_profile = profile

    def begin_raw_sidecar_metadata_capture(
        self,
        sample_count: int,
        *,
        kernel_buffers: int,
        request: bytes,
        **_kwargs: Any,
    ) -> _FakeCapture:
        self.open_request = request
        self.open_shape = (sample_count, kernel_buffers)
        return self.capture

    def read_kernel_buffers_count(self) -> int:
        return 2

    def restore_receiver_settings_readback(
        self, snapshot: IioReceiverSettingsReadback
    ) -> IioReceiverSettingsReadback:
        self.restored = snapshot
        self.active_profile = None
        return snapshot


class _RecallMutatingFastlockRadio(_FakeRadio):
    """Model the AD9361 unlock workaround rewriting saved word 15 on recall."""

    def __init__(self) -> None:
        super().__init__()
        self.saved_profiles: dict[int, tuple[int, ...]] = {}

    def store_rx_fastlock_profile(self, profile: int) -> tuple[int, ...]:
        saved = tuple((profile + index) & 0xFF for index in range(16))
        self.saved_profiles[profile] = saved
        return saved

    def save_rx_fastlock_profile(self, profile: int) -> tuple[int, ...]:
        return self.saved_profiles[profile]

    def recall_rx_fastlock_profile(self, profile: int) -> None:
        super().recall_rx_fastlock_profile(profile)
        current = self.saved_profiles[profile]
        self.saved_profiles[profile] = (*current[:-1], current[-1] ^ 0x80)


class _QuantizedLoRadio(_FakeRadio):
    """Model an RFIC that reads two hertz low at the nominal write."""

    def __init__(self) -> None:
        super().__init__()
        self.requested_lo_hz = self.lo_hz
        self.stored_lo_hz: dict[int, int] = {}

    def write_center_frequency_bufferless(self, center_frequency_hz: float) -> None:
        self.requested_lo_hz = round(center_frequency_hz)
        self.lo_hz = self.requested_lo_hz - 2
        self.active_profile = None

    def store_rx_fastlock_profile(self, profile: int) -> tuple[int, ...]:
        self.stored_lo_hz[profile] = self.lo_hz
        return super().store_rx_fastlock_profile(profile)

    def save_rx_fastlock_profile(self, profile: int) -> tuple[int, ...]:
        return tuple((profile + index) & 0xFF for index in range(16))


def test_backend_prearm_compiles_profiles_and_composes_exact_open_request() -> None:
    radio = _FakeRadio()
    backend = IioPersistentHopBackend(
        URI,
        expected_serial=SERIAL,
        iio_module=SimpleNamespace(),
        radio_factory=lambda _uri, _serial: radio,  # type: ignore[arg-type]
    )
    backend.open()
    requested = dataclasses.replace(
        _plan(),
        profiles=tuple(
            dataclasses.replace(profile, profile_crc32=0)
            for profile in _plan().profiles
        ),
    )
    prepared = backend.prepare_plan(requested)
    request = prepared.request(session_id=SESSION).append_to_tandem_request(
        TandemSessionRequestV1(mode=TandemMode.HOLD),
        SAMPLES,
        retention_frames=3,
    )
    backend.start(request, samples_per_block=SAMPLES, kernel_buffers=2)

    assert radio.geometry == (2_500_000, 2_500_000, (0, 1), 40.0)
    assert radio.open_shape == (SAMPLES, 2)
    assert radio.open_request == request
    assert len(request) == 104 + 288
    decoded = PersistentHopRequestV1.unpack(request[-288:])
    assert decoded.profiles == prepared.profiles
    assert tuple(profile.profile_crc32 for profile in prepared.profiles) == tuple(
        zlib.crc32(bytes((slot + index) & 0xFF for index in range(16))) & 0xFFFFFFFF
        for slot in range(8)
    )


def test_backend_crc_attests_stable_post_recall_fastlock_words() -> None:
    radio = _RecallMutatingFastlockRadio()
    backend = IioPersistentHopBackend(
        URI,
        expected_serial=SERIAL,
        iio_module=SimpleNamespace(),
        radio_factory=lambda _uri, _serial: radio,  # type: ignore[arg-type]
    )
    backend.open()
    requested = dataclasses.replace(
        _plan(),
        profiles=tuple(
            dataclasses.replace(profile, profile_crc32=0)
            for profile in _plan().profiles
        ),
    )

    prepared = backend.prepare_plan(requested)

    stale_pre_recall_crcs = tuple(
        zlib.crc32(bytes((slot + index) & 0xFF for index in range(16))) & 0xFFFFFFFF
        for slot in range(8)
    )
    final_crcs = tuple(
        zlib.crc32(bytes(radio.saved_profiles[slot])) & 0xFFFFFFFF
        for slot in range(8)
    )
    assert tuple(profile.profile_crc32 for profile in prepared.profiles) == final_crcs
    assert final_crcs != stale_pre_recall_crcs


def test_backend_compensates_bounded_lo_quantization_before_fastlock_store() -> None:
    radio = _QuantizedLoRadio()
    backend = IioPersistentHopBackend(
        URI,
        expected_serial=SERIAL,
        iio_module=SimpleNamespace(),
        radio_factory=lambda _uri, _serial: radio,  # type: ignore[arg-type]
    )
    backend.open()
    requested = dataclasses.replace(
        _plan(),
        profiles=tuple(
            dataclasses.replace(profile, profile_crc32=0)
            for profile in _plan().profiles
        ),
    )

    prepared = backend.prepare_plan(requested)

    assert radio.stored_lo_hz == {
        profile.fastlock_profile_index: profile.lo_hz for profile in prepared.profiles
    }
    assert radio.lo_hz == prepared.profiles[0].lo_hz
    assert radio.requested_lo_hz == prepared.profiles[0].lo_hz + 2


def test_backend_extracts_hops_then_reads_cancelled_hopt_before_close() -> None:
    radio = _FakeRadio()
    backend = IioPersistentHopBackend(
        URI,
        expected_serial=SERIAL,
        iio_module=SimpleNamespace(),
        radio_factory=lambda _uri, _serial: radio,  # type: ignore[arg-type]
    )
    client = PersistentHopClient(
        URI,
        expected_serial=SERIAL,
        backend_factory=lambda _uri: backend,
    )
    session = client.start(
        _plan(),
        session_id=SESSION,
        tandem_request=TandemSessionRequestV1(mode=TandemMode.HOLD),
    )

    assert session.start_clock_bracket == PersistentHopStartClockBracketV1(
        before_realtime_ns=1_000_000_000,
        before_monotonic_ns=100_000_000,
        after_realtime_ns=1_002_000_000,
        after_monotonic_ns=102_000_000,
    )

    blocks = session.blocks()
    block = next(blocks)
    assert block.evidence.block_first_counter == 100
    assert block.samples.shape == (2, 24)
    receipt = session.cancel()
    assert radio.capture.cancelled
    assert radio.capture.closed and radio.closed
    assert radio.restored == radio.original
    assert receipt.host_lifecycle is not None
    assert (
        receipt.host_lifecycle.original_settings
        == receipt.host_lifecycle.restored_settings
    )
    assert receipt.host_lifecycle.receive_buffer_closed
    assert receipt.host_lifecycle.fastlock_inactive
    assert session.receipt.capture_outcome == "cancelled"
    assert session.receipt.incomplete_visit_sample_count == 24
    assert session.receipt.valid_sample_count == 0
    assert session.receipt.radio_id == SERIAL
    assert session.receipt.stream_generation == 99
    assert session.receipt.kernel_buffers_requested == 2
    assert session.receipt.kernel_buffers_readback == 2


class _FakeRxAdc:
    kernel_buffers_count = 2

    def set_kernel_buffers_count(self, count: int) -> int:
        self.kernel_buffers_count = count
        return 0


class _FakeMetadataBuffer:
    def __init__(self, metadata: bytes, iq: bytes, status: bytes) -> None:
        self.metadata = metadata
        self.iq = iq
        self.status = status
        self.refilled = False
        self.closed = False
        self.in_band_cancelled = False
        self.generic_cancelled = False

    def refill(self) -> None:
        self.refilled = True

    def read(self) -> bytes:
        return self.iq

    def metadata_status_raw(self, capacity: int) -> bytes:
        assert capacity == len(self.status)
        return self.status

    def cancel_metadata_session(self) -> None:
        self.in_band_cancelled = True

    def cancel(self) -> None:
        self.generic_cancelled = True

    def close(self) -> None:
        self.closed = True


def test_raw_binding_open_sidecar_status_cancel_and_legacy_isolation(
    monkeypatch: Any,
) -> None:
    base_bytes = 64
    metadata = bytearray(base_bytes)
    struct.pack_into("<H", metadata, 6, base_bytes)
    metadata += _sidecar()
    buffer = _FakeMetadataBuffer(
        bytes(metadata),
        bytes(SAMPLES * 8),
        _status(PersistentHopSessionState.RUNNING),
    )
    calls: list[tuple[Any, ...]] = []

    def factory(*args: Any) -> _FakeMetadataBuffer:
        calls.append(args)
        return buffer

    sdr = SimpleNamespace(
        _rxadc=_FakeRxAdc(),
        _rxbuf=None,
        rx_enabled_channels=[0, 1],
        rx_buffer_size=0,
    )
    sdr.rx_destroy_buffer = lambda: setattr(sdr, "_rxbuf", None)
    sdr.rx = lambda: np.zeros((2, SAMPLES), dtype=np.complex64)
    parsed_base = SimpleNamespace(
        samples_per_channel=SAMPLES,
        iq_payload_bytes=SAMPLES * 8,
        enabled_scan_mask=0x0F,
        channel_count=2,
        flags=MetadataFlags.HARDWARE_SAMPLE_COUNTER_VALID,
    )
    monkeypatch.setattr(
        "pluto_plus.hardware.iio_metadata.RadioMetadataV6.unpack",
        lambda raw: SimpleNamespace(base=parsed_base),
    )
    monotonic_values = iter((100_000_000, 102_000_000))
    realtime_values = iter((1_000_000_000, 1_002_000_000))
    monkeypatch.setattr(
        "pluto_plus.hardware.iio_metadata.time.monotonic_ns",
        lambda: next(monotonic_values),
    )
    monkeypatch.setattr(
        "pluto_plus.hardware.iio_metadata.time.time_ns",
        lambda: next(realtime_values),
    )
    request = bytes(range(256)) + bytes(range(136))
    session = IioRawSidecarCaptureSession(
        sdr,
        factory,
        request=request,
        samples_per_channel=SAMPLES,
        kernel_buffers=2,
        metadata_status_reader=lambda item, capacity: _read_metadata_status(
            SimpleNamespace(), item, capacity
        ),
        metadata_canceller=lambda item: _cancel_metadata_session(
            SimpleNamespace(), item
        ),
        status_capacity=160,
    )
    session.open()
    assert session.open_clock_bracket == IioBufferOpenClockBracket(
        before_realtime_ns=1_000_000_000,
        before_monotonic_ns=100_000_000,
        after_realtime_ns=1_002_000_000,
        after_monotonic_ns=102_000_000,
    )
    block = session.read_block()
    assert calls == [(sdr._rxadc, SAMPLES, request, 64 * 1024)]
    assert block.sidecar == _sidecar()
    assert block.iq_payload == bytes(SAMPLES * 8)
    assert session.read_status() == _status(PersistentHopSessionState.RUNNING)
    session.request_cancel()
    assert buffer.in_band_cancelled
    assert not buffer.generic_cancelled
    session.close()
    assert buffer.closed


def test_raw_sidecar_read_failure_preserves_buffer_for_in_band_cleanup() -> None:
    buffer = _FakeMetadataBuffer(b"", b"", _status(PersistentHopSessionState.RUNNING))

    def fail_refill() -> None:
        raise OSError("injected refill failure")

    buffer.refill = fail_refill
    sdr = SimpleNamespace(
        _rxadc=_FakeRxAdc(),
        _rxbuf=None,
        rx_enabled_channels=[0, 1],
        rx_buffer_size=0,
    )
    sdr.rx_destroy_buffer = lambda: setattr(sdr, "_rxbuf", None)
    sdr.rx = lambda: np.zeros((2, SAMPLES), dtype=np.complex64)
    session = IioRawSidecarCaptureSession(
        sdr,
        lambda *_args: buffer,
        request=bytes(range(256)) + bytes(range(136)),
        samples_per_channel=SAMPLES,
        kernel_buffers=2,
        metadata_status_reader=lambda item, capacity: _read_metadata_status(
            SimpleNamespace(), item, capacity
        ),
        metadata_canceller=lambda item: _cancel_metadata_session(
            SimpleNamespace(), item
        ),
        status_capacity=160,
    )
    session.open()

    with pytest.raises(OSError, match="injected refill failure"):
        session.read_block()

    assert session.is_open
    assert not buffer.closed
    session.request_cancel()
    assert buffer.in_band_cancelled
    session.close()
    assert buffer.closed
