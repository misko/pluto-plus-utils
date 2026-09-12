from __future__ import annotations

import dataclasses
import struct
import zlib
from types import SimpleNamespace
from typing import Any

import numpy as np
import pytest

from pluto_plus.direct_radio.usb import MetadataFlags, TimeAnchorFlags, TimeAnchorV1
from pluto_plus.errors import RadioConfigurationError
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
from pluto_plus.hardware.sample_clock import HostRealtimeMapping, HostTimeAnchorMeasurement
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
        self.refined_clock_bracket = IioBufferOpenClockBracket(
            before_realtime_ns=1_000_900_000,
            before_monotonic_ns=100_900_000,
            after_realtime_ns=1_001_100_000,
            after_monotonic_ns=101_100_000,
        )

    @property
    def is_open(self) -> bool:
        return not self.closed

    def read_block(self) -> IioRawSidecarBlock:
        return self._blocks.pop(0)

    def first_sample_clock_bracket(
        self, first_sample_counter: int, *, sample_rate_hz: int
    ) -> IioBufferOpenClockBracket:
        assert first_sample_counter == 100
        assert sample_rate_hz == 2_500_000
        return self.refined_clock_bracket

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


@pytest.mark.parametrize("matching", [True, False])
def test_backend_attests_newly_selected_radio_without_historical_denylist(matching):
    selected = "104000bac4950008230026001b440a003a"
    radio = _FakeRadio()
    radio.identity = radio.identity.model_copy(update={"serial": selected})
    backend = IioPersistentHopBackend(
        URI, expected_serial=selected if matching else SERIAL,
        iio_module=SimpleNamespace(), radio_factory=lambda *_: radio,
    )
    if matching:
        backend.open()
        backend.close()
    else:
        with pytest.raises(RuntimeError, match="identity does not match"):
            backend.open()
    assert radio.closed


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


@pytest.mark.parametrize("receiver_id", [None, 0, 1])
def test_backend_prearm_compiles_profiles_and_composes_exact_open_request(receiver_id) -> None:
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
            dataclasses.replace(profile, profile_crc32=0) for profile in _plan().profiles
        ),
    )
    if receiver_id is not None:
        from pluto_plus.persistent_hop import SingleRxPersistentHopPlanV2

        values = {
            field.name: getattr(requested, field.name) for field in dataclasses.fields(requested)
        }
        values.update(
            sample_rate_hz=10_000_000, rf_bandwidth_hz=10_000_000, receiver_id=receiver_id
        )
        requested = SingleRxPersistentHopPlanV2(**values)
    prepared = backend.prepare_plan(requested)
    request = prepared.request(session_id=SESSION).append_to_tandem_request(
        TandemSessionRequestV1(mode=TandemMode.HOLD),
        SAMPLES,
        retention_frames=3,
    )
    backend.start(request, samples_per_block=SAMPLES, kernel_buffers=2)

    assert radio.geometry == (
        requested.sample_rate_hz,
        requested.sample_rate_hz,
        requested.receiver_ids,
        40.0,
    )
    assert radio.open_shape == (SAMPLES, 2)
    assert radio.open_request == request
    assert len(request) == 104 + 288
    decoded = PersistentHopRequestV1.unpack(request[-288:])
    assert decoded.profiles == prepared.profiles
    assert tuple(profile.profile_crc32 for profile in prepared.profiles) == tuple(
        zlib.crc32(bytes((slot + index) & 0xFF for index in range(16))) & 0xFFFFFFFF
        for slot in range(8)
    )


@pytest.mark.parametrize("mode", [GainMode.SLOW_ATTACK, GainMode.FAST_ATTACK, GainMode.MANUAL])
def test_backend_restoration_distinguishes_agc_observations_from_manual_settings(mode) -> None:
    class GainReadbackRadio(_FakeRadio):
        def restore_receiver_settings_readback(self, snapshot):
            super().restore_receiver_settings_readback(snapshot)
            return dataclasses.replace(snapshot, gain_db=(9.0, 13.0))

    radio = GainReadbackRadio()
    radio.original = dataclasses.replace(radio.original, gain_modes=(mode, mode))
    backend = IioPersistentHopBackend(
        URI, expected_serial=SERIAL, iio_module=SimpleNamespace(),
        radio_factory=lambda _uri, _serial: radio,
    )
    backend.open()
    backend.prepare_plan(_plan())
    if mode is GainMode.MANUAL:
        with pytest.raises(RadioConfigurationError, match="observed=.*gain_db=\\(9.0, 13.0\\)"):
            backend.close()
    else:
        receipt = backend.close()
        assert receipt is not None
        assert receipt.original_settings.gain_db == (11.0, 12.0)
        assert receipt.restored_settings.gain_db == (9.0, 13.0)
        assert receipt.restored_settings.gain_modes == (mode.value, mode.value)
        assert receipt.receive_buffer_closed and receipt.fastlock_inactive
    assert radio.closed
    assert backend.close() is None


@pytest.mark.parametrize("changed", [
    {"center_frequency_hz": 916_000_000.0},
    {"sample_rate_hz": 2_000_000.0},
    {"bandwidth_hz": 2_000_000.0},
    {"channels": (1,), "gain_modes": (GainMode.SLOW_ATTACK,), "gain_db": (12.0,)},
    {"gain_modes": (GainMode.FAST_ATTACK, GainMode.SLOW_ATTACK)},
    {"active_profile": 3},
])
def test_backend_rejects_changed_restoration_configuration_and_closes_radio(changed) -> None:
    class WrongReadbackRadio(_FakeRadio):
        def restore_receiver_settings_readback(self, snapshot):
            super().restore_receiver_settings_readback(snapshot)
            self.active_profile = changed.get("active_profile")
            return dataclasses.replace(
                snapshot,
                **{key: value for key, value in changed.items() if key != "active_profile"},
            )

    radio = WrongReadbackRadio()
    backend = IioPersistentHopBackend(
        URI, expected_serial=SERIAL, iio_module=SimpleNamespace(),
        radio_factory=lambda _uri, _serial: radio,
    )
    backend.open()
    backend.prepare_plan(_plan())
    with pytest.raises(RadioConfigurationError, match="settings restoration was not exact"):
        backend.close()
    assert radio.closed
    assert backend.close() is None


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
            dataclasses.replace(profile, profile_crc32=0) for profile in _plan().profiles
        ),
    )

    prepared = backend.prepare_plan(requested)

    stale_pre_recall_crcs = tuple(
        zlib.crc32(bytes((slot + index) & 0xFF for index in range(16))) & 0xFFFFFFFF
        for slot in range(8)
    )
    final_crcs = tuple(
        zlib.crc32(bytes(radio.saved_profiles[slot])) & 0xFFFFFFFF for slot in range(8)
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
            dataclasses.replace(profile, profile_crc32=0) for profile in _plan().profiles
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
    assert session.start_clock_bracket == PersistentHopStartClockBracketV1(
        before_realtime_ns=1_000_900_000,
        before_monotonic_ns=100_900_000,
        after_realtime_ns=1_001_100_000,
        after_monotonic_ns=101_100_000,
    )
    receipt = session.cancel()
    assert radio.capture.cancelled
    assert radio.capture.closed and radio.closed
    assert radio.restored == radio.original
    assert receipt.host_lifecycle is not None
    assert receipt.host_lifecycle.original_settings == receipt.host_lifecycle.restored_settings
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


@pytest.mark.parametrize("extended", [False, True])
@pytest.mark.parametrize("receiver_ids", [(0, 1), (0,), (1,)])
def test_raw_binding_open_sidecar_status_cancel_and_legacy_isolation(
    monkeypatch: Any,
    extended: bool,
    receiver_ids: tuple[int, ...],
) -> None:
    base_bytes = 64
    metadata = bytearray(base_bytes)
    struct.pack_into("<H", metadata, 6, base_bytes)
    metadata += _sidecar()
    buffer = _FakeMetadataBuffer(
        (b"extension" if extended else b"") + bytes(metadata),
        bytes(SAMPLES * 4 * len(receiver_ids)),
        _status(PersistentHopSessionState.RUNNING),
    )
    calls: list[tuple[Any, ...]] = []
    drains: list[int] = []

    def drain(capacity: int) -> bytes:
        drains.append(capacity)
        return b"terminal metadata"

    buffer.drain_metadata = drain

    def factory(*args: Any) -> _FakeMetadataBuffer:
        calls.append(args)
        return buffer

    sdr = SimpleNamespace(
        _rxadc=_FakeRxAdc(),
        _rxbuf=None,
        rx_enabled_channels=list(receiver_ids),
        rx_buffer_size=0,
    )
    sdr.rx_destroy_buffer = lambda: setattr(sdr, "_rxbuf", None)
    sdr.rx = lambda: np.zeros(
        (len(receiver_ids), SAMPLES) if len(receiver_ids) == 2 else (SAMPLES,),
        dtype=np.complex64,
    )
    parsed_base = SimpleNamespace(
        samples_per_channel=SAMPLES,
        iq_payload_bytes=SAMPLES * 4 * len(receiver_ids),
        enabled_scan_mask=sum(3 << (2 * rx) for rx in receiver_ids),
        channel_count=len(receiver_ids),
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
        receiver_ids=receiver_ids,
        request=request,
        samples_per_channel=SAMPLES,
        kernel_buffers=2,
        metadata_status_reader=lambda item, capacity: _read_metadata_status(
            SimpleNamespace(), item, capacity
        ),
        metadata_canceller=lambda item: _cancel_metadata_session(SimpleNamespace(), item),
        status_capacity=160,
        metadata_unwrapper=(lambda raw: raw[len(b"extension") :]) if extended else None,
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
    assert block.iq_payload == bytes(SAMPLES * 4 * len(receiver_ids))
    assert block.extension_metadata == (b"extension" + bytes(metadata) if extended else None)
    buffer.refilled = False
    assert session.drain_metadata() == b"terminal metadata"
    assert drains == [65536]
    assert not buffer.refilled and buffer.iq == block.iq_payload
    assert session.read_status() == _status(PersistentHopSessionState.RUNNING)
    parsed_base.enabled_scan_mask ^= 0x0F
    with pytest.raises(RuntimeError, match="geometry disagrees"):
        session.read_block()
    session.request_cancel()
    assert buffer.in_band_cancelled
    assert not buffer.generic_cancelled
    session.close()
    assert buffer.closed


@pytest.mark.parametrize("mode", ["wrapped", "unsupported", "exception", "invalid"])
def test_backend_negotiates_extension_once_before_open_and_falls_back_without_reopen(mode: str):
    radio = _FakeRadio()
    negotiations: list[tuple[bytes, bool]] = []
    errors: list[str] = []

    def negotiate(request: bytes, attributes: dict[str, str], *, drain_supported: bool):
        assert attributes["hw_serial"] == SERIAL
        negotiations.append((request, drain_supported))
        if mode == "exception":
            raise ValueError("injected negotiation failure")
        if mode == "invalid":
            return None
        return b"wrapped" + request if mode == "wrapped" else request

    extension = SimpleNamespace(negotiate=negotiate, unwrap=lambda raw: raw, fail=errors.append)
    backend = IioPersistentHopBackend(
        URI,
        expected_serial=SERIAL,
        iio_module=SimpleNamespace(MetadataBuffer=SimpleNamespace(drain_metadata=lambda: None)),
        radio_factory=lambda _uri, _serial: radio,
        metadata_extension=extension,
    )
    backend.open()
    prepared = backend.prepare_plan(_plan())
    request = prepared.request(session_id=SESSION).append_to_tandem_request(
        TandemSessionRequestV1(mode=TandemMode.HOLD), SAMPLES, retention_frames=3
    )
    backend.start(request, samples_per_block=SAMPLES, kernel_buffers=2)
    assert negotiations == [(request, True)]
    assert radio.open_request == (b"wrapped" + request if mode == "wrapped" else request)
    assert bool(errors) == (mode in {"exception", "invalid"})
    assert backend.metadata_extension is extension
    assert bool(backend.metadata_extension_error) == bool(errors)
    backend.close()


def test_raw_binding_projects_first_sample_from_fpga_counter_anchor() -> None:
    sdr = SimpleNamespace(
        _rxadc=_FakeRxAdc(),
        _rxbuf=None,
        rx_enabled_channels=[0, 1],
        rx_buffer_size=0,
    )
    session = IioRawSidecarCaptureSession(
        sdr,
        object,
        request=b"request",
        samples_per_channel=SAMPLES,
        kernel_buffers=2,
        metadata_status_reader=lambda _item, _capacity: b"",
        metadata_canceller=lambda _item: None,
        status_capacity=160,
    )
    session._open_clock_bracket = IioBufferOpenClockBracket(  # noqa: SLF001
        before_realtime_ns=900_000_000,
        before_monotonic_ns=1,
        after_realtime_ns=1_100_000_000,
        after_monotonic_ns=200_000_000,
    )
    session._start_time_anchors = [  # noqa: SLF001
        HostTimeAnchorMeasurement(
            anchor=TimeAnchorV1(
                flags=(
                    TimeAnchorFlags.COUNTER_INTERVAL_VALID
                    | TimeAnchorFlags.MONOTONIC_INTERVAL_VALID
                    | TimeAnchorFlags.COUNTER_LOW32
                ),
                request_id=1,
                radio_monotonic_before_ns=0,
                sample_counter_before=251_000,
                sample_counter_after=251_000,
                radio_monotonic_after_ns=0,
            ),
            host_monotonic_before_ns=200_000_000,
            host_monotonic_after_ns=202_000_000,
            transport="iio",
        )
    ]
    session._start_realtime_mapping = HostRealtimeMapping(  # noqa: SLF001
        monotonic_midpoint_ns=201_000_000,
        realtime_ns_at_midpoint=1_101_000_000,
        uncertainty_ns=100,
    )

    assert session.first_sample_clock_bracket(
        1_000, sample_rate_hz=2_500_000
    ) == IioBufferOpenClockBracket(
        before_realtime_ns=999_989_900,
        before_monotonic_ns=99_989_900,
        after_realtime_ns=1_002_010_100,
        after_monotonic_ns=102_010_100,
    )


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
        metadata_canceller=lambda item: _cancel_metadata_session(SimpleNamespace(), item),
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
