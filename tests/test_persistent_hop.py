from __future__ import annotations

import dataclasses
import struct
from collections.abc import Iterator, Mapping

import numpy as np
import pytest

from pluto_plus.persistent_hop import (
    PERSISTENT_HOP_CAPABILITIES,
    PERSISTENT_HOP_EVENT_BYTES,
    PERSISTENT_HOP_EXCLUDED_SERIAL,
    PERSISTENT_HOP_NONE_PROFILE,
    PERSISTENT_HOP_REQUEST_BYTES,
    PERSISTENT_HOP_STATUS_BYTES,
    PersistentHopBackend,
    PersistentHopCancellationReceiptV1,
    PersistentHopClient,
    PersistentHopClientError,
    PersistentHopEventFlag,
    PersistentHopEventKind,
    PersistentHopEventV1,
    PersistentHopEvidenceV1,
    PersistentHopPlanV1,
    PersistentHopProfileV1,
    PersistentHopProtocolError,
    PersistentHopRequestV1,
    PersistentHopSession,
    PersistentHopSessionState,
    PersistentHopStatusFlag,
    PersistentHopStatusV1,
    PersistentHopTerminalReason,
    PersistentHopWireBlock,
    require_physical_lan_uri,
)
from pluto_plus.tandem import TandemMode, TandemSessionRequestV1

SERIAL = "1040007c4a94000211000b009186843ef2"
URI = "ip:192.168.1.18"
SESSION_ID = 0x0102030405060708
IF_OFFSET_HZ = 1_000
GUARD_SAMPLES = 10


def _profiles() -> tuple[PersistentHopProfileV1, ...]:
    return tuple(
        PersistentHopProfileV1(
            target_index=index,
            fastlock_profile_index=index,
            center_hz=1_000_000_000 + index * 1_000_000 + IF_OFFSET_HZ,
            lo_hz=1_000_000_000 + index * 1_000_000,
            profile_crc32=index + 1,
        )
        for index in range(8)
    )


def _plan() -> PersistentHopPlanV1:
    return PersistentHopPlanV1(
        nominal_duration_seconds=300,
        valid_visit_ms=120,
        sample_rate_hz=2_500_000,
        rf_bandwidth_hz=2_500_000,
        transition_guard_samples=GUARD_SAMPLES,
        samples_per_block=1_024,
        kernel_buffers=2,
        minimum_valid_duty_ppm=900_000,
        manual_gain_db=40.0,
        profiles=_profiles(),
    )


def _event(
    *,
    sequence: int = 0,
    dwell: int = 0,
    invalid_start: int = 1_000,
) -> PersistentHopEventV1:
    target = dwell % 8
    profile = _profiles()[target]
    transition_after = invalid_start + 1
    return PersistentHopEventV1(
        event_sequence=sequence,
        dwell_index=dwell,
        transition_before_counter=invalid_start,
        transition_after_counter=transition_after,
        invalid_start_counter=invalid_start,
        invalid_end_counter_exclusive=transition_after + GUARD_SAMPLES,
        from_profile_index=PERSISTENT_HOP_NONE_PROFILE if dwell == 0 else (target - 1) % 8,
        to_profile_index=target,
        kind=PersistentHopEventKind.STARTUP if dwell == 0 else PersistentHopEventKind.RETUNE,
        flags=(PersistentHopEventFlag.COUNTER_BOUNDS_ATTESTED | PersistentHopEventFlag.LO_ATTESTED),
        fastlock_slot=profile.fastlock_profile_index,
        actual_lo_frequency_hz=profile.lo_hz,
        actual_if_offset_hz=IF_OFFSET_HZ,
        device_event_id=sequence + 1,
    )


def _active_status() -> PersistentHopStatusV1:
    return PersistentHopStatusV1(
        state=PersistentHopSessionState.ARMED,
        reason=PersistentHopTerminalReason.NONE,
        error_code=0,
        flags=PersistentHopStatusFlag.RESTORE_REQUIRED,
        session_id=SESSION_ID,
        planned_dwells=2_500,
        visits_started=0,
        events_emitted=0,
        next_event_sequence=0,
        last_block_sequence=0,
        last_block_end_counter=0,
        first_counter=1_000,
        final_counter=0,
        restore_before_counter=0,
        restore_after_counter=0,
        restored_lo_frequency_hz=0,
        restore_error_code=0,
        active_profile_index=PERSISTENT_HOP_NONE_PROFILE,
        restored_profile_index=PERSISTENT_HOP_NONE_PROFILE,
        startup_invalid_start_counter=0,
        startup_invalid_end_counter_exclusive=0,
        device_dropped_events=0,
    )


def _cancelled_status() -> PersistentHopStatusV1:
    return PersistentHopStatusV1(
        state=PersistentHopSessionState.CANCELLED,
        reason=PersistentHopTerminalReason.CLIENT_CLOSE,
        error_code=0,
        flags=(
            PersistentHopStatusFlag.TERMINAL
            | PersistentHopStatusFlag.RESTORE_ATTEMPTED
            | PersistentHopStatusFlag.RESTORE_SUCCEEDED
            | PersistentHopStatusFlag.RESTORE_REQUIRED
        ),
        session_id=SESSION_ID,
        planned_dwells=2_500,
        visits_started=1,
        events_emitted=1,
        next_event_sequence=1,
        last_block_sequence=0,
        last_block_end_counter=2_024,
        first_counter=1_000,
        final_counter=2_024,
        restore_before_counter=2_024,
        restore_after_counter=2_025,
        restored_lo_frequency_hz=915_000_000,
        restore_error_code=0,
        active_profile_index=PERSISTENT_HOP_NONE_PROFILE,
        restored_profile_index=PERSISTENT_HOP_NONE_PROFILE,
        startup_invalid_start_counter=1_000,
        startup_invalid_end_counter_exclusive=1_011,
        device_dropped_events=0,
    )


def _wire_block(
    *,
    buffer_sequence: int = 0,
    first_counter: int = 1_000,
    end_counter: int = 2_024,
    flags: PersistentHopStatusFlag = PersistentHopStatusFlag.RESTORE_REQUIRED,
    events: tuple[PersistentHopEventV1, ...] = (_event(),),
) -> PersistentHopWireBlock:
    overflow = bool(flags & PersistentHopStatusFlag.DEVICE_EVENT_OVERFLOW)
    if overflow:
        flags |= (
            PersistentHopStatusFlag.TERMINAL
            | PersistentHopStatusFlag.RESTORE_ATTEMPTED
            | PersistentHopStatusFlag.RESTORE_SUCCEEDED
        )
    evidence = PersistentHopEvidenceV1(
        flags=flags,
        session_id=SESSION_ID,
        buffer_sequence=buffer_sequence,
        block_first_counter=first_counter,
        block_end_counter_exclusive=end_counter,
        state=PersistentHopSessionState.FAILED if overflow else PersistentHopSessionState.RUNNING,
        reason=(
            PersistentHopTerminalReason.EVENT_OVERFLOW
            if overflow
            else PersistentHopTerminalReason.NONE
        ),
        error_code=-75 if overflow else 0,
        events=events,
    )
    payload = np.zeros((end_counter - first_counter, 4), dtype="<i2").tobytes()
    return PersistentHopWireBlock(evidence=evidence.pack(), iq_payload=payload)


class _Backend(PersistentHopBackend):
    def __init__(
        self,
        uri: str,
        *,
        serial: str = SERIAL,
        capabilities: Mapping[str, str] | None = None,
        blocks: tuple[PersistentHopWireBlock, ...] = (),
    ) -> None:
        self._uri = uri
        self.serial = serial
        self.capabilities = dict(
            capabilities
            if capabilities is not None
            else {
                "hw_serial": serial,
                "iio,buffer-metadata": "3",
                **{name: "1" for name in PERSISTENT_HOP_CAPABILITIES},
            }
        )
        self.wire_blocks = blocks
        self.statuses = [_active_status(), _cancelled_status()]
        self.started_request: bytes | None = None
        self.started_shape: tuple[int, int] | None = None
        self.opened = False
        self.cancelled = False
        self.closed = False

    @property
    def uri(self) -> str:
        return self._uri

    def open(self) -> None:
        self.opened = True

    def context_attributes(self) -> Mapping[str, str]:
        return self.capabilities

    def start(
        self,
        request: bytes,
        *,
        samples_per_block: int,
        kernel_buffers: int,
    ) -> None:
        self.started_request = request
        self.started_shape = (samples_per_block, kernel_buffers)

    def blocks(self) -> Iterator[PersistentHopWireBlock]:
        yield from self.wire_blocks

    def cancel(self) -> None:
        self.cancelled = True

    def read_status(self) -> bytes:
        return self.statuses.pop(0).pack()

    def close(self) -> None:
        self.closed = True


class _PreparingBackend(_Backend):
    def prepare_plan(self, plan: PersistentHopPlanV1) -> PersistentHopPlanV1:
        return dataclasses.replace(
            plan,
            profiles=tuple(
                dataclasses.replace(profile, profile_crc32=index + 101)
                for index, profile in enumerate(plan.profiles)
            ),
        )


def _client(backend: _Backend, *, expected_serial: str = SERIAL) -> PersistentHopClient:
    return PersistentHopClient(
        URI,
        expected_serial=expected_serial,
        backend_factory=lambda _uri: backend,
    )


def test_hopr_layout_round_trips_exact_final_wire() -> None:
    request = _plan().request(session_id=SESSION_ID)
    payload = request.pack()

    assert len(payload) == PERSISTENT_HOP_REQUEST_BYTES
    assert struct.unpack_from("<IHH", payload, 0) == (0x52504F48, 1, 288)
    assert struct.unpack_from("<II", payload, 8) == (0x1F, 0x03)
    assert struct.unpack_from("<H", payload, 76)[0] == PERSISTENT_HOP_EVENT_BYTES
    assert payload[80:88] == bytes(8)
    assert struct.unpack_from("<Q", payload, 88)[0] == 750_000_000
    assert request.dwell_count == 2_500
    assert PersistentHopRequestV1.unpack(payload) == request

    combined = request.append_to_tandem_request(
        TandemSessionRequestV1(mode=TandemMode.HOLD),
        1_024,
        retention_frames=3,
    )
    assert len(combined) == 104 + 288
    assert combined[-288:] == payload


def test_hopr_rejects_duplicate_profiles_and_reserved_bytes() -> None:
    request = _plan().request(session_id=SESSION_ID)
    duplicate = dataclasses.replace(
        request,
        profiles=(
            request.profiles[0],
            dataclasses.replace(request.profiles[1], fastlock_profile_index=0),
            *request.profiles[2:],
        ),
    )
    with pytest.raises(PersistentHopProtocolError, match="unique"):
        duplicate.pack()

    corrupt = bytearray(request.pack())
    corrupt[80] = 1
    with pytest.raises(PersistentHopProtocolError, match="reserved"):
        PersistentHopRequestV1.unpack(corrupt)


def test_hops_event_and_status_codecs_reject_malformed_order() -> None:
    first = _event()
    second = _event(sequence=1, dwell=1, invalid_start=301_011)
    evidence = PersistentHopEvidenceV1(
        flags=PersistentHopStatusFlag.RESTORE_REQUIRED,
        session_id=SESSION_ID,
        buffer_sequence=0,
        block_first_counter=1_000,
        block_end_counter_exclusive=302_000,
        state=PersistentHopSessionState.RUNNING,
        reason=PersistentHopTerminalReason.NONE,
        error_code=0,
        events=(first, second),
    )
    payload = evidence.pack()
    assert len(payload) == 64 + 2 * 80
    assert struct.unpack_from("<IHH", payload, 0) == (0x53504F48, 1, 64)
    assert struct.unpack_from("<I", payload, 8)[0] == len(payload)
    assert struct.unpack_from("<I", payload, 12)[0] == 0x1F
    assert struct.unpack_from("<HH", payload, 20) == (2, 8)
    assert struct.unpack_from("<Q", payload, 64 + 56)[0] == first.actual_lo_frequency_hz
    assert struct.unpack_from("<q", payload, 64 + 64)[0] == first.actual_if_offset_hz
    assert struct.unpack_from("<Q", payload, 64 + 72)[0] == first.device_event_id
    assert PersistentHopEvidenceV1.unpack(payload) == evidence
    status_payload = _cancelled_status().pack()
    assert PersistentHopStatusV1.unpack(status_payload) == _cancelled_status()
    assert len(status_payload) == PERSISTENT_HOP_STATUS_BYTES
    assert struct.unpack_from("<IHHI", status_payload, 0) == (0x54504F48, 1, 160, 0x1F)
    assert struct.unpack_from("<Q", status_payload, 24)[0] == SESSION_ID
    assert struct.unpack_from("<Q", status_payload, 112)[0] == 915_000_000
    assert status_payload[124:126] == bytes((PERSISTENT_HOP_NONE_PROFILE,) * 2)
    assert status_payload[126:128] == bytes(2)
    assert status_payload[152:160] == bytes(8)

    delayed_restore = dataclasses.replace(
        _cancelled_status(),
        restore_before_counter=2_100,
        restore_after_counter=2_101,
    )
    assert PersistentHopStatusV1.unpack(delayed_restore.pack()) == delayed_restore
    with pytest.raises(PersistentHopProtocolError, match="before the terminal counter"):
        dataclasses.replace(
            _cancelled_status(),
            restore_before_counter=2_023,
        ).pack()

    out_of_order = bytearray(payload)
    struct.pack_into("<Q", out_of_order, 64 + 80, 3)
    with pytest.raises(PersistentHopProtocolError, match="out of order"):
        PersistentHopEvidenceV1.unpack(out_of_order)

    zero_device_event_id = bytearray(first.pack())
    struct.pack_into("<Q", zero_device_event_id, 72, 0)
    with pytest.raises(PersistentHopProtocolError, match="device identity"):
        PersistentHopEventV1.unpack(zero_device_event_id)


def test_hops_event_delivery_is_not_synthesized_from_attached_block_bounds() -> None:
    evidence = PersistentHopEvidenceV1(
        flags=PersistentHopStatusFlag.RESTORE_REQUIRED,
        session_id=SESSION_ID,
        buffer_sequence=4,
        block_first_counter=500_000,
        block_end_counter_exclusive=501_024,
        state=PersistentHopSessionState.RUNNING,
        reason=PersistentHopTerminalReason.NONE,
        error_code=0,
        events=(_event(invalid_start=1_000),),
    )

    assert PersistentHopEvidenceV1.unpack(evidence.pack()) == evidence


def test_hops_event_permits_conservative_scheduler_lead_time() -> None:
    event = dataclasses.replace(
        _event(),
        invalid_start_counter=990,
    )

    assert PersistentHopEventV1.unpack(event.pack()) == event


@pytest.mark.parametrize(
    "uri",
    (
        "usb:3.11.5",
        "ip:192.168.2.18",
        "ip:radio.local",
        "ip:192.168.1.018",
        "ip:192.168.1.0",
        "ip:192.168.1.255",
        " ip:192.168.1.18",
        "ip:192.168.1.18:",
        "ip:192.168.1.18:0",
        "ip:192.168.1.18:030432",
        "ip:192.168.1.18:65536",
        "ip:192.168.1.18:not-a-port",
    ),
)
def test_client_rejects_every_nonphysical_or_noncanonical_uri(uri: str) -> None:
    with pytest.raises(ValueError, match="persistent hopping"):
        require_physical_lan_uri(uri)


def test_client_accepts_canonical_physical_lan_uri_with_explicit_port() -> None:
    assert require_physical_lan_uri("ip:192.168.1.18:30432") == (
        "ip:192.168.1.18:30432"
    )


def test_client_rejects_wrong_and_excluded_serial_before_capture() -> None:
    wrong = _Backend(URI, serial="wrong")
    with pytest.raises(PersistentHopClientError, match="does not match"):
        _client(wrong).start(
            _plan(),
            session_id=SESSION_ID,
            tandem_request=TandemSessionRequestV1(mode=TandemMode.HOLD),
        )
    assert wrong.started_request is None and wrong.closed

    with pytest.raises(ValueError, match="forbidden"):
        PersistentHopClient(
            URI,
            expected_serial=PERSISTENT_HOP_EXCLUDED_SERIAL,
            backend_factory=lambda _uri: wrong,
        )

    excluded = _Backend(URI, serial=PERSISTENT_HOP_EXCLUDED_SERIAL)
    with pytest.raises(PersistentHopClientError, match="forbidden"):
        _client(excluded).start(
            _plan(),
            session_id=SESSION_ID,
            tandem_request=TandemSessionRequestV1(mode=TandemMode.HOLD),
        )
    assert excluded.started_request is None and excluded.closed


def test_client_requires_every_exact_capability_literal() -> None:
    attributes = {
        "hw_serial": SERIAL,
        "iio,buffer-metadata": "3",
        **{name: "1" for name in PERSISTENT_HOP_CAPABILITIES},
    }
    attributes[PERSISTENT_HOP_CAPABILITIES[-1]] = "2"
    backend = _Backend(URI, capabilities=attributes)

    with pytest.raises(PersistentHopClientError, match="capability negotiation"):
        _client(backend).start(
            _plan(),
            session_id=SESSION_ID,
            tandem_request=TandemSessionRequestV1(mode=TandemMode.HOLD),
        )
    assert backend.started_request is None and backend.closed


def test_client_compiles_zero_crc_plan_before_composing_hopr() -> None:
    plan = dataclasses.replace(
        _plan(),
        profiles=tuple(
            dataclasses.replace(profile, profile_crc32=0)
            for profile in _plan().profiles
        ),
    )
    backend = _PreparingBackend(URI)
    backend.statuses[1] = dataclasses.replace(
        _cancelled_status(),
        visits_started=0,
        events_emitted=0,
        next_event_sequence=0,
        last_block_end_counter=0,
        final_counter=1_000,
        restore_before_counter=1_000,
        restore_after_counter=1_001,
        startup_invalid_start_counter=0,
        startup_invalid_end_counter_exclusive=0,
    )

    session = _client(backend).start(
        plan,
        session_id=SESSION_ID,
        tandem_request=TandemSessionRequestV1(mode=TandemMode.HOLD),
    )

    assert backend.started_request is not None
    request = PersistentHopRequestV1.unpack(backend.started_request[-288:])
    assert tuple(profile.profile_crc32 for profile in request.profiles) == tuple(
        range(101, 109)
    )
    session.close()


def test_continuous_client_yields_dual_rx_and_cancel_restore_receipts() -> None:
    backend = _Backend(URI, blocks=(_wire_block(),))
    session = _client(backend).start(
        _plan(),
        session_id=SESSION_ID,
        tandem_request=TandemSessionRequestV1(mode=TandemMode.HOLD),
    )
    blocks = session.blocks()
    block = next(blocks)

    assert block.samples.shape == (2, 1_024)
    assert backend.started_shape == (1_024, 2)
    assert backend.started_request is not None
    assert len(backend.started_request) == 104 + 288
    assert PersistentHopRequestV1.unpack(backend.started_request[-288:]).session_id == SESSION_ID

    receipt = session.cancel()
    assert isinstance(receipt, PersistentHopCancellationReceiptV1)
    assert receipt.reason is PersistentHopTerminalReason.CLIENT_CLOSE
    assert receipt.restoration.status == "restored"
    assert receipt.restoration.restored_lo_frequency_hz == 915_000_000
    assert backend.cancelled and backend.closed
    assert session.receipt.capture_outcome == "cancelled"
    assert session.receipt.valid_sample_count == 0
    assert session.receipt.transition_invalid_sample_count == 11
    assert session.receipt.incomplete_visit_sample_count == 1_013
    assert (
        session.receipt.valid_sample_count
        + session.receipt.transition_invalid_sample_count
        + session.receipt.incomplete_visit_sample_count
        == session.receipt.duty_denominator_sample_count
    )


def test_visit_iterator_slices_split_boundaries_and_emits_final_visit() -> None:
    plan = _plan()
    request = dataclasses.replace(
        plan.request(session_id=SESSION_ID),
        dwell_count=2,
        capture_span_samples=600_000,
    )
    first_event = _event()
    second_event = _event(sequence=1, dwell=1, invalid_start=301_011)
    terminal_flags = (
        PersistentHopStatusFlag.TERMINAL
        | PersistentHopStatusFlag.RESTORE_ATTEMPTED
        | PersistentHopStatusFlag.RESTORE_SUCCEEDED
        | PersistentHopStatusFlag.RESTORE_REQUIRED
    )

    def block(
        sequence: int,
        start: int,
        end: int,
        *,
        events: tuple[PersistentHopEventV1, ...] = (),
        terminal: bool = False,
    ) -> PersistentHopWireBlock:
        evidence = PersistentHopEvidenceV1(
            flags=terminal_flags if terminal else PersistentHopStatusFlag.RESTORE_REQUIRED,
            session_id=SESSION_ID,
            buffer_sequence=sequence,
            block_first_counter=start,
            block_end_counter_exclusive=end,
            state=(
                PersistentHopSessionState.COMPLETED
                if terminal
                else PersistentHopSessionState.RUNNING
            ),
            reason=(
                PersistentHopTerminalReason.PLAN_COMPLETE
                if terminal
                else PersistentHopTerminalReason.NONE
            ),
            error_code=0,
            events=events,
        )
        components = np.zeros((end - start, 4), dtype="<i2")
        components[:, 0] = sequence + 1
        components[:, 2] = sequence + 11
        return PersistentHopWireBlock(evidence.pack(), components.tobytes())

    final_counter = 601_022
    terminal_block_end = final_counter + 500
    backend = _Backend(
        URI,
        blocks=(
            # OPEN may snapshot the scheduler before the first refill has
            # anchored its counter epoch. Only transition-invalid IQ precedes
            # the first block here, so no valid visit samples are absent.
            block(0, 1_005, 150_000, events=(first_event,)),
            block(1, 150_000, 400_000, events=(second_event,)),
            # Completion is observed at refill granularity. The final refill
            # can therefore contain an ignored tail after the plan boundary.
            block(2, 400_000, terminal_block_end, terminal=True),
        ),
    )
    completed = dataclasses.replace(
        _cancelled_status(),
        state=PersistentHopSessionState.COMPLETED,
        reason=PersistentHopTerminalReason.PLAN_COMPLETE,
        planned_dwells=2,
        visits_started=2,
        events_emitted=2,
        next_event_sequence=2,
        last_block_sequence=2,
        last_block_end_counter=terminal_block_end,
        final_counter=final_counter,
        restore_before_counter=terminal_block_end,
        restore_after_counter=terminal_block_end + 1,
    )
    backend.statuses = [completed]
    initial = dataclasses.replace(_active_status(), planned_dwells=2)
    session = PersistentHopSession(_client(backend), backend, plan, request, initial)

    visits = list(session.visits())

    assert len(visits) == 2
    assert tuple(item.visit.target_index for item in visits) == (0, 1)
    assert tuple(item.samples.shape for item in visits) == ((2, 300_000), (2, 300_000))
    # Visit zero crosses the first refill boundary; the final visit crosses
    # the last and is emitted only after HOPT supplies final_counter.
    assert visits[0].samples[0, 0] == 1 + 0j
    assert visits[0].samples[0, 148_988] == 1 + 0j
    assert visits[0].samples[0, 148_989] == 2 + 0j
    assert visits[1].samples[0, -1] == 3 + 0j
    assert session.receipt.visits[-1].valid_device_sample_counter_end_exclusive == (
        final_counter
    )
    assert session.receipt.status.last_block_end_counter == terminal_block_end
    assert session.receipt.status.restore_before_counter >= terminal_block_end
    assert backend.closed


def test_cancelled_full_receipt_keeps_only_completed_visits_and_partial_span() -> None:
    second_event = _event(sequence=1, dwell=1, invalid_start=301_011)
    backend = _Backend(
        URI,
        blocks=(
            _wire_block(end_counter=150_000),
            _wire_block(
                buffer_sequence=1,
                first_counter=150_000,
                end_counter=400_000,
                events=(second_event,),
            ),
        ),
    )
    backend.statuses[1] = dataclasses.replace(
        _cancelled_status(),
        visits_started=2,
        events_emitted=2,
        next_event_sequence=2,
        last_block_sequence=1,
        last_block_end_counter=400_000,
        final_counter=400_100,
        restore_before_counter=400_100,
        restore_after_counter=400_101,
    )
    session = _client(backend).start(
        _plan(),
        session_id=SESSION_ID,
        tandem_request=TandemSessionRequestV1(mode=TandemMode.HOLD),
    )
    blocks = session.blocks()
    next(blocks)
    next(blocks)

    session.cancel()
    receipt = session.receipt

    assert receipt.capture_outcome == "cancelled"
    assert len(receipt.visits) == 1
    assert receipt.target_coverage[0].visit_count == 1
    assert receipt.valid_sample_count == 300_000
    assert receipt.transition_invalid_sample_count == 22
    assert receipt.incomplete_visit_sample_count == 99_078
    assert receipt.incomplete_visit_device_sample_counter == 301_022
    assert receipt.incomplete_visit_device_sample_counter_end_exclusive == 400_100
    assert receipt.valid_duty_ppm == 751_691


def test_cancelled_receipt_reports_attained_duty_independently_of_completion() -> None:
    second_event = _event(sequence=1, dwell=1, invalid_start=301_011)
    final_counter = second_event.invalid_end_counter_exclusive
    backend = _Backend(
        URI,
        blocks=(
            _wire_block(end_counter=150_000),
            _wire_block(
                buffer_sequence=1,
                first_counter=150_000,
                end_counter=final_counter,
                events=(second_event,),
            ),
        ),
    )
    backend.statuses[1] = dataclasses.replace(
        _cancelled_status(),
        visits_started=2,
        events_emitted=2,
        next_event_sequence=2,
        last_block_sequence=1,
        last_block_end_counter=final_counter,
        final_counter=final_counter,
        restore_before_counter=final_counter,
        restore_after_counter=final_counter + 1,
    )
    session = _client(backend).start(
        _plan(),
        session_id=SESSION_ID,
        tandem_request=TandemSessionRequestV1(mode=TandemMode.HOLD),
    )
    blocks = session.blocks()
    next(blocks)
    next(blocks)

    session.cancel()
    receipt = session.receipt

    assert receipt.capture_outcome == "cancelled"
    assert receipt.valid_duty_ppm == 999_926
    assert receipt.duty_target_met


@pytest.mark.parametrize(
    ("block", "message"),
    (
        (_wire_block(buffer_sequence=1), "buffer sequence"),
        (
            _wire_block(
                flags=(
                    PersistentHopStatusFlag.RESTORE_REQUIRED
                    | PersistentHopStatusFlag.DEVICE_EVENT_OVERFLOW
                )
            ),
            "overflow",
        ),
        (
            _wire_block(events=(dataclasses.replace(_event(), event_sequence=1),)),
            "event sequence",
        ),
        (
            _wire_block(
                events=(
                    dataclasses.replace(
                        _event(),
                        actual_lo_frequency_hz=_event().actual_lo_frequency_hz + 1,
                        actual_if_offset_hz=_event().actual_if_offset_hz - 1,
                    ),
                )
            ),
            "actual LO or IF",
        ),
    ),
)
def test_client_fails_closed_on_gaps_overflow_and_out_of_order_events(
    block: PersistentHopWireBlock,
    message: str,
) -> None:
    backend = _Backend(URI, blocks=(block,))
    session = _client(backend).start(
        _plan(),
        session_id=SESSION_ID,
        tandem_request=TandemSessionRequestV1(mode=TandemMode.HOLD),
    )

    with pytest.raises(PersistentHopClientError, match=message):
        list(session.blocks())
    assert backend.cancelled and backend.closed


def test_client_rejects_abi3_stream_generation_change() -> None:
    backend = _Backend(
        URI,
        blocks=(
            dataclasses.replace(_wire_block(), stream_generation=41),
            dataclasses.replace(
                _wire_block(
                    buffer_sequence=1,
                    first_counter=2_024,
                    end_counter=3_048,
                    events=(),
                ),
                stream_generation=42,
            ),
        ),
    )
    session = _client(backend).start(
        _plan(),
        session_id=SESSION_ID,
        tandem_request=TandemSessionRequestV1(mode=TandemMode.HOLD),
    )

    with pytest.raises(PersistentHopClientError, match="stream generation changed"):
        list(session.blocks())
    assert backend.cancelled and backend.closed
