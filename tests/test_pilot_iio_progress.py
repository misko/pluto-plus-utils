"""Bounded pilot notifications with fake IIO, never RF/DMA qualification."""

from __future__ import annotations

import hashlib
import queue
import threading
from dataclasses import FrozenInstanceError
from typing import Any

import pytest
from test_pilot_iio_client import _assert_restored, _Buffer, _connect, _setup

from pluto_plus.hardware.pilot_iio import (
    PILOT_MAX_PROGRESS_EVENTS,
    PilotArmedEvent,
    PilotCapture,
    PilotCaptureError,
    PilotCaptureEvent,
    PilotIqChunkEvent,
    PilotOriginEvent,
    PilotTerminalEvent,
)


def _drain(events: queue.Queue[PilotCaptureEvent]) -> list[PilotCaptureEvent]:
    result = []
    while True:
        try:
            result.append(events.get_nowait())
            events.task_done()
        except queue.Empty:
            return result


def _events(size: int = 20) -> queue.Queue[PilotCaptureEvent]:
    return queue.Queue(maxsize=size)


@pytest.mark.parametrize("rate", (15_000_000, 30_000_000, 60_000_000))
def test_empty_arm_then_first_received_origin_and_exact_chunks(rate: int) -> None:
    device, context, module = _setup(rate=rate)
    events = _events()
    with _connect(module) as client:
        capture = client.capture(visit_id=17, samples=8, refill_samples=2, progress_queue=events)
    arm, origin, *rest = _drain(events)
    assert isinstance(arm, PilotArmedEvent) and arm.snapshot.axis_delivered_samples == 0
    assert isinstance(origin, PilotOriginEvent)
    assert origin.snapshot.axis_delivered_samples == origin.received_samples == 2
    assert origin.first_source_center == 271 * (rate // 15_000_000)
    assert capture.snapshot_origin == origin.snapshot
    assert origin.snapshot.generation > arm.snapshot.generation
    assert capture.snapshot_final.generation == 4  # Post-CLEAR ARM/origin/final/stopped.
    chunks, terminal = rest[:-1], rest[-1]
    assert all(isinstance(chunk, PilotIqChunkEvent) for chunk in chunks)
    assert [chunk.output_offset for chunk in chunks] == [0, 2, 4, 6]
    assert [chunk.sample_count for chunk in chunks] == [2] * 4
    assert b"".join(chunk.iq for chunk in chunks) == capture.iq
    assert isinstance(terminal, PilotTerminalEvent) and terminal.complete
    assert terminal.received_bytes == terminal.published_iq_bytes == 32
    assert terminal.iq_sha256 == hashlib.sha256(capture.iq).hexdigest()
    assert terminal.snapshots[-1] == capture.snapshot_final
    assert not terminal.failure and not terminal.cleanup_errors and not terminal.progress_errors
    assert all(event.identity == arm.identity for event in (origin, *rest))
    assert arm.identity.serial == capture.serial and arm.identity.boot_id == "boot-a"
    assert arm.identity.session_id == capture.session_id and arm.identity.visit_id == 17
    assert arm.identity.source_rate_hz == rate and arm.identity.output_rate_hz == 2_500_000
    assert arm.identity.requested_samples == 8 and arm.identity.refill_samples == 2
    assert context.closes == 1
    _assert_restored(device, module)
    with pytest.raises(FrozenInstanceError):
        origin.received_samples = 3  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        arm.identity.visit_id = 3  # type: ignore[misc]


def test_existing_arm_prefix_is_not_published_as_received_until_first_refill() -> None:
    device, _, module = _setup()
    events = _events()
    at_refill: list[list[PilotCaptureEvent]] = []

    def configure(buffer: _Buffer) -> None:
        device.samples = 1  # The early hardware prefix is shorter than one host refill.

        def refill() -> None:
            if buffer.refills == 1:
                at_refill.append(_drain(events))
            device.samples = (buffer.refills - 1) * buffer.count

        buffer.on_refill = refill

    module.configure = configure
    with _connect(module) as client:
        capture = client.capture(visit_id=17, samples=8, refill_samples=2, progress_queue=events)
    assert len(at_refill[0]) == 1 and isinstance(at_refill[0][0], PilotArmedEvent)
    origin, *rest = _drain(events)
    assert isinstance(origin, PilotOriginEvent) and origin.received_samples == 2
    assert origin.snapshot == capture.snapshot_armed
    assert origin.snapshot.axis_delivered_samples == 1  # NOT a fabricated count of 2.
    assert capture.snapshot_final.generation == 3  # No extra snapshot was needed.
    assert len(rest) == 5
    _assert_restored(device, module)


def test_no_option_has_original_iq_and_snapshot_requests() -> None:
    device, _, module = _setup()
    with _connect(module) as client:
        client.cancel()  # Preserve the legacy per-capture reset behavior.
        result = client.capture(visit_id=17, samples=8, refill_samples=2)
    assert result.iq == b"".join(bytes([index]) * 8 for index in range(1, 5))
    assert result.snapshot_final.generation == 3 and result.snapshot_origin is None
    _assert_restored(device, module)


@pytest.mark.parametrize("value", [
    queue.Queue(), queue.Queue(-1), queue.Queue(True), queue.Queue(PILOT_MAX_PROGRESS_EVENTS + 1),
    queue.SimpleQueue(), queue.LifoQueue(10), queue.PriorityQueue(10), object(),
])
def test_queue_requires_standard_bounded_fifo_before_hardware(value: Any) -> None:
    device, context, module = _setup()
    with _connect(module) as client:
        initial_timeouts = list(context.timeouts)
        with pytest.raises(ValueError, match="progress_queue"):
            client.capture(visit_id=17, progress_queue=value)
        assert context.timeouts == initial_timeouts
    assert device.generation == 0 and not module.buffers


def test_cancel_token_requires_standard_event_before_hardware() -> None:
    device, _, module = _setup()
    with _connect(module) as client, pytest.raises(ValueError, match="cancel_event"):
        client.capture(visit_id=17, cancel_event=object())  # type: ignore[arg-type]
    assert not device.generation and not module.buffers


@pytest.mark.parametrize("size,refills,published", [(1, 1, 0), (2, 1, 0), (3, 2, 8), (6, 4, 32)])
def test_queue_full_at_origin_chunk_or_terminal_is_fatal_and_restores(
    size: int, refills: int, published: int,
) -> None:
    device, _, module = _setup()
    events = _events(size)
    with (
        _connect(module) as client,
        pytest.raises(PilotCaptureError, match="queue is full") as raised,
    ):
        client.capture(visit_id=17, samples=8, refill_samples=2, progress_queue=events)
    error = raised.value
    assert len(error.partial_iq) == refills * 8
    assert error.snapshots[-1].axis_delivered_samples == refills * 2
    assert error.progress_errors and not error.cleanup_errors
    pending = _drain(events)
    chunks = [event for event in pending if isinstance(event, PilotIqChunkEvent)]
    assert sum(len(event.iq) for event in chunks) == published
    assert not any(isinstance(event, PilotTerminalEvent) for event in pending)
    assert module.buffers[0].refills == refills
    _assert_restored(device, module)


def test_queue_full_on_arm_never_reads_and_cannot_silently_drop_event() -> None:
    device, _, module = _setup()
    events = _events(1)
    events.put_nowait(object())  # type: ignore[arg-type]  # Simulate a stale caller-owned queue.
    with (
        _connect(module) as client,
        pytest.raises(PilotCaptureError, match="queue is full") as raised,
    ):
        client.capture(visit_id=17, samples=8, refill_samples=2, progress_queue=events)
    assert not raised.value.partial_iq and module.buffers[0].refills == 0
    assert len(raised.value.progress_errors) == 2  # ARM and attempted terminal, neither discarded.
    _assert_restored(device, module)


def test_event_delivery_error_retains_partial_and_deliverable_failed_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    device, _, module = _setup()
    events = _events()
    original = events.put_nowait

    def fail_first_chunk(event: PilotCaptureEvent) -> None:
        if isinstance(event, PilotIqChunkEvent):
            raise OSError("injected event delivery error")
        original(event)

    monkeypatch.setattr(events, "put_nowait", fail_first_chunk)
    with _connect(module) as client, pytest.raises(PilotCaptureError, match="delivery") as raised:
        client.capture(visit_id=17, samples=8, refill_samples=2, progress_queue=events)
    terminal = _drain(events)[-1]
    assert isinstance(terminal, PilotTerminalEvent) and not terminal.complete
    assert terminal.received_bytes == len(raised.value.partial_iq) == 8
    assert terminal.published_iq_bytes == 0
    assert terminal.progress_errors == raised.value.progress_errors
    assert "injected event delivery error" in terminal.failure
    _assert_restored(device, module)


@pytest.mark.parametrize("during_reset", (False, True))
def test_external_startup_cancel_never_cleared_or_performs_io(
    monkeypatch: pytest.MonkeyPatch, during_reset: bool,
) -> None:
    device, context, module = _setup()
    cancelled = threading.Event()
    events = _events()
    with _connect(module) as client:
        initial_timeouts = list(context.timeouts)
        monkeypatch.setattr(client, "_attest_identity",
                            lambda _: pytest.fail("unexpected identity I/O"))
        if during_reset:
            original_clear = client._cancel.clear

            def startup_race() -> None:
                cancelled.set()
                original_clear()

            monkeypatch.setattr(client._cancel, "clear", startup_race)
        else:
            cancelled.set()
        with pytest.raises(PilotCaptureError, match="cancelled") as raised:
            client.capture(visit_id=17, progress_queue=events, cancel_event=cancelled)
        assert context.timeouts == initial_timeouts
    assert cancelled.is_set() and not module.buffers and not device.generation
    assert not raised.value.partial_iq and not raised.value.snapshots
    terminal, = _drain(events)
    assert isinstance(terminal, PilotTerminalEvent) and not terminal.complete
    assert not terminal.snapshots and terminal.received_bytes == 0
    _assert_restored(device, module)


@pytest.mark.parametrize("when", (
    "configure", "construct", "first-refill", "second-refill", "cleanup",
))
def test_external_cancel_between_startup_refill_and_cleanup_budgets(when: str) -> None:
    device, _, module = _setup()
    cancelled = threading.Event()
    events = _events()
    if when == "configure":
        device.attrs["capture_visit_id"].on_write = lambda _: cancelled.set()

    def configure(buffer: _Buffer) -> None:
        if when == "construct":
            cancelled.set()
        elif when == "cleanup":
            buffer.on_close = cancelled.set
        else:
            def refill() -> None:
                if (when, buffer.refills) in (("first-refill", 1), ("second-refill", 2)):
                    cancelled.set()
            buffer.on_refill = refill

    module.configure = configure
    with _connect(module) as client, pytest.raises(PilotCaptureError, match="cancelled") as raised:
        client.capture(visit_id=17, samples=8, refill_samples=2, progress_queue=events,
                       cancel_event=cancelled)
    expected = {
        "configure": 0, "construct": 0, "first-refill": 8, "second-refill": 16, "cleanup": 32,
    }
    assert len(raised.value.partial_iq) == expected[when] and cancelled.is_set()
    terminal = _drain(events)[-1]
    assert isinstance(terminal, PilotTerminalEvent) and not terminal.complete
    assert terminal.received_bytes == expected[when]
    _assert_restored(device, module)


def test_early_origin_is_available_to_an_independent_consumer_before_capture_finishes() -> None:
    device, _, module = _setup()
    events = _events()
    entered = threading.Event()
    release = threading.Event()
    cancelled = threading.Event()
    outcomes: list[PilotCapture | BaseException] = []

    def configure(buffer: _Buffer) -> None:
        def refill() -> None:
            if buffer.refills == 2:
                entered.set()
                assert release.wait(2), "test consumer did not release the bounded fake refill"
        buffer.on_refill = refill

    module.configure = configure
    with _connect(module) as client:
        def capture() -> None:
            try:
                outcomes.append(client.capture(visit_id=17, samples=8, refill_samples=2,
                                               progress_queue=events, cancel_event=cancelled))
            except BaseException as error:
                outcomes.append(error)

        worker = threading.Thread(target=capture)
        worker.start()
        try:
            assert entered.wait(2) and worker.is_alive()
            arm, origin, chunk = _drain(events)
            assert isinstance(arm, PilotArmedEvent) and isinstance(origin, PilotOriginEvent)
            assert isinstance(chunk, PilotIqChunkEvent) and chunk.output_offset == 0
            assert origin.received_samples == 2 and origin.first_source_center == 271
            cancelled.set()
        finally:
            release.set()
            worker.join(2)
        assert not worker.is_alive()
    assert len(outcomes) == 1 and isinstance(outcomes[0], PilotCaptureError)
    assert len(outcomes[0].partial_iq) == 16
    _assert_restored(device, module)


def test_cancel_during_final_iq_hash_precedes_terminal_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    device, _, module = _setup()
    events = _events()
    cancelled = threading.Event()
    original_hash = hashlib.sha256

    def cancel_while_hashing(iq: bytes) -> Any:
        cancelled.set()
        return original_hash(iq)

    monkeypatch.setattr(hashlib, "sha256", cancel_while_hashing)
    with _connect(module) as client, pytest.raises(PilotCaptureError, match="cancelled") as raised:
        client.capture(visit_id=17, samples=8, refill_samples=2, progress_queue=events,
                       cancel_event=cancelled)
    terminal = _drain(events)[-1]
    assert isinstance(terminal, PilotTerminalEvent) and not terminal.complete
    assert terminal.received_bytes == terminal.published_iq_bytes == 32
    assert len(raised.value.partial_iq) == 32 and not raised.value.cleanup_errors
    _assert_restored(device, module)


@pytest.mark.parametrize("field,value", [
    ("samples", 0), ("samples", 1), ("visit", 99), ("actual_rate", 2_500_000),
    ("dma_error", -5), ("fault", 4), ("ddc_fault", 1), ("clips", 1),
    ("freeze_generation", True),
])
def test_early_snapshot_must_attest_origin_visit_rate_generation_and_health(
    field: str, value: int,
) -> None:
    device, _, module = _setup()
    events = _events()

    def configure(buffer: _Buffer) -> None:
        def snapshot() -> None:
            if buffer.refills:
                setattr(device, field, value)
        device.snapshot_hook = snapshot

    module.configure = configure
    with _connect(module) as client, pytest.raises(PilotCaptureError) as raised:
        client.capture(visit_id=17, samples=8, refill_samples=2, progress_queue=events)
    assert len(raised.value.partial_iq) == 8
    pending = _drain(events)
    assert not any(isinstance(event, (PilotOriginEvent, PilotIqChunkEvent)) for event in pending)
    assert isinstance(pending[-1], PilotTerminalEvent) and not pending[-1].complete
    _assert_restored(device, module)


@pytest.mark.parametrize("use_arm", (False, True))
@pytest.mark.parametrize("attribute,value", [("hw_serial", "other-radio"), ("boot_id", "boot-b")])
def test_origin_identity_is_rechecked_even_when_reusing_arm(
    use_arm: bool, attribute: str, value: str,
) -> None:
    device, context, module = _setup()
    events = _events()

    def configure(buffer: _Buffer) -> None:
        if use_arm:
            device.samples = 1

        def refill() -> None:
            device.samples = (buffer.refills - 1) * buffer.count
            context.attrs[attribute] = value
        buffer.on_refill = refill

    module.configure = configure
    with _connect(module) as client, pytest.raises(PilotCaptureError) as raised:
        client.capture(visit_id=17, samples=8, refill_samples=2, progress_queue=events)
    assert len(raised.value.partial_iq) == 8
    assert not any(isinstance(event, PilotOriginEvent) for event in _drain(events))
    _assert_restored(device, module)


@pytest.mark.parametrize("when", ("origin", "final", "stopped"))
def test_invalid_or_changed_origin_never_becomes_final_transport_success(when: str) -> None:
    device, _, module = _setup()
    events = _events()
    snapshot = device.snapshot

    def modified_snapshot() -> str:
        fields = snapshot().split()
        if not module.buffers:
            return " ".join(fields)
        buffer = module.buffers[0]
        modify = ((when == "origin" and buffer.refills) or
                  (when == "final" and buffer.refills == 4) or
                  (when == "stopped" and buffer.closes))
        if modify and device.samples:
            first = 534 if when == "origin" else 546
            fields[8] = f"{first:08x}"
            fields[10] = f"{first + (device.samples - 1) * 6:08x}"
        return " ".join(fields)

    device.attrs["capture_snapshot"].getter = modified_snapshot
    with _connect(module) as client, pytest.raises(PilotCaptureError) as raised:
        client.capture(visit_id=17, samples=8, refill_samples=2, progress_queue=events)
    assert len(raised.value.partial_iq) == (8 if when == "origin" else 32)
    pending = _drain(events)
    assert isinstance(pending[-1], PilotTerminalEvent) and not pending[-1].complete
    if when == "origin":
        assert not any(isinstance(event, PilotOriginEvent) for event in pending)
    _assert_restored(device, module)


@pytest.mark.parametrize("prior_generation", (0, 16, 0xfffffffe))
def test_driver_preenable_clear_makes_arm_a_new_snapshot_epoch(prior_generation: int) -> None:
    device, _, module = _setup()
    events = _events()
    device.generation = prior_generation
    # The common fake Buffer models pilot_preenable's mandatory CLEAR, before ARM.
    with _connect(module) as client:
        result = client.capture(visit_id=17, samples=8, refill_samples=2, progress_queue=events)
    assert result.snapshot_before.generation == prior_generation + 1
    assert result.snapshot_armed.generation == 1
    assert result.snapshot_origin.generation == 2
    assert result.snapshot_final.generation == 4
    pending = _drain(events)
    assert isinstance(pending[-1], PilotTerminalEvent) and pending[-1].complete
    _assert_restored(device, module)


@pytest.mark.parametrize("when", ("origin", "final", "stopped"))
def test_u32_generation_wrap_is_fail_closed_not_mistaken_for_freshness(when: str) -> None:
    device, _, module = _setup()
    events = _events()
    initial = {"origin": 0xfffffffe, "final": 0xfffffffd, "stopped": 0xfffffffc}
    # Inject near-wrap state AFTER the mandatory CLEAR, within the new epoch.
    module.configure = lambda _: setattr(device, "generation", initial[when])

    def wrap() -> None:
        if device.generation == 0xffffffff:
            # Wire returns 1: valid u32, but epoch continuity is not admitted here.
            device.generation = 0

    device.snapshot_hook = wrap
    with _connect(module) as client, pytest.raises(PilotCaptureError, match="generation"):
        client.capture(visit_id=17, samples=8, refill_samples=2, progress_queue=events)
    pending = _drain(events)
    assert isinstance(pending[-1], PilotTerminalEvent) and not pending[-1].complete
    _assert_restored(device, module)


@pytest.mark.parametrize("when", ("final", "stopped"))
@pytest.mark.parametrize("field,value", [("fault", 4), ("ddc_fault", 1), ("clips", 1)])
def test_late_fault_invalidates_healthy_early_origin_and_retains_all_bytes(
    when: str, field: str, value: int,
) -> None:
    device, _, module = _setup()
    events = _events()

    def configure(buffer: _Buffer) -> None:
        def refill() -> None:
            if when == "final" and buffer.refills == 4:
                setattr(device, field, value)
        buffer.on_refill = refill
        if when == "stopped":
            buffer.on_close = lambda: setattr(device, field, value)

    module.configure = configure
    with _connect(module) as client, pytest.raises(PilotCaptureError) as raised:
        client.capture(visit_id=17, samples=8, refill_samples=2, progress_queue=events)
    pending = _drain(events)
    assert isinstance(pending[1], PilotOriginEvent) and not pending[1].snapshot.capture_faults
    assert isinstance(pending[-1], PilotTerminalEvent) and not pending[-1].complete
    assert pending[-1].received_bytes == pending[-1].published_iq_bytes == 32
    assert len(raised.value.partial_iq) == 32 and len(raised.value.snapshots) == 5
    _assert_restored(device, module)
