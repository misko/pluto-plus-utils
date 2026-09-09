"""Raw PSS receipt tests with bounded fake IIO, not hardware qualification."""

from __future__ import annotations

import struct
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import FrozenInstanceError, replace
from types import SimpleNamespace
from typing import Any

import pytest
from test_pss_iio import (
    _Buffer,
    _client,
    _Device,
    _fine_scan,
    _health_line,
    _install_health,
    _map_scan,
)

from pluto_plus.errors import RadioConfigurationError
from pluto_plus.hardware import pss_iio
from pluto_plus.hardware.pss_iio import (
    PSS_MAP_SCAN_BYTES,
    PSS_MAX_BATCH_BYTES,
    PSS_MAX_BATCH_SCANS,
    PSS_TRACK_SCAN_BYTES,
    PssBatchError,
    PssBatchReceipt,
    PssFinePacket,
    PssGracefulCloseError,
    PssIioClient,
    PssMapChunk,
    PssMapReassembler,
)


class _BatchBuffer(_Buffer):
    def __init__(self, device: _Device, count: int, cyclic: bool) -> None:
        super().__init__(device, count, cyclic)
        self.step = device.sample_size
        self.byte_length = count * self.step
        self._samples_count = count
        self.refills = self.reads = 0
        self.on_refill: Callable[[], None] | None = None
        self.return_count: int | None = None
        if device.name.endswith("track"):
            self.payload: bytes | bytearray = b"".join(
                _fine_scan(request=3 + index) for index in range(count)
            )
        else:
            self.payload = b"".join(
                _map_scan(index % 200, generation=5 + index // 200) for index in range(count)
            )
            payload = bytearray(self.payload)
            for offset in range(0, len(payload), self.step):
                struct.pack_into("<I", payload, offset + 4, int(device.attrs["abi_version"].value))
            self.payload = bytes(payload)

    def __len__(self) -> int:
        return self.byte_length

    def refill(self) -> int | None:
        self.refills += 1
        if self.on_refill:
            self.on_refill()
        return self.return_count

    def read(self) -> bytes | bytearray:
        self.reads += 1
        return self.payload


def _setup(*, rate: int = 60, shared: bool = False) -> tuple[PssIioClient, list[_BatchBuffer]]:
    client, tracker, phase_map = _client(rate=rate, shared_xfft=shared)
    tracker.sample_size = PSS_TRACK_SCAN_BYTES
    phase_map.sample_size = PSS_MAP_SCAN_BYTES
    made: list[_BatchBuffer] = []

    def buffer(device: _Device, count: int, cyclic: bool) -> _BatchBuffer:
        assert client.context.timeouts, "batch admission must set timeout before native allocation"
        created = _BatchBuffer(device, count, cyclic)
        made.append(created)
        return created

    client._iio = SimpleNamespace(Buffer=buffer)
    return client, made


def _open(client: PssIioClient, stream: str, **kwargs: Any) -> None:
    if stream == "map":
        client.open_maps(refill_chunks=200, batch_mode=True, **kwargs)
    else:
        client.open_fine(first_center=1_000_000, period_q32_32=80_000 << 32,
                         request_base=3, count=4, refill_results=4, batch_mode=True, **kwargs)


def _read(client: PssIioClient, stream: str, **kwargs: Any) -> PssBatchReceipt:
    return (client.read_map_batch(**kwargs) if stream == "map" else
            client.read_fine_batch(**kwargs))


def _cleanup(client: PssIioClient, buffers: list[_BatchBuffer]) -> None:
    _install_health(client.phase_map, _health_line(abi=client.map_abi_version),
                    _health_line(abi=client.map_abi_version, generation=9))
    # Failed batch/incomplete finite work stays unqualified, but still gets torn down.
    with suppress(PssGracefulCloseError):
        client.close_gracefully(readers_joined=True)
    assert all(buffer.close_count == 1 and not buffer.cancelled for buffer in buffers)
    assert client.context.close_count == 1 and not client._active_operations


@pytest.mark.parametrize("stream", ("map", "fine"))
@pytest.mark.parametrize("rate,shared", ((15, True), (15, False), (30, False), (60, False)))
def test_batch_retains_exact_raw_and_native_boundary(stream: str, rate: int, shared: bool) -> None:
    client, made = _setup(rate=rate, shared=shared)
    _open(client, stream, timeout_ms=123)
    receipt = _read(client, stream, timeout_ms=321)
    buffer = made[0]
    assert receipt.complete and receipt.raw_retention_complete
    assert receipt.raw == buffer.payload and receipt.observed_bytes == len(buffer.payload)
    assert receipt.buffer_bytes == len(buffer) and receipt.buffer_step == buffer.step
    assert receipt.refill_started and receipt.refill_completed
    assert receipt.native_refill_bytes is None
    assert receipt.batch_index == 0 and receipt.complete_scans == buffer.count
    assert not receipt.trailing_bytes and not receipt.errors
    assert receipt.rate_msps == rate
    assert receipt.attributes_before.fault_flags == receipt.attributes_after.fault_flags == 0
    assert client.context.timeouts == [123, 321]
    assert buffer.refills == buffer.reads == 1
    assert all(scan.byte_offset == scan.index * buffer.step for scan in receipt.scans)
    if stream == "fine":
        assert all(isinstance(scan.decoded, PssFinePacket) for scan in receipt.scans)
        assert client._expected_request == 7 and client._remaining_results == 0
        assert receipt.expected_request_before == 3 and receipt.remaining_results_before == 4
    else:
        assert all(isinstance(scan.decoded, PssMapChunk) for scan in receipt.scans)
        reassembler = PssMapReassembler()
        complete = [reassembler.add(scan.decoded) for scan in receipt.scans]
        assert complete[-1].start_index == 1234  # Still canonical source coordinates.
    with pytest.raises(FrozenInstanceError):
        receipt.raw = b"lost"  # type: ignore[misc]
    _cleanup(client, made)


def test_normal_16_result_fine_batches_commit_separately_and_keep_stream_identity() -> None:
    client, made = _setup()
    client.open_fine(first_center=1_000_000, period_q32_32=80_000 << 32,
                     request_base=3, count=32, batch_mode=True)
    first = client.read_fine_batch()
    made[0].payload = b"".join(_fine_scan(request=19 + index) for index in range(16))
    second = client.read_fine_batch()
    assert first.batch_index == 0 and second.batch_index == 1
    assert first.stream_id == second.stream_id
    assert first.raw != second.raw and first.remaining_results_before == 32
    assert second.remaining_results_before == 16 and client._remaining_results == 0
    _cleanup(client, made)


def test_negative_maps_are_retained_without_detection_based_filtering() -> None:
    client, made = _setup(rate=15, shared=True)
    _open(client, "map")
    raw = bytearray(made[0].payload)
    for offset in range(0, len(raw), PSS_MAP_SCAN_BYTES):
        raw[offset + 36:offset + 236] = bytes(200)
    made[0].payload = raw
    receipt = client.read_map_batch()
    assert receipt.complete and receipt.raw == bytes(raw)
    assert all(not any(scan.decoded.bins) for scan in receipt.scans)
    raw[:] = bytes(len(raw))  # Binding memory reuse cannot mutate the retained receipt.
    assert receipt.raw[:4] != bytes(4)
    _cleanup(client, made)


@pytest.mark.parametrize("stream", ("map", "fine"))
@pytest.mark.parametrize("kind", ("padding", "magic", "context"))
def test_malformed_middle_scan_retains_later_observations_and_does_not_advance_fine(
    stream: str, kind: str,
) -> None:
    client, made = _setup()
    _open(client, stream)
    buffer = made[0]
    raw = bytearray(buffer.payload)
    if kind == "padding":
        raw[2 * buffer.step - 1] = 1
    elif kind == "magic":
        raw[buffer.step] ^= 0xFF
    else:
        offset = 10 * 4 if stream == "fine" else 4
        struct.pack_into("<I", raw, buffer.step + offset, 8 if stream == "fine" else 0x10001)
    buffer.payload = bytes(raw)
    with pytest.raises(PssBatchError) as caught:
        _read(client, stream)
    receipt = caught.value.receipt
    assert receipt.raw == bytes(raw) and receipt.raw_retention_complete and not receipt.complete
    assert receipt.scans[0].decoded is not None and not receipt.scans[0].errors
    assert receipt.scans[1].errors
    assert receipt.scans[2].decoded is not None and not receipt.scans[2].errors
    if stream == "fine":
        assert client._expected_request == 3 and client._remaining_results == 4
    with pytest.raises(RadioConfigurationError, match="failed"):
        _read(client, stream)
    assert buffer.refills == 1
    _cleanup(client, made)


@pytest.mark.parametrize("stream", ("map", "fine"))
@pytest.mark.parametrize("kind", ("empty", "short-whole", "partial-tail", "oversize"))
def test_refill_length_failures_keep_exact_raw_or_explicit_bounded_prefix(
    stream: str, kind: str,
) -> None:
    client, made = _setup()
    _open(client, stream)
    buffer = made[0]
    cap = min(PSS_MAX_BATCH_BYTES, PSS_MAX_BATCH_SCANS * buffer.step)
    if kind == "empty":
        raw = b""
    elif kind == "short-whole":
        raw = buffer.payload[:-buffer.step]
    elif kind == "partial-tail":
        raw = buffer.payload[:-1]
    else:
        raw = bytes(buffer.payload[:buffer.step]) * PSS_MAX_BATCH_SCANS + b"tail"
    buffer.payload = raw
    with pytest.raises(PssBatchError) as caught:
        _read(client, stream)
    receipt = caught.value.receipt
    assert receipt.raw == raw[:cap] and receipt.observed_bytes == len(raw)
    assert receipt.raw_retention_complete == (kind != "oversize")
    assert not receipt.complete and len(receipt.scans) <= PSS_MAX_BATCH_SCANS
    if kind == "partial-tail":
        assert receipt.trailing_bytes == buffer.step - 1
        assert receipt.scans[-1].decoded is None and "truncated" in receipt.scans[-1].errors[0]
    _cleanup(client, made)


@pytest.mark.parametrize("stream", ("map", "fine"))
@pytest.mark.parametrize("where", ("refill", "read", "negative-return"))
def test_io_failure_never_substitutes_stale_buffer_or_empty_payload(
    stream: str, where: str,
) -> None:
    client, made = _setup()
    _open(client, stream)
    buffer = made[0]

    def failure() -> None:
        raise TimeoutError("bounded injected failure")

    if where == "refill":
        buffer.on_refill = failure
    elif where == "read":
        buffer.read = failure
    else:
        buffer.return_count = -5
    with pytest.raises(PssBatchError) as caught:
        _read(client, stream)
    receipt = caught.value.receipt
    assert receipt.raw is None and receipt.observed_bytes is None
    assert not receipt.raw_retention_complete and receipt.refill_started
    assert receipt.refill_completed == (where == "read")
    assert receipt.attributes_after.fault_flags == 0
    assert buffer.reads == 0
    _cleanup(client, made)


@pytest.mark.parametrize("native", (512, 511, 0))
def test_exposed_native_byte_count_is_not_confused_with_unavailable_count(native: int) -> None:
    client, made = _setup()
    _open(client, "fine")
    made[0].return_count = native
    if native == 512:
        receipt = client.read_fine_batch()
    else:
        with pytest.raises(PssBatchError) as caught:
            client.read_fine_batch()
        receipt = caught.value.receipt
    assert receipt.native_refill_bytes == native and receipt.observed_bytes == 512
    assert receipt.complete == (native == 512)
    _cleanup(client, made)


@pytest.mark.parametrize("stream", ("map", "fine"))
@pytest.mark.parametrize("when", ("before", "after"))
@pytest.mark.parametrize("kind", ("missing", "malformed", "fault"))
def test_unknown_or_faulted_attributes_are_retained_without_fabricated_zero(
    stream: str, when: str, kind: str,
) -> None:
    client, made = _setup()
    _open(client, stream)
    device = made[0].device

    def change() -> None:
        if kind == "missing":
            del device.attrs["fault_flags"]
        else:
            device.attrs["fault_flags"].value = "broken" if kind == "malformed" else "4"

    if when == "before":
        change()
    else:
        made[0].on_refill = change
    with pytest.raises(PssBatchError) as caught:
        _read(client, stream)
    receipt = caught.value.receipt
    observed = receipt.attributes_before if when == "before" else receipt.attributes_after
    assert observed.fault_flags == (4 if kind == "fault" else None)
    assert observed.errors
    assert (receipt.raw is not None) == (when == "after")
    assert made[0].refills == (1 if when == "after" else 0)
    if kind == "malformed":
        assert ("fault_flags", "broken") in observed.raw
    _cleanup(client, made)


@pytest.mark.parametrize("value", ("8", "0", "bad"))
def test_late_coefficient_change_cannot_commit_fine_sequence(value: str) -> None:
    client, made = _setup()
    _open(client, "fine")
    made[0].on_refill = lambda: setattr(client.tracker.attrs["active_coefficient_generation"],
                                      "value", value)
    with pytest.raises(PssBatchError) as caught:
        client.read_fine_batch()
    assert caught.value.receipt.raw == made[0].payload
    assert client._expected_request == 3 and client._remaining_results == 4
    assert all(scan.decoded is not None for scan in caught.value.receipt.scans)
    _cleanup(client, made)


@pytest.mark.parametrize("stream", ("map", "fine"))
@pytest.mark.parametrize("count", (4097, True, 2.5))
def test_batch_cap_rejects_native_allocation_before_control_io(stream: str, count: Any) -> None:
    client, made = _setup()
    with pytest.raises(ValueError):
        if stream == "map":
            client.open_maps(refill_chunks=count, batch_mode=True)
        else:
            client.open_fine(first_center=1_000_000, period_q32_32=80_000 << 32,
                             request_base=3, count=0, refill_results=count, batch_mode=True)
    assert not made and not client.context.timeouts
    _cleanup(client, made)


@pytest.mark.parametrize("stream", ("map", "fine"))
@pytest.mark.parametrize("timeout", (0, 60001, True))
def test_batch_timeout_is_required_before_open_io(stream: str, timeout: Any) -> None:
    client, made = _setup()
    with pytest.raises(ValueError, match="timeout"):
        _open(client, stream, timeout_ms=timeout)
    assert not made and not client.context.timeouts
    _cleanup(client, made)


def test_finite_fine_tail_is_rejected_before_allocating_a_stranded_refill() -> None:
    client, made = _setup()
    with pytest.raises(ValueError, match="whole native refills"):
        client.open_fine(first_center=1_000_000, period_q32_32=80_000 << 32,
                         request_base=3, count=17, refill_results=16, batch_mode=True)
    assert not made and not client.context.timeouts
    _cleanup(client, made)


@pytest.mark.parametrize("field,value", (("byte_length", 99), ("step", 1), ("_samples_count", 99)))
def test_changed_native_geometry_fails_before_refill_and_still_allows_cleanup(
    field: str, value: int,
) -> None:
    client, made = _setup()
    _open(client, "fine")
    setattr(made[0], field, value)
    with pytest.raises(PssBatchError, match="mismatch") as caught:
        client.read_fine_batch()
    assert caught.value.receipt.raw is None and not made[0].refills
    _cleanup(client, made)


@pytest.mark.parametrize("stream", ("map", "fine"))
def test_selected_batch_and_legacy_read_modes_cannot_mix(stream: str) -> None:
    client, made = _setup()
    _open(client, stream)
    with pytest.raises(RadioConfigurationError, match="mode"):
        client.read_map_chunks() if stream == "map" else client.read_fine()
    assert made[0].refills == 0
    _read(client, stream)
    _cleanup(client, made)

    legacy, _, _ = _client()
    if stream == "map":
        legacy.open_maps()
    else:
        legacy.open_fine(first_center=1_000_000, period_q32_32=80_000 << 32,
                         request_base=3, count=1)
    with pytest.raises(RadioConfigurationError, match="mode"):
        _read(legacy, stream)
    assert not legacy.context.timeouts
    legacy.close()


def test_bounded_refill_guards_other_public_io_but_releases_for_joined_cleanup() -> None:
    client, made = _setup()
    _open(client, "map")
    entered = threading.Event()
    release = threading.Event()
    outcome: list[Any] = []

    def hold() -> None:
        entered.set()
        assert release.wait(2)

    made[0].on_refill = hold

    def read() -> None:
        try:
            outcome.append(client.read_map_batch())
        except BaseException as error:
            outcome.append(error)

    worker = threading.Thread(target=read)
    worker.start()
    try:
        assert entered.wait(2)
        for operation in (client.close_maps, client.read_acquisition_health, client.read_map_batch):
            with pytest.raises(RadioConfigurationError, match="in flight"):
                operation()
        with pytest.raises(RadioConfigurationError, match="in-flight"):
            client.close_gracefully(readers_joined=True)
        assert not made[0].closed
    finally:
        release.set()
        worker.join(2)
    assert not worker.is_alive() and len(outcome) == 1 and isinstance(outcome[0], PssBatchReceipt)
    _cleanup(client, made)


def test_an_existing_legacy_operation_prevents_batch_timeout_race() -> None:
    client, made = _setup()
    with client._operation_lock:
        client._active_operations = 1  # Another public operation already entered.
    try:
        with pytest.raises(RadioConfigurationError, match="other PSS operations"):
            _open(client, "map")
        assert not made and not client.context.timeouts
    finally:
        with client._operation_lock:
            client._active_operations = 0
    _cleanup(client, made)


def test_middecode_interrupt_retains_full_raw_and_earlier_diagnostics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, made = _setup()
    _open(client, "fine")
    original = PssFinePacket.decode

    def interrupt(payload: bytes, *, rate_msps: int) -> PssFinePacket:
        if struct.unpack_from("<I", payload, 8)[0] == 4:
            raise KeyboardInterrupt("middecode")
        return original(payload, rate_msps=rate_msps)

    monkeypatch.setattr(PssFinePacket, "decode", interrupt)
    with pytest.raises(KeyboardInterrupt) as caught:
        client.read_fine_batch()
    receipt = caught.value.pss_batch_receipt
    assert receipt.raw == made[0].payload and not receipt.complete
    assert receipt.scans[0].decoded.request_id == 3
    assert len(receipt.scans) == 2 and receipt.scans[1].errors
    assert client._expected_request == 3 and client._remaining_results == 4
    with pytest.raises(RadioConfigurationError, match="failed"):
        client.read_fine_batch()
    _cleanup(client, made)


def test_receipt_finalization_interrupt_retains_raw_receipt_and_decoded_scans(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, made = _setup()
    _open(client, "fine")

    def interrupt(*args: Any, **kwargs: Any) -> Any:
        raise KeyboardInterrupt("receipt replacement")

    monkeypatch.setattr(pss_iio, "replace", interrupt)
    with pytest.raises(KeyboardInterrupt) as caught:
        client.read_fine_batch()
    assert caught.value.pss_batch_receipt.raw == made[0].payload
    assert not caught.value.pss_batch_receipt.complete
    assert len(caught.value.pss_batch_scans) == 4
    assert client._expected_request == 3
    _cleanup(client, made)


@pytest.mark.parametrize("stream", ("map", "fine"))
@pytest.mark.parametrize("field,value", (("byte_length", 99), ("step", 1), ("_samples_count", 99)))
def test_failed_open_geometry_destroys_once_without_native_cancel(
    stream: str, field: str, value: int,
) -> None:
    client, made = _setup()
    constructor = client._iio.Buffer

    def bad_buffer(device: _Device, count: int, cyclic: bool) -> _BatchBuffer:
        buffer = constructor(device, count, cyclic)
        setattr(buffer, field, value)
        return buffer

    client._iio.Buffer = bad_buffer
    with pytest.raises(RadioConfigurationError, match="mismatch"):
        _open(client, stream)
    assert len(made) == 1 and made[0].close_count == 1 and not made[0].cancelled
    assert not client._batch_io_active and not client._active_operations
    _cleanup(client, made)


@pytest.mark.parametrize("stream", ("map", "fine"))
def test_exact_scan_cap_fits_native_buffer(stream: str) -> None:
    client, made = _setup()
    if stream == "map":
        client.open_maps(refill_chunks=PSS_MAX_BATCH_SCANS, batch_mode=True)
    else:
        client.open_fine(first_center=1_000_000, period_q32_32=80_000 << 32,
                         request_base=3, count=PSS_MAX_BATCH_SCANS,
                         refill_results=PSS_MAX_BATCH_SCANS, batch_mode=True)
    receipt = _read(client, stream)
    assert receipt.complete and receipt.complete_scans == PSS_MAX_BATCH_SCANS
    assert len(receipt.raw) == PSS_MAX_BATCH_SCANS * made[0].step <= PSS_MAX_BATCH_BYTES
    _cleanup(client, made)


@pytest.mark.parametrize("stream", ("map", "fine"))
def test_byte_cap_is_checked_independently_before_allocation(
    stream: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, made = _setup()
    monkeypatch.setattr(pss_iio, "PSS_MAX_BATCH_BYTES", 511)
    with pytest.raises(ValueError, match="byte cap"):
        _open(client, stream)
    assert not made and not client.context.timeouts
    _cleanup(client, made)


@pytest.mark.parametrize("stream", ("map", "fine"))
def test_invalid_read_timeout_has_no_observation_or_counter_side_effect(stream: str) -> None:
    client, made = _setup()
    _open(client, stream)
    timeouts = list(client.context.timeouts)
    with pytest.raises(ValueError, match="timeout"):
        _read(client, stream, timeout_ms=0)
    assert not made[0].refills and client.context.timeouts == timeouts
    assert _read(client, stream).batch_index == 0
    _cleanup(client, made)


@pytest.mark.parametrize("remaining", (1, 2, 0))
def test_fine_wrap_is_allowed_only_after_last_finite_result(remaining: int) -> None:
    client, made = _setup()
    client.open_fine(first_center=1_000_000, period_q32_32=80_000 << 32,
                     request_base=0xffffffff, count=remaining, refill_results=1, batch_mode=True)
    made[0].payload = _fine_scan(request=0xffffffff)
    if remaining == 1:
        assert client.read_fine_batch().complete
        assert client._expected_request == 0 and client._remaining_results == 0
    else:
        with pytest.raises(PssBatchError, match="wrap") as caught:
            client.read_fine_batch()
        assert caught.value.receipt.raw == made[0].payload
        assert client._expected_request == 0xffffffff
    _cleanup(client, made)


def test_late_fault_and_malformed_scan_are_both_retained() -> None:
    client, made = _setup()
    _open(client, "map")
    raw = bytearray(made[0].payload)
    raw[PSS_MAP_SCAN_BYTES] ^= 0xff
    made[0].payload = bytes(raw)
    made[0].on_refill = lambda: setattr(client.phase_map.attrs["fault_flags"], "value", "4")
    with pytest.raises(PssBatchError) as caught:
        client.read_map_batch()
    receipt = caught.value.receipt
    assert receipt.raw == bytes(raw)
    assert receipt.attributes_after.fault_flags == 4 and receipt.scans[1].errors
    assert receipt.scans[2].decoded is not None
    _cleanup(client, made)


def test_raw_survives_the_callers_subsequent_reassembler_failure() -> None:
    client, made = _setup()
    _open(client, "map")
    raw = bytearray(made[0].payload)
    raw[50 * PSS_MAP_SCAN_BYTES:51 * PSS_MAP_SCAN_BYTES] = _map_scan(52)
    made[0].payload = bytes(raw)
    receipt = client.read_map_batch()
    assert receipt.complete  # Wire-level batch, NOT map continuity qualification.
    reassembler = PssMapReassembler()
    with pytest.raises(ValueError, match="missing"):
        for scan in receipt.scans:
            reassembler.add(scan.decoded)
    assert not reassembler._chunks and receipt.raw == bytes(raw)
    assert len(receipt.scans) == 200
    _cleanup(client, made)


def test_raw_receipt_exists_before_any_scan_is_decoded(monkeypatch: pytest.MonkeyPatch) -> None:
    client, made = _setup()
    _open(client, "fine")
    raw_receipts: list[PssBatchReceipt] = []
    original_constructor = PssBatchReceipt
    original_decoder = client._decode_batch_scans

    def constructor(**kwargs: Any) -> PssBatchReceipt:
        receipt = original_constructor(**kwargs)
        raw_receipts.append(receipt)
        return receipt

    def decode(*args: Any, **kwargs: Any) -> Any:
        assert len(raw_receipts) == 1 and raw_receipts[0].raw == made[0].payload
        assert not raw_receipts[0].scans and not raw_receipts[0].complete
        return original_decoder(*args, **kwargs)

    monkeypatch.setattr(pss_iio, "PssBatchReceipt", constructor)
    monkeypatch.setattr(client, "_decode_batch_scans", decode)
    assert client.read_fine_batch().complete
    _cleanup(client, made)


def test_raw_receipt_constructor_failure_still_retains_bytes_and_poisoned_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, made = _setup()
    _open(client, "fine")

    def interrupt(**kwargs: Any) -> Any:
        raise KeyboardInterrupt("raw receipt construction")

    monkeypatch.setattr(pss_iio, "PssBatchReceipt", interrupt)
    with pytest.raises(KeyboardInterrupt) as caught:
        client.read_fine_batch()
    assert caught.value.pss_batch_raw == made[0].payload
    assert client._batch_streams["fine"].failed
    assert client._expected_request == 3 and client._remaining_results == 4
    _cleanup(client, made)


@pytest.mark.parametrize("kind", (
    "raw-only", "missing", "duplicate", "index", "offset", "stride", "undecoded", "error",
))
def test_complete_requires_exact_decoded_scan_coverage(kind: str) -> None:
    client, made = _setup()
    _open(client, "fine")
    receipt = client.read_fine_batch()
    assert receipt.complete
    scans = list(receipt.scans)
    if kind == "raw-only":
        scans = []
    elif kind == "missing":
        scans.pop()
    elif kind == "duplicate":
        scans[1] = scans[0]
    else:
        changes = {
            "index": {"index": 9}, "offset": {"byte_offset": 0},
            "stride": {"byte_count": PSS_TRACK_SCAN_BYTES - 1},
            "undecoded": {"decoded": None}, "error": {"errors": ("not admitted",)},
        }
        scans[1] = replace(scans[1], **changes[kind])
    incomplete = replace(receipt, scans=tuple(scans))
    assert not incomplete.complete
    assert incomplete.raw == receipt.raw and incomplete.raw_retention_complete
    _cleanup(client, made)


def _pause_admission(
    client: PssIioClient, monkeypatch: pytest.MonkeyPatch, operation: Callable[[], Any],
) -> tuple[threading.Thread, threading.Event, list[Any]]:
    """Pause after public-operation entry but before exclusive mutable-state admission."""
    entered = threading.Event()
    release = threading.Event()
    outcomes: list[Any] = []
    original = client._exclusive_batch_io

    @contextmanager
    def pause() -> Iterator[None]:
        entered.set()
        assert release.wait(2), "test admission was not released"
        with original():
            yield

    monkeypatch.setattr(client, "_exclusive_batch_io", pause)

    def run() -> None:
        try:
            outcomes.append(operation())
        except BaseException as error:
            outcomes.append(error)

    worker = threading.Thread(target=run)
    worker.start()
    assert entered.wait(2), "worker never reached admission"
    return worker, release, outcomes


@pytest.mark.parametrize("stream", ("map", "fine"))
@pytest.mark.parametrize("close_context", (False, True))
def test_close_completed_before_admission_cannot_read_destroyed_cached_buffer(
    stream: str, close_context: bool, monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, made = _setup()
    _open(client, stream)
    prior_timeouts = list(client.context.timeouts)
    worker, release, outcomes = _pause_admission(client, monkeypatch, lambda: _read(client, stream))
    try:
        if close_context:
            client.close()
        elif stream == "map":
            client.close_maps()
        else:
            client.close_fine()
        assert made[0].closed and made[0].close_count == 1
    finally:
        release.set()
        worker.join(2)
    assert not worker.is_alive() and len(outcomes) == 1
    assert isinstance(outcomes[0], RadioConfigurationError)
    assert ("closed" if close_context else "not open") in str(outcomes[0])
    assert made[0].refills == made[0].reads == 0
    assert client.context.timeouts == prior_timeouts
    assert not client._active_operations and not client._batch_io_active
    # The competing operation was deliberately LEGACY close; its existing
    # native-cancel policy is not exercised by the new reader or changed here.
    client.close()
    assert made[0].close_count == 1 and client.context.close_count == 1


@pytest.mark.parametrize("stream", ("map", "fine"))
def test_competing_open_completed_before_admission_is_rechecked(
    stream: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, made = _setup()
    client.context.set_timeout(1000)  # Legacy opener's caller-owned timeout.
    worker, release, outcomes = _pause_admission(client, monkeypatch, lambda: _open(client, stream))
    try:
        if stream == "map":
            client.open_maps(refill_chunks=200)
        else:
            client.open_fine(first_center=1_000_000, period_q32_32=80_000 << 32,
                             request_base=3, count=4, refill_results=4)
        assert len(made) == 1
    finally:
        release.set()
        worker.join(2)
    assert not worker.is_alive() and len(outcomes) == 1
    assert isinstance(outcomes[0], RadioConfigurationError) and "already open" in str(outcomes[0])
    assert len(made) == 1 and not client._batch_streams[stream].batch_mode
    assert not client._active_operations and not client._batch_io_active
    client.close()
    assert made[0].close_count == 1


@pytest.mark.parametrize("stream", ("map", "fine"))
def test_context_closed_before_batch_open_admission_cannot_allocate(
    stream: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, made = _setup()
    worker, release, outcomes = _pause_admission(client, monkeypatch, lambda: _open(client, stream))
    try:
        client.close()
    finally:
        release.set()
        worker.join(2)
    assert not worker.is_alive() and len(outcomes) == 1
    assert isinstance(outcomes[0], RadioConfigurationError) and "closed" in str(outcomes[0])
    assert not made and not client.context.timeouts
    assert not client._active_operations and not client._batch_io_active
    assert client.context.close_count == 1


def test_completion_traversal_interrupt_retains_all_decoded_scans_and_poisoned_stream(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, made = _setup()
    _open(client, "fine")

    def interrupt_complete(receipt: PssBatchReceipt) -> bool:
        assert len(receipt.scans) == 4
        raise KeyboardInterrupt("completeness traversal")

    with monkeypatch.context() as patch:
        patch.setattr(PssBatchReceipt, "complete", property(interrupt_complete))
        with pytest.raises(KeyboardInterrupt) as caught:
            client.read_fine_batch()
    receipt = caught.value.pss_batch_receipt
    assert not receipt.complete and receipt.raw == made[0].payload and len(receipt.scans) == 4
    assert all(scan.decoded is not None for scan in receipt.scans)
    assert client._batch_streams["fine"].failed
    assert client._expected_request == 3 and client._remaining_results == 4
    with pytest.raises(RadioConfigurationError, match="failed"):
        client.read_fine_batch()
    _cleanup(client, made)


def test_interrupted_ledger_commit_cannot_resume_half_updated_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, made = _setup()
    _open(client, "fine")
    original = PssIioClient.__setattr__

    def interrupt_commit(self: PssIioClient, name: str, value: Any) -> None:
        if self is client and name == "_remaining_results" and value == 0:
            raise KeyboardInterrupt("second ledger update")
        original(self, name, value)

    with monkeypatch.context() as patch:
        patch.setattr(PssIioClient, "__setattr__", interrupt_commit)
        with pytest.raises(KeyboardInterrupt) as caught:
            client.read_fine_batch()
    receipt = caught.value.pss_batch_receipt
    assert not receipt.complete and len(receipt.scans) == 4 and receipt.raw == made[0].payload
    assert receipt.expected_request_before == 3 and receipt.remaining_results_before == 4
    assert client._expected_request == 7 and client._remaining_results == 4  # No invented rollback.
    assert client._batch_streams["fine"].failed
    with pytest.raises(RadioConfigurationError, match="failed"):
        client.read_fine_batch()
    _cleanup(client, made)


@pytest.mark.parametrize("stream", ("map", "fine"))
def test_identity_failure_precedes_native_allocation(
    stream: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, made = _setup()

    def interrupt_uuid() -> Any:
        raise KeyboardInterrupt("stream identity")

    monkeypatch.setattr(pss_iio, "uuid4", interrupt_uuid)
    with pytest.raises(KeyboardInterrupt):
        _open(client, stream)
    assert not made and not client._batch_streams
    assert client.tracker.attrs["schedule_enable"].value == "0"
    assert client.phase_map.attrs["acquisition_flush"].value == "0"
    assert not client._map_session_consumed
    assert not client._active_operations and not client._batch_io_active
    _cleanup(client, made)


@pytest.mark.parametrize("stream", ("map", "fine"))
def test_registration_failure_after_allocation_still_destroys_owned_buffer(
    stream: str,
) -> None:
    client, made = _setup()

    class InterruptedRegistry(dict):
        def __setitem__(self, key: Any, value: Any) -> None:
            raise KeyboardInterrupt("stream registration")

    client._batch_streams = InterruptedRegistry()
    with pytest.raises(KeyboardInterrupt):
        _open(client, stream)
    assert len(made) == 1 and made[0].close_count == 1 and not made[0].cancelled
    assert not client._batch_streams
    assert not client._active_operations and not client._batch_io_active
    _cleanup(client, made)


@pytest.mark.parametrize("stream", ("map", "fine"))
@pytest.mark.parametrize("failure", ("disable", "destroy-open", "destroy-closed", "both"))
def test_uncertain_failed_open_cleanup_quarantines_context_without_destroy_retry(
    stream: str, failure: str,
) -> None:
    client, made = _setup()
    device = client.tracker if stream == "fine" else client.phase_map
    enable = "schedule_enable" if stream == "fine" else "acquisition_enable"
    constructor = client._iio.Buffer

    class UncertainDisable:
        @property
        def value(self) -> str:
            return "0"

        @value.setter
        def value(self, value: str) -> None:
            raise OSError("disable was not acknowledged")

    def bad_buffer(device: _Device, count: int, cyclic: bool) -> _BatchBuffer:
        buffer = constructor(device, count, cyclic)
        buffer.byte_length = 99  # Primary open-admission failure, before enable.

        def uncertain_destroy() -> None:
            buffer.close_count += 1
            buffer.closed = failure == "destroy-closed"
            raise OSError("destruction was not acknowledged")

        if failure != "disable":
            buffer.close = uncertain_destroy
        return buffer

    client._iio.Buffer = bad_buffer
    if failure in ("disable", "both"):
        device.attrs[enable] = UncertainDisable()
    with pytest.raises(RadioConfigurationError, match="mismatch") as caught:
        _open(client, stream)
    assert client._batch_cleanup_errors and caught.value.__notes__
    assert len(made) == 1 and made[0].close_count == 1 and not made[0].cancelled
    client._iio.Buffer = constructor  # A working constructor must NOT permit reuse.

    def legacy_open() -> None:
        if stream == "map":
            client.open_maps()
        else:
            client.open_fine(first_center=1_000_000, period_q32_32=80_000 << 32,
                             request_base=9, count=1)

    prior_timeouts = list(client.context.timeouts)
    for operation in (lambda: _open(client, stream), legacy_open,
                      lambda: _read(client, stream), client.read_fine,
                      client.read_map_chunks, client.read_acquisition_health,
                      client.close_fine, client.close_maps, client.close):
        with pytest.raises(RadioConfigurationError, match="unverified.*joined graceful"):
            operation()
    assert len(made) == 1 and client.context.timeouts == prior_timeouts
    assert not client._active_operations and not client._batch_io_active
    _install_health(client.phase_map, _health_line(abi=client.map_abi_version),
                    _health_line(abi=client.map_abi_version, generation=9))
    with pytest.raises(PssGracefulCloseError) as cleanup:
        client.close_gracefully(readers_joined=True)
    assert any("unverified" in error for error in cleanup.value.receipt.errors)
    assert made[0].close_count == 1 and client.context.close_count == 1
    with pytest.raises(PssGracefulCloseError) as repeat:
        client.close_gracefully(readers_joined=True)
    assert repeat.value.receipt is cleanup.value.receipt
    assert made[0].close_count == 1 and client.context.close_count == 1
