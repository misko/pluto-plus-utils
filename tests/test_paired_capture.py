"""Concurrent real-client/fake-IIO tests, never a radio or DMA qualification."""

from __future__ import annotations

import hashlib
import json
import queue
import struct
import threading
import time
from dataclasses import replace
from types import SimpleNamespace

import pytest
from test_fine_schedule import _bytes, _packet
from test_pilot_iio_client import SERIAL, _connect, _setup
from test_pss_iio import _health_line, _map_scan
from test_pss_stop import encode, words
from test_pss_stop_control import OBS as OLD_OBS
from test_pss_stop_control import _Harness

from pluto_plus.hardware import paired_capture as paired
from pluto_plus.hardware.pss_iio import PssAcquisitionHealth, PssMapChunk, PssPhaseMap
from pluto_plus.hardware.pss_stop import PssMapStopReceipt

OBS = replace(OLD_OBS, serial=SERIAL, boot_id="boot-a", visit_id=17)
PLAN = paired.PairedFinePlan(4_000_000, 20_000 << 32, 3, 768, 7)


class Attr:
    def __init__(self, getter, setter=None):
        self.getter, self.setter = getter, setter

    @property
    def value(self):
        return self.getter()

    @value.setter
    def value(self, value):
        assert self.setter is not None
        self.setter(value)


class NativeHarness:
    """Use unmodified pilot/map/fine public APIs over deterministic native doubles.

    Fake counters represent source coordinates, not measured wall-clock rates.
    Only the native binding/device boundary is simulated; no recorder, receipt,
    decoder, schedule validator, durability or qualification helper is bypassed.
    """

    def __init__(self, *, fault=None):
        self.fault = fault
        self.map_h, self.fine_h = _Harness(), _Harness()
        self.maps, self.fine = self.map_h.client, self.fine_h.client
        self.device, self.context, self.module = _setup()
        self.pilot = _connect(self.module, expected_boot_id=OBS.boot_id)
        self.generation = 0
        self.delivered = self.read_count = self.fine_count = 0
        self.stop_ticket = 0
        self.terminal_count = 0
        self.opened = False
        self.fine_started = threading.Event()
        self.pilot_started = threading.Event()
        self.map_native_reads = []
        self.owner_calls = 0
        self.close_calls = 0
        for harness in (self.map_h, self.fine_h):
            harness.client.context.attrs = {"hw_serial": OBS.serial, "boot_id": OBS.boot_id}
            harness.fine.attr("packets_delivered").text = "0"
            harness.fine.attr("schedule_submitted").text = "0"
            harness.client.phase_map.attrs["acquisition_health"] = Attr(self.health)
        self.maps.phase_map.attrs["acquisition_stop"] = Attr(self.stop_receipt)
        self.maps.phase_map.attrs["acquisition_stop_request"] = Attr(
            lambda: str(self.stop_ticket), self.request_stop)
        self.maps.phase_map.attrs["maps_delivered"] = Attr(lambda: str(self.delivered))

        old_map_buffer = self.maps._iio.Buffer

        def map_buffer(device, count, cyclic):
            assert count == 200 and not self.pilot_started.is_set()
            buffer = old_map_buffer(device, count, cyclic)
            self.opened = True

            def refill():
                self.map_native_reads.append((self.delivered, self.read_count))
                assert self.delivered > self.read_count
                if self.fault == "map_read":
                    raise OSError("injected map transport disconnect")
                self.read_count += 1
                generation = self.read_count
                start = (generation - 1) * paired._MAP_SPAN
                raw = bytearray(b"".join(_map_scan(index, generation=generation, start=start)
                                         for index in range(200)))
                for offset in range(0, len(raw), 256):
                    struct.pack_into("<I", raw, offset + 4, 0x10006)
                if self.fault == "partial_map":
                    raw = raw[:-9]
                buffer.payload = bytes(raw)

            buffer.on_refill = refill
            return buffer

        self.maps._iio = SimpleNamespace(Buffer=map_buffer)
        old_fine_buffer = self.fine._iio.Buffer

        def fine_buffer(device, count, cyclic):
            assert count == 16 and self.pilot_started.is_set()
            buffer = old_fine_buffer(device, count, cyclic)

            def refill():
                first = int(device.attrs["schedule_first_center"].value)
                period = int(device.attrs["schedule_period_q32_32"].value)
                base = int(device.attrs["schedule_request_base"].value)
                packets = [_packet(base + self.fine_count + index,
                                   first + (((self.fine_count + index) * period) >> 32))
                           for index in range(count)]
                raw = b"".join(_bytes(packet) for packet in packets)
                if self.fault == "fine_corruption":
                    raw = raw[:-1] + b"x"
                buffer.payload = raw
                self.fine_count += count
                self.fine_h.fine.attr("packets_delivered").text = str(self.fine_count)
                self.fine_h.fine.attr("schedule_submitted").text = str(self.fine_count)

            buffer.on_refill = refill
            return buffer

        self.fine._iio = SimpleNamespace(Buffer=fine_buffer)

        def fine_write(name, value):
            if name == "schedule_enable" and value == "1":
                self.fine_started.set()

        self.fine_h.fine.on_write = fine_write

        def pilot_buffer(buffer):
            assert self.opened
            self.pilot_started.set()

            def refill():
                # This native double has no DMA clock. Pace it by consumer
                # progress, so slow CI disks/CPython versions do not turn a
                # successful finite-envelope test into a queue-overflow test.
                # Explicit queue.Full injection below still tests that failure.
                deadline = time.monotonic() + 5
                while self.progress_events.qsize() > 4 and not self.capture_cancelled.is_set():
                    assert time.monotonic() < deadline, "fake DMA consumer stopped progressing"
                    self.capture_cancelled.wait(0.001)
                self.capture_cancelled.wait(0.01)
                if self.fault == "pilot_short":
                    buffer.read_delta = -4

            buffer.on_refill = refill

        self.module.configure = pilot_buffer
        self.backend = paired.NativePairedBackend(self.pilot, self.maps, self.fine)
        native_capture = self.backend.capture_pilot

        def capture_pilot(observation, events, cancelled):
            self.progress_events = events
            self.capture_cancelled = cancelled
            return native_capture(observation, events, cancelled)

        self.backend.capture_pilot = capture_pilot

    def health(self):
        self.generation += 1
        if self.fine_started.is_set() and not self.stop_ticket:
            self.delivered = min(self.read_count + 1, 40)
        if self.stop_ticket:
            self.delivered = self.terminal_count
        active = int(self.maps.phase_map.attrs["acquisition_enable"].value)
        lifecycle = 5 if self.maps._map_buffer is not None else 0
        changes = {5: lifecycle | (2 if active and not self.stop_ticket else 0),
                   7: self.delivered, 8: self.delivered * 200}
        if self.fault == "health" and self.pilot_started.is_set():
            changes[24] = 1 << 13
        if self.fault == "late_health" and self.pilot._closed:
            changes[24] = 1 << 14
        return _health_line(abi=0x10005, generation=self.generation, changes=changes).replace(
            "00010005", "00010006", 1)

    def request_stop(self, value):
        assert value == "1" and not self.stop_ticket
        self.stop_ticket = 1
        self.terminal_count = self.delivered
        self.maps.phase_map.attrs["acquisition_enable"].value = "0"

    def stop_receipt(self):
        if self.stop_ticket:
            return encode(words(start=(self.terminal_count - 1) * paired._MAP_SPAN,
                                generation=self.terminal_count, ticket=1))
        return encode([0x50535354, 0x1000c, 32 if self.opened else 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

    def attest(self):
        self.owner_calls += 1
        if self.fault == "owner_after" and self.owner_calls > 1:
            raise ValueError("external boot changed during cleanup")
        return paired.PairedAttestation(
            OBS, b"offline fake owner evidence; not hardware attestation")

    def recorder(self):
        return paired.FinitePairedRecorder(self.backend, OBS, PLAN, self.attest)

    def assert_closed(self):
        assert self.context.closes == 1
        for harness in (self.map_h, self.fine_h):
            assert harness.client.context.close_count == 1
            assert all(buffer.close_count == 1 and not buffer.cancelled for buffer in harness.made)
        assert all(buffer.closes == 1 and buffer.cancels == 0 for buffer in self.module.buffers)


def test_real_public_clients_concurrently_record_and_reconcile_full_finite_envelope(tmp_path):
    radio = NativeHarness()
    recorder = radio.recorder()
    receipt = recorder.record(tmp_path / "paired")
    assert receipt.finite_transport_complete and receipt.cleanup_complete
    assert receipt.pilot_bytes_received == 20_000_000
    assert receipt.fine_results_received == 768 and receipt.maps_received >= 16
    assert receipt.common_support.samples >= 15_000_000
    assert not receipt.rf_or_lock_qualified and not receipt.persistent_30_300_second_qualified
    assert radio.owner_calls == 2
    assert all(delivered > read for delivered, read in radio.map_native_reads)
    radio.assert_closed()
    final = json.loads((receipt.output / receipt.final_artifact["path"]).read_text())
    assert final["status"] == "FINITE_PAIRED_TRANSPORT_COMPLETE"
    raw_files = sorted(receipt.output.glob("*-pilot-progress-iq.bin"))
    assert len(raw_files) == 200
    for metadata in receipt.output.glob("*.json"):
        json.loads(metadata.read_text())
    for marker in receipt.output.glob("*-map-raw-batch.json"):
        document = json.loads(marker.read_text())
        artifact = document["raw"]["artifact"]
        raw = (receipt.output / artifact["path"]).read_bytes()
        assert len(raw) == artifact["bytes"] == 51200
        assert hashlib.sha256(raw).hexdigest() == artifact["sha256"]
    with pytest.raises(ValueError, match="already used"):
        recorder.record(tmp_path / "again")


@pytest.mark.parametrize("fault", ["health", "map_read", "partial_map", "fine_corruption",
                                  "pilot_short", "owner_after"])
def test_failed_native_paths_retain_evidence_and_join_before_destroy(tmp_path, fault):
    radio = NativeHarness(fault=fault)
    with pytest.raises(paired.PairedCaptureError) as error:
        radio.recorder().record(tmp_path / fault)
    receipt = error.value.receipt
    assert not receipt.finite_transport_complete and receipt.errors
    assert not receipt.unjoined_workers
    radio.assert_closed()
    assert list(receipt.output.glob("*-failure.json"))
    if fault == "partial_map":
        failures = list(receipt.output.glob("*-maps-failure-receipt-raw.bin"))
        assert len(failures) == 1 and failures[0].stat().st_size == 51200 - 9


@pytest.mark.parametrize(("field", "value"), [
    ("count", 767), ("count", 1040), ("request_base", 0xffffffff),
    ("first_center_offset", 1), ("first_center_offset", 29_000_000),
    ("period_q32_32", 1), ("coefficient_generation", 1 << 32),
])
def test_invalid_fine_geometry_is_rejected_without_io(field, value):
    with pytest.raises(ValueError):
        replace(PLAN, **{field: value})


def test_journal_new_directory_raw_hash_and_no_overwrite(tmp_path):
    journal = paired._Journal(tmp_path / "new")
    receipt = journal.put("raw", {"raw": b"\0\xff", "negative": True})
    encoded = json.loads((journal.path / receipt["path"]).read_text())
    artifact = encoded["raw"]["artifact"]
    assert (journal.path / artifact["path"]).read_bytes() == b"\0\xff"
    assert artifact["sha256"] == hashlib.sha256(b"\0\xff").hexdigest()
    with pytest.raises(FileExistsError):
        paired._Journal(journal.path)
    with pytest.raises(ValueError):
        journal._file("../not-owned", b"bad")
    assert not (tmp_path / "not-owned").exists()


def test_disk_failure_is_sticky_and_cannot_claim_durability(tmp_path, monkeypatch):
    journal = paired._Journal(tmp_path / "disk")
    monkeypatch.setattr(paired.os, "fsync", lambda _fd: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(OSError, match="disk full"):
        journal.put("partial", {"raw": b"retained partial artifact"})
    assert journal.failed
    with pytest.raises(OSError, match="quarantined"):
        journal.put("later", {"success": True})


def test_unjoined_worker_retains_context_ownership_without_destroy():
    closed = []
    backend = SimpleNamespace(close=lambda: closed.append(True) or ())
    recorder = paired.FinitePairedRecorder(backend, OBS, PLAN,
                                         lambda: paired.PairedAttestation(OBS, b"external"))
    release = threading.Event()
    worker = threading.Thread(target=release.wait, daemon=True)
    recorder._threads.append(worker)
    worker.start()
    try:
        with pytest.raises(RuntimeError, match="no context was destroyed"):
            recorder.join_and_close(timeout_seconds=0.01)
        assert closed == []
    finally:
        release.set()
        worker.join(1)
    recorder.join_and_close()
    recorder.join_and_close()
    assert closed == [True]


def terminal_fixture():
    maps = tuple(PssPhaseMap(0x10006, index + 1, 1000 + index * paired._MAP_SPAN,
                             (0,) * 20000) for index in range(3))
    stop = PssMapStopReceipt.decode(encode(words(start=maps[-1].start_index,
                                                generation=3, ticket=1)))
    health = PssAcquisitionHealth.decode(_health_line(
        abi=0x10005, changes={7: 3, 8: 600}).replace("00010005", "00010006", 1))
    return stop, health, maps


@pytest.mark.parametrize(("word", "value"), [(7, 2), (7, 4), (8, 599), (8, 601),
                                               (10, 1), (5, 2), (24, 1 << 14)])
def test_terminal_driver_publish_host_mismatch_rejected(word, value):
    stop, health, maps = terminal_fixture()
    paired.require_terminal_delivery(stop, health, maps)
    values = list(health.words)
    values[word] = value
    if word == 10:
        values[11] = 3
    corrupted = PssAcquisitionHealth.decode("PSMH 1 46 " + " ".join(f"{v:08x}" for v in values))
    with pytest.raises(ValueError):
        paired.require_terminal_delivery(stop, corrupted, maps)


def test_map_redecode_rejects_padding_and_decoded_alias(tmp_path):
    radio = NativeHarness()
    radio.backend.open_maps()
    radio.fine_started.set()
    radio.backend.read_health()
    batch = radio.backend.read_maps()
    phase_map = paired._map_from_batch(batch, index=0, stream_id=None)
    assert phase_map.generation == 1
    altered = replace(batch, raw=batch.raw[:-1] + b"x")
    with pytest.raises(ValueError, match="padding"):
        paired._map_from_batch(altered, index=0, stream_id=None)
    scans = list(batch.scans)
    assert isinstance(scans[0].decoded, PssMapChunk)
    scans[0] = replace(scans[0], decoded=replace(scans[0].decoded, generation=99))
    with pytest.raises(ValueError, match="retained raw"):
        paired._map_from_batch(replace(batch, scans=tuple(scans)), index=0, stream_id=None)
    radio.backend.close()
    radio.assert_closed()


def test_failed_cleanup_is_sticky_and_never_repeats_native_destruction():
    calls = []
    failure = RuntimeError("acknowledged CLOSE missing")

    def close():
        calls.append(True)
        raise failure

    recorder = paired.FinitePairedRecorder(SimpleNamespace(close=close), OBS, PLAN,
                                         lambda: paired.PairedAttestation(OBS, b"external"))
    for _ in range(2):
        with pytest.raises(RuntimeError) as caught:
            recorder.join_and_close()
        assert caught.value is failure
    assert calls == [True]


@pytest.mark.parametrize(("word", "value"),
                         [(2, bit) for bit in (1, 2, 4, 8, 16, 32)]
                         + [(index, 1) for index in range(3, 12)])
def test_unused_epoch_rejects_every_stale_stop_field_before_arm(tmp_path, word, value):
    radio = NativeHarness()
    raw = [0x50535354, 0x1000c] + [0] * 10
    raw[word] = value
    radio.maps.phase_map.attrs["acquisition_stop"] = Attr(lambda: encode(raw))
    with pytest.raises(paired.PairedCaptureError) as caught:
        radio.recorder().record(tmp_path / "stale")
    assert any("unused stop/map reset epoch" in error for error in caught.value.receipt.errors)
    assert not radio.opened and not radio.pilot_started.is_set()
    radio.assert_closed()


@pytest.mark.parametrize("phase", ["context_after", "owner_after"])
def test_late_external_cancellation_cannot_be_hidden_by_internal_cleanup(tmp_path, phase):
    radio = NativeHarness()
    recorder = radio.recorder()
    if phase == "context_after":
        original = radio.backend.attest
        calls = []

        def attest(observation):
            result = original(observation)
            calls.append(True)
            if len(calls) == 2:
                assert recorder.cancel()
            return result

        radio.backend.attest = attest
    else:
        original_owner = recorder.attest

        def owner():
            result = original_owner()
            if radio.owner_calls == 2:
                assert recorder.cancel()
            return result

        recorder.attest = owner
    with pytest.raises(paired.PairedCaptureError) as caught:
        recorder.record(tmp_path / phase)
    receipt = caught.value.receipt
    assert not receipt.finite_transport_complete and receipt.cleanup_complete
    assert any("external cancellation accepted" in error for error in receipt.errors)
    final = json.loads((receipt.output / receipt.final_artifact["path"]).read_text())
    assert final["status"] == "INCOMPLETE"
    assert not recorder.cancel()  # Terminal decision already sealed.
    radio.assert_closed()


@pytest.mark.parametrize("interrupt", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("phase", ["preflight", "map_worker"])
def test_process_control_exceptions_rethrow_after_receipted_cleanup(tmp_path, interrupt, phase):
    radio = NativeHarness()
    recorder = radio.recorder()
    failure = interrupt("deliberate process control")

    def raise_interrupt(*_args):
        raise failure

    if phase == "preflight":
        recorder.attest = raise_interrupt
    else:
        radio.backend.read_maps = raise_interrupt
    with pytest.raises(interrupt) as caught:
        recorder.record(tmp_path / phase)
    assert caught.value is failure
    receipt = failure.paired_capture_receipt
    assert not receipt.finite_transport_complete
    # Destruction must finish, but interrupted queued work (or an interrupted
    # final external attestation) must not acquire a qualified cleanup receipt.
    if not receipt.cleanup_complete:
        assert any(error.startswith("cleanup:") for error in receipt.errors)
    assert receipt.final_artifact and not receipt.unjoined_workers
    radio.assert_closed()


def test_storage_failure_during_live_workers_keeps_incomplete_receipt_and_closes(
        tmp_path, monkeypatch):
    radio = NativeHarness()
    write = paired._Journal._file

    def broken_write(journal, name, raw):
        if name.endswith("-pilot-progress-iq.bin"):
            assert radio.pilot_started.is_set()
            raise OSError("disk disconnected with producers active")
        return write(journal, name, raw)

    monkeypatch.setattr(paired._Journal, "_file", broken_write)
    with pytest.raises(paired.PairedCaptureError) as caught:
        radio.recorder().record(tmp_path / "disk-live")
    receipt = caught.value.receipt
    assert not receipt.finite_transport_complete and receipt.final_artifact is None
    assert any("disk disconnected" in error for error in receipt.errors)
    assert not receipt.unjoined_workers
    radio.assert_closed()


@pytest.mark.parametrize("fault", ["duplicate_arm", "orphan_iq", "queue_full"])
def test_invalid_pilot_progress_is_retained_and_never_qualifies(tmp_path, monkeypatch, fault):
    radio = NativeHarness()
    put = queue.Queue.put_nowait

    def progress(target, event):
        if fault == "duplicate_arm" and isinstance(event, paired.PilotArmedEvent):
            put(target, event)
        if fault == "orphan_iq" and isinstance(event, paired.PilotOriginEvent):
            return None  # First IQ now has no declared source origin.
        if fault == "queue_full" and isinstance(event, paired.PilotIqChunkEvent):
            raise queue.Full
        return put(target, event)

    monkeypatch.setattr(queue.Queue, "put_nowait", progress)
    with pytest.raises(paired.PairedCaptureError) as caught:
        radio.recorder().record(tmp_path / fault)
    assert not caught.value.receipt.finite_transport_complete
    assert not caught.value.receipt.unjoined_workers
    radio.assert_closed()


def test_fatal_health_stops_before_any_subsequent_full_map_refill(tmp_path):
    radio = NativeHarness(fault="health")
    with pytest.raises(paired.PairedCaptureError):
        radio.recorder().record(tmp_path / "health")
    assert radio.map_native_reads == []
    radio.assert_closed()


def test_late_map_terminal_health_fault_cannot_qualify(tmp_path):
    radio = NativeHarness()
    health = radio.backend.read_health

    def late_fault():
        result = health()
        if radio.stop_ticket:
            values = list(result.words)
            values[24] |= 1 << 14
            return PssAcquisitionHealth.decode("PSMH 1 46 " + " ".join(
                f"{value:08x}" for value in values))
        return result

    radio.backend.read_health = late_fault
    with pytest.raises(paired.PairedCaptureError) as caught:
        radio.recorder().record(tmp_path / "late-map-fault")
    assert not caught.value.receipt.finite_transport_complete
    radio.assert_closed()


@pytest.mark.parametrize(("index", "change"), [
    (0, {"generation": 2}), (1, {"generation": 0xffffffff}),
    (0, {"abi_version": 0x10005}), (1, {"start_index": 1}),
])
def test_terminal_ledger_checks_whole_prefix_not_just_last_map(index, change):
    stop, health, maps = terminal_fixture()
    corrupted = list(maps)
    corrupted[index] = replace(corrupted[index], **change)
    with pytest.raises(ValueError, match="generation/source prefix"):
        paired.require_terminal_delivery(stop, health, tuple(corrupted))
