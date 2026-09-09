"""Fake-IIO ABI1.6 operations: no radio, actual driver or RF qualification."""

from __future__ import annotations

import struct
import threading
from contextlib import suppress
from dataclasses import replace
from types import SimpleNamespace

import pytest
from test_fine_schedule import OBS as OLD_OBS
from test_fine_schedule import _batch, _manifest
from test_pss_control import _Harness as _FineHarness
from test_pss_iio import _Attr, _health_line, _install_health, _map_scan
from test_pss_stop import encode, words
from test_source_support import _map

from pluto_plus.errors import RadioConfigurationError
from pluto_plus.hardware import pss_iio, pss_stop_control
from pluto_plus.hardware.fine_schedule import FineScheduleLedger, validate_fine_batch
from pluto_plus.hardware.pss_control import PssWriteAcceptance
from pluto_plus.hardware.pss_iio import (
    PssAcquisitionHealth,
    PssGracefulCloseError,
    PssIioClient,
    PssMapChunk,
    PssMapReassembler,
)
from pluto_plus.hardware.pss_stop_control import (
    STOP_CONTRACT,
    PssMapStopOperation,
    PssMapStopOperationError,
)
from pluto_plus.hardware.source_support import ProcessingProfile, map_support

PROFILE = ProcessingProfile.PAIRED_15_SHARED_XFFT_512_447_STOP_V1
OBS = replace(OLD_OBS, profile=PROFILE)


def _idle(ticket=0):
    return [0x50535354, 0x0001000c, 32, ticket, 0, 0, 0, 0, 0, 0, 0, 0]


class _ObservedAttr:
    def __init__(self, owner, name, text):
        self.owner, self.name, self.text = owner, name, text

    @property
    def value(self):
        self.owner.calls.append(("read", self.name))
        if self.owner.on_call:
            self.owner.on_call("read", self.name)
        return self.text

    @value.setter
    def value(self, text):
        self.owner.calls.append(("write", self.name, text))
        if self.name == "acquisition_stop_request" and int(text) != self.owner.values[3]:
            self.owner.values[3] = int(text)
            self.owner.values[2] = 33  # Applied but pending, not a completed stop.
            self.owner.values[10:12] = [0, 0]
            self.owner.sync()
        if self.owner.on_call:
            self.owner.on_call("write", self.name)
        self.text = text


class _Harness:
    def __init__(self):
        self.fine = _FineHarness()
        old = self.fine.client
        old.phase_map.attrs.update({name: _Attr(value) for name, value in STOP_CONTRACT})
        self.client = PssIioClient(old.context, old._iio, experimental_shared_xfft=True,
                                   experimental_boundary_stop=True)
        self.fine.client = self.client
        self.made = self.fine.made
        self.client.context.attrs = {"hw_serial": OBS.serial, "boot_id": OBS.boot_id}
        self.calls = []
        self.on_call = None
        self.client.phase_map.attrs = {
            name: _ObservedAttr(self, name, attr.value)
            for name, attr in self.client.phase_map.attrs.items()
        }
        self.values = _idle()
        self.client.phase_map.attrs["acquisition_stop"] = _ObservedAttr(
            self, "acquisition_stop", "")
        self.client.phase_map.attrs["acquisition_stop_request"] = _ObservedAttr(
            self, "acquisition_stop_request", "0")
        self.sync()

    def attr(self, name):
        return self.client.phase_map.attrs[name]

    def sync(self):
        self.attr("acquisition_stop").text = encode(self.values)

    def cleanup(self):
        self.on_call = self.fine.on_read = self.fine.on_write = None
        lines = [_health_line(abi=0x10005, generation=g).replace("00010005", "00010006", 1)
                 for g in (8, 9)]
        _install_health(self.client.phase_map, *lines)
        with suppress(PssGracefulCloseError):
            self.client.close_gracefully(readers_joined=True)
        assert self.client.context.close_count == 1
        assert all(buffer.close_count == 1 and not buffer.cancelled for buffer in self.made)


def _receipt(error):
    return (error.receipt if isinstance(error, PssMapStopOperationError)
            else error.pss_stop_receipt)


def test_explicit_admission_does_not_change_legacy_defaults():
    assert pss_iio._map_contract(15, False) == (0x10001, 0x3f)
    assert pss_iio._map_contract(15, True) == (0x10005, 0x13f)
    assert pss_iio._map_contract(15, True, True) == (0x10006, 0x33f)
    radio = _Harness()
    for kwargs in ({}, {"experimental_shared_xfft": True}):
        with pytest.raises(RadioConfigurationError):
            PssIioClient(radio.client.context, radio.client._iio, **kwargs)
    radio.cleanup()


@pytest.mark.parametrize("shared,stop,rate", [
    (False, True, 15), (1, True, 15), (True, 1, 15), (True, None, 15),
    (True, True, 30), (True, True, 60),
])
def test_stop_optin_and_rate_are_exact(shared, stop, rate):
    with pytest.raises(ValueError):
        pss_iio._map_contract(rate, shared, stop)


@pytest.mark.parametrize("field,expected", STOP_CONTRACT)
@pytest.mark.parametrize("bit", range(32))
def test_every_contract_bit_is_exact_before_native_admission(field, expected, bit):
    radio = _Harness()
    radio.attr(field).text = str(expected ^ (1 << bit))
    with pytest.raises((RadioConfigurationError, ValueError)):
        PssIioClient(radio.client.context, radio.client._iio, experimental_shared_xfft=True,
                     experimental_boundary_stop=True)
    assert not radio.made
    radio.cleanup()


def test_constructor_timeout_precedes_all_contract_reads():
    radio = _Harness()
    radio.client.context.timeouts.clear()

    def assert_timeout(action, name):
        assert radio.client.context.timeouts == [1000]

    radio.on_call = assert_timeout
    PssIioClient(radio.client.context, radio.client._iio, experimental_shared_xfft=True,
                 experimental_boundary_stop=True)
    radio.cleanup()


def test_connect_requires_exact_serial_and_sets_timeout_before_metadata():
    radio = _Harness()
    context = radio.client.context
    context.timeouts.clear()
    module = SimpleNamespace(Context=lambda uri: context)
    with pytest.raises(ValueError):
        PssIioClient.connect("fake:", experimental_shared_xfft=True,
                             experimental_boundary_stop=True, iio_module=module)
    assert context.timeouts == []
    connected = PssIioClient.connect("fake:", expected_serial=OBS.serial,
                                     experimental_shared_xfft=True,
                                     experimental_boundary_stop=True, iio_module=module)
    assert context.timeouts[:2] == [1000, 1000]
    assert connected._stop_context_id != radio.client._stop_context_id
    radio.cleanup()


def test_fresh_idle_and_unchanged_reads_preserve_zero_without_qualifying_stop():
    radio = _Harness()
    raw = " \t" + encode(radio.values) + "\n"
    radio.attr("acquisition_stop").text = raw
    first = radio.client.read_map_stop(OBS)
    second = radio.client.read_map_stop(OBS)
    assert first.complete and second.complete and second.previous == first.after
    assert first.after.raw == raw and first.observed_accepted_ticket == 0
    assert first.write_acceptance is PssWriteAcceptance.NOT_ATTEMPTED
    assert first.context_id == second.context_id and len(first.context_id) == 36
    assert sum(name == "acquisition_stop" for _, name in radio.calls) == 2
    assert not radio.made and all(call[0] == "read" for call in radio.calls)
    with pytest.raises(ValueError):
        first.after.require_boundary_complete(expected_ticket=1)
    radio.cleanup()


def test_request_acknowledgment_is_not_terminal_completion_or_delivery():
    radio = _Harness()
    receipt = radio.client.request_map_stop(OBS, ticket=1)
    assert receipt.complete and receipt.before.accepted_ticket == 0
    assert receipt.after.accepted_ticket == 1 and receipt.after.pending
    assert receipt.write_acceptance is PssWriteAcceptance.ACKNOWLEDGED
    assert [call for call in radio.calls if call[0] == "write"] == [
        ("write", "acquisition_stop_request", "1")]
    assert not radio.made and not radio.client.context.close_count
    with pytest.raises(ValueError):
        receipt.after.require_boundary_complete(expected_ticket=1)
    radio.cleanup()


@pytest.mark.parametrize("ticket", [0, -1, 1 << 32, True, 1.0, "1", None])
def test_bad_tickets_are_rejected_before_native_io(ticket):
    radio = _Harness()
    radio.client.context.timeouts.clear()
    with pytest.raises(ValueError):
        radio.client.request_map_stop(OBS, ticket=ticket)
    assert not radio.calls and not radio.client.context.timeouts
    radio.cleanup()


@pytest.mark.parametrize("accepted,ticket,allowed", [(0, 2, False), (2, 1, False),
    (2, 2, True), (2, 3, True), (0xffffffff, 1, False), (0xffffffff, 0xffffffff, True)])
def test_next_or_idempotent_ticket_without_wrap(accepted, ticket, allowed):
    radio = _Harness()
    radio.values[3] = accepted
    radio.sync()
    if allowed:
        receipt = radio.client.request_map_stop(OBS, ticket=ticket)
        assert receipt.complete and receipt.observed_accepted_ticket == ticket
    else:
        with pytest.raises(PssMapStopOperationError) as caught:
            radio.client.request_map_stop(OBS, ticket=ticket)
        assert not caught.value.receipt.complete
        assert caught.value.receipt.write_acceptance is PssWriteAcceptance.NOT_ATTEMPTED
    radio.cleanup()


def test_expected_ticket_mismatch_retains_actual_readback():
    radio = _Harness()
    with pytest.raises(PssMapStopOperationError) as caught:
        radio.client.read_map_stop(OBS, expected_ticket=1)
    assert caught.value.receipt.after.raw == encode(radio.values)
    assert caught.value.receipt.observed_accepted_ticket == 0
    assert not caught.value.receipt.complete
    radio.cleanup()


@pytest.mark.parametrize("failure_type", [OSError, KeyboardInterrupt])
@pytest.mark.parametrize("call_index", range(1, 22))
def test_each_native_failure_or_interrupt_retains_bounded_evidence(call_index, failure_type):
    radio = _Harness()

    def fail(action, name):
        if len(radio.calls) == call_index:
            raise failure_type("injected native outcome lost")

    radio.on_call = fail
    error_type = PssMapStopOperationError if failure_type is OSError else KeyboardInterrupt
    with pytest.raises(error_type) as caught:
        radio.client.request_map_stop(OBS, ticket=1)
    receipt = _receipt(caught.value)
    assert not receipt.complete and receipt.errors and len(receipt.steps) <= 32
    step = next(step for step in receipt.steps if step.error)
    assert step.attempted and not step.returned
    if call_index == 11:  # Remote write applied but binding return was lost.
        assert receipt.write_acceptance is PssWriteAcceptance.UNKNOWN
        assert receipt.observed_accepted_ticket == (1 if failure_type is OSError else None)
    assert not radio.made and not radio.client.context.close_count
    assert not radio.client._active_operations and not radio.client._batch_io_active
    radio.cleanup()


@pytest.mark.parametrize("index,value", [(2, 64), (10, 64), (11, 6), (0, 0)])
def test_reserved_or_invalid_psst_retains_raw_without_fake_decoded_state(index, value):
    radio = _Harness()
    radio.values[index] = value
    radio.sync()
    with pytest.raises(PssMapStopOperationError) as caught:
        radio.client.read_map_stop(OBS)
    receipt = caught.value.receipt
    assert receipt.after is None and receipt.observed_accepted_ticket is None
    assert receipt.steps[-1].raw == encode(radio.values)
    assert receipt.steps[-1].returned
    radio.cleanup()


@pytest.mark.parametrize("raw", ["bad", "x" * 513, None, 0])
def test_malformed_or_oversized_raw_is_missing_not_zero(raw):
    radio = _Harness()
    radio.attr("acquisition_stop").text = raw
    with pytest.raises(PssMapStopOperationError) as caught:
        radio.client.read_map_stop(OBS)
    step = caught.value.receipt.steps[-1]
    assert step.returned and caught.value.receipt.after is None
    assert step.raw == (raw[:512] if isinstance(raw, str) else None)
    assert step.raw_characters == (len(raw) if isinstance(raw, str) else None)
    radio.cleanup()


def test_late_failed_status_is_a_complete_negative_observation_not_healthy_success():
    radio = _Harness()
    radio.values = words(ticket=1)
    radio.sync()
    first = radio.client.read_map_stop(OBS, expected_ticket=1)
    first.after.require_boundary_complete(expected_ticket=1)
    radio.values[2] |= 8
    radio.values[10] = 2
    radio.sync()
    failed = radio.client.read_map_stop(OBS, expected_ticket=1)
    assert failed.complete and failed.after.failed and failed.after.failure_reasons == 2
    assert failed.previous == first.after and failed.after.words[3:10] == first.after.words[3:10]
    with pytest.raises(ValueError):
        failed.after.require_boundary_complete(expected_ticket=1)
    radio.cleanup()


@pytest.mark.parametrize("mutation", ["reset", "tuple", "reason-cleared"])
def test_epoch_or_historical_tuple_contradiction_invalidates_context_stickily(mutation):
    radio = _Harness()
    radio.values = words(ticket=1)
    if mutation == "reason-cleared":
        radio.values[2] |= 8
        radio.values[10] = 2
    radio.sync()
    initial = radio.client.read_map_stop(OBS)
    if mutation == "reset":
        radio.values = _idle()
    elif mutation == "tuple":
        radio.values[5] += 1
    else:
        radio.values[10] = 0
    radio.sync()
    with pytest.raises(PssMapStopOperationError) as caught:
        radio.client.read_map_stop(OBS)
    assert caught.value.receipt.after.raw == encode(radio.values)
    assert radio.client._stop_epoch_invalid
    radio.attr("acquisition_stop").text = initial.after.raw
    with pytest.raises(PssMapStopOperationError):
        radio.client.request_map_stop(OBS, ticket=2)
    assert not any(call[0] == "write" for call in radio.calls)
    radio.cleanup()


@pytest.mark.parametrize("attrs", [{}, {"hw_serial": "wrong"},
    {"hw_serial": OBS.serial, "serial": "wrong"},
    {"hw_serial": OBS.serial, "boot_id": "wrong"}])
def test_identity_mismatch_stops_before_any_map_io(attrs):
    radio = _Harness()
    radio.client.context.attrs = attrs
    with pytest.raises(PssMapStopOperationError) as caught:
        radio.client.request_map_stop(OBS, ticket=1)
    assert not radio.calls and caught.value.receipt.context_identity
    assert caught.value.receipt.write_acceptance is PssWriteAcceptance.NOT_ATTEMPTED
    radio.cleanup()


def test_observation_binding_and_legacy_profile_cannot_be_silently_reused():
    radio = _Harness()
    with pytest.raises(ValueError):
        radio.client.read_map_stop(OLD_OBS)
    assert not radio.calls
    del radio.client.context.attrs["boot_id"]
    first = radio.client.read_map_stop(OBS)
    assert first.complete and dict(first.context_identity)["boot_id"] is None
    radio.calls.clear()
    with pytest.raises(PssMapStopOperationError):
        radio.client.read_map_stop(replace(OBS, visit_id=2))
    assert not radio.calls
    radio.cleanup()
    legacy = _FineHarness()
    with pytest.raises(ValueError, match="ABI1.6"):
        legacy.client.read_map_stop(OLD_OBS)
    legacy.cleanup()


@pytest.mark.parametrize("phase", ["contract_before", "contract_after"])
def test_contract_mismatch_retains_late_ack_and_readback(phase):
    radio = _Harness()

    def mutate(action, name):
        if phase == "contract_after" and action == "write":
            radio.attr("capabilities").text = "895"  # 0x33f plus reserved bit 6.

    radio.on_call = mutate
    if phase == "contract_before":
        radio.attr("capabilities").text = "895"
    with pytest.raises(PssMapStopOperationError) as caught:
        radio.client.request_map_stop(OBS, ticket=1)
    receipt = caught.value.receipt
    assert not receipt.complete
    assert receipt.write_acceptance is (PssWriteAcceptance.ACKNOWLEDGED
        if phase == "contract_after" else PssWriteAcceptance.NOT_ATTEMPTED)
    assert receipt.observed_accepted_ticket == (1 if phase == "contract_after" else None)
    assert receipt.steps[-1].raw == "895"
    radio.cleanup()


def test_timeout_setup_failure_retains_unattempted_step_and_never_destroys_context():
    radio = _Harness()
    setter = radio.client.context.set_timeout

    def fail(value):
        raise OSError("timeout setup failed")

    radio.client.context.set_timeout = fail
    with pytest.raises(PssMapStopOperationError) as caught:
        radio.client.read_map_stop(OBS)
    assert not caught.value.receipt.steps[0].attempted and not radio.calls
    assert not radio.client.context.close_count
    radio.client.context.set_timeout = setter
    radio.cleanup()


@pytest.mark.parametrize("where", ["last-read", "write", "qualification"])
def test_late_return_retains_raw_or_ack_but_fails_whole_operation(monkeypatch, where):
    radio = _Harness()
    now = [100.0]
    monkeypatch.setattr(pss_stop_control.time, "monotonic", lambda: now[0])

    def late(action, name):
        if ((where == "last-read" and len(radio.calls) == 21) or
                (where == "write" and action == "write")):
            now[0] += 10

    radio.on_call = late
    if where == "qualification":
        original = PssMapStopOperation.complete.fget

        def complete(receipt):
            result = original(receipt)
            now[0] += 10
            return result

        monkeypatch.setattr(PssMapStopOperation, "complete", property(complete))
    with pytest.raises(PssMapStopOperationError) as caught:
        radio.client.request_map_stop(OBS, ticket=1, budget_ms=1000)
    receipt = caught.value.receipt
    assert receipt.errors and receipt.write_acceptance is PssWriteAcceptance.ACKNOWLEDGED
    if where == "last-read":
        assert receipt.steps[-1].returned and receipt.steps[-1].raw == "200"
        assert len(radio.calls) == 21
    elif where == "write":
        assert receipt.steps[-2].returned and receipt.steps[-2].error
        assert not receipt.steps[-1].attempted and len(radio.calls) == 11
    radio.cleanup()


def test_budget_configuration_and_elapsed_observation_are_retained():
    radio = _Harness()
    receipt = radio.client.read_map_stop(OBS, timeout_ms=47, budget_ms=900)
    assert receipt.timeout_ms == 47 and receipt.budget_ms == 900
    assert 0 <= receipt.elapsed_ms < 900 and receipt.complete
    for fields in ({"timeout_ms": True}, {"budget_ms": 0}, {"elapsed_ms": -1},
                   {"elapsed_ms": float("nan")}, {"elapsed_ms": 900}):
        assert not replace(receipt, **fields).complete
    radio.cleanup()


def test_budget_exhausted_by_timeout_setter_does_not_start_native_call(monkeypatch):
    radio = _Harness()
    now = [100.0]
    monkeypatch.setattr(pss_stop_control.time, "monotonic", lambda: now[0])
    setter = radio.client.context.set_timeout

    def slow_setter(timeout):
        setter(timeout)
        now[0] += 2

    radio.client.context.set_timeout = slow_setter
    with pytest.raises(PssMapStopOperationError) as caught:
        radio.client.read_map_stop(OBS, budget_ms=1000)
    receipt = caught.value.receipt
    assert not radio.calls and not receipt.steps[0].attempted
    assert receipt.budget_ms == 1000 and receipt.elapsed_ms == 2000
    radio.client.context.set_timeout = setter
    radio.cleanup()


@pytest.mark.parametrize("where", ["decode", "complete", "constructor"])
def test_finalization_interrupts_keep_evidence_without_buffer_lifecycle_side_effects(
    monkeypatch, where,
):
    radio = _Harness()

    def fail(*args, **kwargs):
        raise KeyboardInterrupt("receipt finalization interrupted")

    if where == "decode":
        monkeypatch.setattr(pss_iio.PssMapStopReceipt, "decode", fail)
    elif where == "complete":
        monkeypatch.setattr(PssMapStopOperation, "complete", property(fail))
    else:
        monkeypatch.setattr(pss_iio, "PssMapStopOperation", fail)
    with pytest.raises(KeyboardInterrupt) as caught:
        radio.client.read_map_stop(OBS)
    assert any(step.name == "acquisition_stop" and step.raw == encode(radio.values)
               for step in caught.value.pss_stop_steps)
    assert caught.value.pss_stop_context_id == radio.client._stop_context_id
    if where != "constructor":
        assert caught.value.pss_stop_receipt.errors
    assert not radio.made and not radio.client._batch_io_active
    radio.cleanup()


@pytest.mark.parametrize("reader", ["map", "stop"])
def test_exclusive_native_operation_prevents_concurrent_close_or_other_io(reader):
    radio = _Harness()
    radio.client.open_maps(refill_chunks=200, batch_mode=True)
    entered, release = threading.Event(), threading.Event()
    results, errors = [], []

    def pause():
        entered.set()
        assert release.wait(3)

    if reader == "map":
        radio.made[0].on_refill = pause
        operation = radio.client.read_map_batch
        def competing():
            return radio.client.read_map_stop(OBS)
    else:
        def on_call(action, name):
            if name == "acquisition_stop":
                pause()

        radio.on_call = on_call
        def operation():
            return radio.client.read_map_stop(OBS)
        competing = radio.client.read_map_batch

    def run():
        try:
            results.append(operation())
        except BaseException as error:
            errors.append(error)

    worker = threading.Thread(target=run)
    worker.start()
    try:
        assert entered.wait(3)
        with pytest.raises(RadioConfigurationError):
            competing()
        with pytest.raises(RadioConfigurationError):
            radio.client.close_gracefully(readers_joined=True)
        assert not radio.made[0].closed and not radio.client.context.close_count
    finally:
        release.set()
        worker.join(3)
    assert not worker.is_alive() and not errors and results[0].complete
    radio.cleanup()


@pytest.mark.parametrize("changes", [
    {"errors": None}, {"errors": []}, {"steps": []}, {"after": "bad"},
    {"before": 1}, {"previous": []}, {"observation": OLD_OBS},
    {"context_id": ""}, {"ticket": True}, {"context_identity": []},
])
def test_reconstructed_operation_cannot_contradict_exact_receipt_shape(changes):
    radio = _Harness()
    receipt = radio.client.read_map_stop(OBS)
    assert not replace(receipt, **changes).complete
    radio.cleanup()


def test_abi16_map_batches_support_and_fine_schedule_use_explicit_matching_profile():
    radio = _Harness()
    radio.client.open_maps(refill_chunks=200, batch_mode=True)
    batch = radio.client.read_map_batch()
    assert batch.complete and batch.abi_version == 0x10006
    assembler = PssMapReassembler()
    phase_map = None
    for scan in batch.scans:
        phase_map = assembler.add(scan.decoded)
    assert phase_map is not None and phase_map.abi_version == 0x10006
    supported_map = replace(_map(), abi_version=0x10006)
    assert map_support(supported_map, observation=OBS).observation == OBS
    with pytest.raises(ValueError):
        map_support(supported_map, observation=OLD_OBS)
    with pytest.raises(ValueError):
        map_support(_map(), observation=OBS)
    manifest = _manifest(observation=OBS)
    ledger = FineScheduleLedger(manifest)
    evidence = validate_fine_batch(ledger, _batch(ledger), observation=OBS)
    assert evidence.after.remaining_results == 0 and evidence.accepted
    assert radio.client.read_current_index(OBS).complete
    start = radio.client.open_fine_receipted(manifest)
    assert start.complete and start.manifest.observation == OBS
    radio.cleanup()


def test_pure_abi16_chunk_decoder_requires_both_optins_and_exact_analysis_contract():
    raw = bytearray(_map_scan(0)[:236])
    struct.pack_into("<I", raw, 4, 0x10006)
    for options in ({}, {"allow_experimental_shared_xfft": True},
                    {"allow_experimental_boundary_stop": True}):
        with pytest.raises(ValueError):
            PssMapChunk.decode(raw, **options)
    chunk = PssMapChunk.decode(raw, allow_experimental_shared_xfft=True,
                               allow_experimental_boundary_stop=True)
    assert chunk.abi_version == 0x10006
    maps = [replace(_map(start=1_280_000 * index, generation=1 + index), abi_version=0x10006)
            for index in range(3)]
    with pytest.raises(ValueError):
        pss_iio.analyze_phase_maps(maps, rate_msps=15, experimental_shared_xfft=True)
    result = pss_iio.analyze_phase_maps(maps, rate_msps=15, experimental_shared_xfft=True,
                                       experimental_boundary_stop=True)
    assert result


def test_abi16_health_retains_shared_fft_fault_mask_and_no_ddc_telemetry():
    raw = _health_line(abi=0x10005).replace("00010005", "00010006", 1)
    health = PssAcquisitionHealth.decode(raw)
    health.require_fault_free()
    assert health.ddc_telemetry_mode == 0
    # Shared-XFFT health bit 14 remains fatal in ABI1.6; not forgiven as stop tail.
    failed = _health_line(abi=0x10005, changes={24: 1 << 14}).replace(
        "00010005", "00010006", 1)
    with pytest.raises(ValueError):
        PssAcquisitionHealth.decode(failed).require_fault_free()
