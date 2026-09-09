"""Fake-IIO control lifecycle checks, never hardware or RF qualification."""

from __future__ import annotations

import threading
from dataclasses import replace
from typing import Any

import pytest
from test_fine_schedule import OBS, _manifest
from test_pss_iio import _Attr, _health_line, _install_health
from test_pss_iio_batches import _cleanup, _setup

from pluto_plus.errors import RadioConfigurationError
from pluto_plus.hardware import pss_control, pss_iio
from pluto_plus.hardware.pss_control import (
    CONTROL_FIELDS,
    PssFineStartError,
    PssFineStartReceipt,
    PssTrackerControlError,
    PssWriteAcceptance,
)
from pluto_plus.hardware.pss_iio import PssGracefulCloseError


class _ObservedAttr:
    def __init__(self, owner: _Harness, name: str, value: str) -> None:
        self.owner, self.name, self.text = owner, name, value

    @property
    def value(self) -> str:
        self.owner.calls.append(("read", self.name, self.owner.armed))
        if self.owner.on_read:
            self.owner.on_read(self.name)
        return self.text

    @value.setter
    def value(self, value: str) -> None:
        self.owner.calls.append(("write", self.name, value))
        if self.owner.on_write:
            self.owner.on_write(self.name, value)
        self.text = value
        if self.name == "schedule_enable" and value == "1":
            self.owner.armed = True
            self.owner.attr("schedule_submitted").text = "0"


class _Harness:
    def __init__(self) -> None:
        self.client, self.made = _setup(rate=15, shared=True)
        self.client.context.attrs = {"hw_serial": OBS.serial, "boot_id": OBS.boot_id}
        self.calls: list[tuple[Any, ...]] = []
        self.armed = False
        self.on_read = None
        self.on_write = None
        self.client.tracker.attrs.update({name: _Attr(value) for name, value in {
            "status": 9, "current_index": 100_000, "schedule_submitted": 21,
            "packets_delivered": 21, "buffer_push_failures": 0,
            "packet_validation_failures": 0,
        }.items()})
        self.client.tracker.attrs = {
            name: _ObservedAttr(self, name, attr.value)
            for name, attr in self.client.tracker.attrs.items()
        }

    def attr(self, name: str) -> _ObservedAttr:
        return self.client.tracker.attrs[name]

    def open(self, **kwargs):
        return self.client.open_fine_receipted(_manifest(), **kwargs)

    def cleanup(self) -> None:
        self.on_read = self.on_write = None
        _cleanup(self.client, self.made)


def _receipt(error: BaseException) -> PssFineStartReceipt:
    return error.receipt if isinstance(error, PssFineStartError) else error.pss_fine_start_receipt


def test_current_index_zero_u64_and_raw_whitespace_are_not_missing_values() -> None:
    radio = _Harness()
    for value in (0, 0xffffffff, 0x100000000, (1 << 64) - 1):
        radio.attr("current_index").text = f" {value}\n"
        receipt = radio.client.read_current_index(OBS)
        assert receipt.complete and receipt.current_index == value
        assert receipt.steps[0].raw == f" {value}\n"
        assert receipt.steps[0].raw_characters == len(receipt.steps[0].raw)
        assert receipt.context_boot_id == OBS.boot_id
    assert [call[1] for call in radio.calls] == ["current_index"] * 4
    assert all(1 <= timeout <= 1000 for timeout in radio.client.context.timeouts)
    radio.cleanup()


def test_tracker_control_reads_separately_and_preserves_negative_diagnostic_states() -> None:
    radio = _Harness()
    radio.attr("fault_flags").text = "8"
    radio.attr("active_coefficient_generation").text = "0"
    receipt = radio.client.read_tracker_control(OBS)
    assert receipt.complete and receipt.requested_fields == CONTROL_FIELDS
    assert receipt.value("fault_flags") == 8
    assert receipt.value("active_coefficient_generation") == 0
    assert receipt.value("absent") is None
    assert tuple(call[1] for call in radio.calls) == CONTROL_FIELDS
    radio.attr("fault_flags").text = "0"
    radio.cleanup()


@pytest.mark.parametrize("value", ("-1", str(1 << 64), "nonnumeric", "0" * 129))
def test_bad_current_index_retains_exact_raw_or_explicit_bounded_prefix(value: str) -> None:
    radio = _Harness()
    radio.attr("current_index").text = value
    with pytest.raises(PssTrackerControlError) as caught:
        radio.client.read_current_index(OBS)
    receipt = caught.value.receipt
    assert not receipt.complete and receipt.current_index is None
    assert receipt.steps[0].raw == value[:128]
    assert receipt.steps[0].raw_characters == len(value)
    radio.cleanup()


@pytest.mark.parametrize("failure", (OSError("read failed"), KeyboardInterrupt("stop")))
def test_control_read_exceptions_preserve_missing_not_fake_zero(failure) -> None:
    radio = _Harness()

    def fail(name):
        raise failure

    radio.on_read = fail
    expected = PssTrackerControlError if isinstance(failure, Exception) else KeyboardInterrupt
    with pytest.raises(expected) as caught:
        radio.client.read_current_index(OBS)
    receipt = (caught.value.receipt if isinstance(caught.value, PssTrackerControlError)
               else caught.value.pss_control_receipt)
    assert not receipt.complete and receipt.current_index is None
    assert receipt.steps[0].attempted and not receipt.steps[0].returned
    assert receipt.steps[0].raw is None
    assert not radio.client._active_operations and not radio.client._batch_io_active
    radio.cleanup()


@pytest.mark.parametrize("attrs", ({}, {"hw_serial": "wrong"},
                                  {"hw_serial": OBS.serial, "serial": "wrong"},
                                  {"hw_serial": OBS.serial, "boot_id": "wrong"}))
def test_bad_identity_does_not_read_or_write_tracker(attrs) -> None:
    radio = _Harness()
    radio.client.context.attrs = attrs
    with pytest.raises(PssFineStartError) as caught:
        radio.open()
    assert not caught.value.receipt.complete and not radio.calls and not radio.made
    assert caught.value.receipt.enable_acceptance is PssWriteAcceptance.NOT_ATTEMPTED
    radio.cleanup()


def test_absent_boot_metadata_is_explicit_not_inferred_from_supplied_observation() -> None:
    radio = _Harness()
    del radio.client.context.attrs["boot_id"]
    receipt = radio.client.read_current_index(OBS)
    assert receipt.complete and receipt.context_boot_id is None
    assert receipt.observation.boot_id == OBS.boot_id  # Caller-owned, not observed here.
    radio.cleanup()


def test_start_records_exact_writes_buffer_admission_and_acceptance_before_results() -> None:
    radio = _Harness()
    receipt = radio.open()
    assert receipt.complete and receipt.enable_acceptance is PssWriteAcceptance.ACKNOWLEDGED
    assert receipt.stream_id == radio.client._batch_streams["fine"].stream_id
    assert receipt.refill_results == 4 and receipt.manifest == _manifest()
    assert receipt.before.value("schedule_submitted") == 21  # Old epoch is not this request.
    assert receipt.after.value("schedule_submitted") == 0
    assert receipt.after.value("packets_delivered") == 21  # Not new received results.
    writes = [(step.name, step.requested) for step in receipt.steps
              if step.phase == "open" and step.action == "write"]
    assert writes == [("schedule_first_center", "2000000"),
                      ("schedule_period_q32_32", str(20_000 << 32)),
                      ("schedule_request_base", "3"), ("schedule_count", "4"),
                      ("schedule_queue_target", "7"), ("schedule_enable", "1")]
    assert not receipt.cleanup_attempted and receipt.cleanup_verified is None
    assert not radio.made[0].refills and not radio.made[0].reads
    radio.cleanup()


def test_worker_may_already_finish_finite_submission_without_reversing_write_acceptance() -> None:
    radio = _Harness()

    def completed(name):
        if radio.armed:
            radio.attr("schedule_enable").text = "0"
            radio.attr("schedule_submitted").text = "4"

    radio.on_read = completed
    receipt = radio.open()
    assert receipt.complete and receipt.after.value("schedule_enable") == 0
    assert receipt.enable_acceptance is PssWriteAcceptance.ACKNOWLEDGED
    radio.cleanup()


@pytest.mark.parametrize("name", ("schedule_first_center", "schedule_period_q32_32",
                                 "schedule_request_base", "schedule_count",
                                 "schedule_queue_target", "schedule_enable"))
@pytest.mark.parametrize("failure_type", (OSError, KeyboardInterrupt))
def test_each_write_failure_or_interrupt_is_retained_and_its_attempt_is_cleaned(name, failure_type):
    radio = _Harness()

    def fail(field, value):
        if field == name and value != "0":
            # The remote side may have applied the value before losing the acknowledgment.
            radio.attr(field).text = value
            raise failure_type("write outcome lost")

    radio.on_write = fail
    expected = PssFineStartError if failure_type is OSError else KeyboardInterrupt
    with pytest.raises(expected) as caught:
        radio.open()
    receipt = _receipt(caught.value)
    assert not receipt.complete and receipt.cleanup_attempted and receipt.cleanup_verified
    attempted = next(step for step in receipt.steps if step.phase == "open" and step.name == name)
    assert attempted.attempted and not attempted.returned and attempted.error
    assert receipt.enable_acceptance is (
        PssWriteAcceptance.UNKNOWN if name == "schedule_enable"
        else PssWriteAcceptance.NOT_ATTEMPTED)
    assert radio.attr("schedule_enable").text == "0"
    assert all(buffer.close_count == 1 and not buffer.cancelled for buffer in radio.made)
    assert radio.client._fine_buffer is None and not radio.client._batch_streams
    radio.cleanup()


@pytest.mark.parametrize("phase", ("before", "after"))
@pytest.mark.parametrize("field,value", (("fault_flags", "8"), ("buffer_push_failures", "1"),
                                         ("packet_validation_failures", "1"),
                                         ("active_coefficient_generation", "0"),
                                         ("active_coefficient_generation", "8"),
                                         ("status", "0"), ("abi_version", "65539"),
                                         ("current_index", "invalid")))
def test_early_and_late_evidence_failures_are_retained_and_late_acceptance_not_erased(
    phase, field, value,
):
    radio = _Harness()

    def modify(name):
        if name == field and radio.armed == (phase == "after"):
            radio.attr(field).text = value

    radio.on_read = modify
    with pytest.raises(PssFineStartError) as caught:
        radio.open()
    receipt = caught.value.receipt
    assert not receipt.complete
    observed = receipt.after if phase == "after" else receipt.before
    assert next(step for step in observed.steps if step.name == field).raw == value
    assert receipt.enable_acceptance is (
        PssWriteAcceptance.ACKNOWLEDGED if phase == "after" else PssWriteAcceptance.NOT_ATTEMPTED)
    assert receipt.cleanup_attempted == (phase == "after")
    radio.attr("fault_flags").text = "0"
    radio.cleanup()


@pytest.mark.parametrize("field,value", (("schedule_first_center", "2000001"),
                                         ("schedule_request_base", "4"),
                                         ("schedule_submitted", "5"),
                                         ("schedule_enable", "0"),
                                         ("current_index", "99999")))
def test_late_changed_control_or_regressed_index_invalidates_start(field, value):
    radio = _Harness()

    def modify(name):
        if radio.armed and name == field:
            radio.attr(field).text = value

    radio.on_read = modify
    with pytest.raises(PssFineStartError) as caught:
        radio.open()
    assert caught.value.receipt.enable_acceptance is PssWriteAcceptance.ACKNOWLEDGED
    assert caught.value.receipt.cleanup_verified
    radio.cleanup()


@pytest.mark.parametrize("failure_type", (OSError, KeyboardInterrupt))
@pytest.mark.parametrize("stage", ("allocate", "validate", "uuid", "after_read"))
def test_buffer_preparation_and_after_read_stage_errors_keep_evidence(
    stage, failure_type, monkeypatch,
):
    radio = _Harness()
    if stage == "allocate":
        def allocate(*args):
            raise failure_type("constructor outcome unavailable")
        radio.client._iio.Buffer = allocate
    elif stage == "validate":
        def invalid(*args):
            raise failure_type("bad native geometry")
        monkeypatch.setattr(radio.client, "_check_batch_buffer", invalid)
    elif stage == "uuid":
        def uuid():
            raise failure_type("uuid failed before allocation")
        monkeypatch.setattr(pss_iio, "uuid4", uuid)
    else:
        def read(name):
            if radio.armed and name == "status":
                raise failure_type("late read failed")
        radio.on_read = read
    expected = PssFineStartError if failure_type is OSError else KeyboardInterrupt
    with pytest.raises(expected) as caught:
        radio.open()
    receipt = _receipt(caught.value)
    assert not receipt.complete and receipt.steps
    assert all(buffer.close_count == 1 and not buffer.cancelled for buffer in radio.made)
    if stage == "allocate":
        assert receipt.cleanup_verified is False and radio.client._batch_cleanup_errors
    elif stage == "uuid":
        assert not receipt.cleanup_attempted and not radio.made
    else:
        assert receipt.cleanup_verified
    radio.cleanup()


@pytest.mark.parametrize("stage", ("disable", "destroy", "timeout"))
def test_uncertain_cleanup_is_sticky_and_never_reuses_or_destroys_the_handle_twice(stage):
    radio = _Harness()

    def fail_after(name):
        if radio.armed and name == "fault_flags":
            radio.attr(name).text = "1"
            if stage == "destroy":
                def fail_close():
                    raise OSError("destroy outcome unknown")
                radio.made[0].close = fail_close
            if stage == "timeout":
                def fail_timeout(value):
                    raise OSError("timeout setup failed")
                radio.client.context.set_timeout = fail_timeout

    def write(name, value):
        if stage == "disable" and name == "schedule_enable" and value == "0":
            raise OSError("disable outcome unknown")

    radio.on_read, radio.on_write = fail_after, write
    with pytest.raises(PssFineStartError) as caught:
        radio.open()
    receipt = caught.value.receipt
    assert not receipt.complete and receipt.cleanup_verified is False
    assert radio.client._batch_cleanup_errors
    assert radio.client._fine_buffer is (radio.made[0] if stage == "timeout" else None)
    for operation in (radio.open, lambda: radio.client.read_current_index(OBS),
                      lambda: radio.client.open_fine(first_center=1, period_q32_32=1,
                                                     request_base=1, count=1), radio.client.close):
        with pytest.raises(RadioConfigurationError, match="cleanup is unverified"):
            operation()
    radio.on_read = radio.on_write = None
    radio.attr("fault_flags").text = "0"
    radio.client.context.set_timeout = lambda value: None
    _install_health(radio.client.phase_map, _health_line(abi=0x10005),
                    _health_line(abi=0x10005, generation=9))
    before = radio.made[0].close_count
    with pytest.raises(PssGracefulCloseError):
        radio.client.close_gracefully(readers_joined=True)
    assert radio.client.context.close_count == 1
    assert radio.made[0].close_count == before + (stage == "timeout")


def test_one_exclusive_admission_blocks_control_read_close_and_open_interleaving() -> None:
    radio = _Harness()
    entered, release = threading.Event(), threading.Event()
    result = []

    def pause(name):
        if not entered.is_set():
            entered.set()
            assert release.wait(2)

    radio.on_read = pause
    worker = threading.Thread(target=lambda: result.append(radio.open()))
    worker.start()
    assert entered.wait(2)
    try:
        for operation in (radio.open, lambda: radio.client.read_current_index(OBS),
                          radio.client.close_fine, radio.client.close):
            with pytest.raises(RadioConfigurationError, match="in flight"):
                operation()
        with pytest.raises(RadioConfigurationError, match="in-flight"):
            radio.client.close_gracefully(readers_joined=True)
    finally:
        release.set()
        worker.join(2)
    assert not worker.is_alive() and result[0].complete
    radio.cleanup()


def test_read_deadline_bounds_attempts_and_cleanup_has_separate_reserve(monkeypatch) -> None:
    radio = _Harness()
    now = [100.0]
    monkeypatch.setattr(pss_control.time, "monotonic", lambda: now[0])

    def spend(name, value):
        if name == "schedule_enable" and value == "1":
            now[0] += 10

    radio.on_write = spend
    with pytest.raises(PssFineStartError) as caught:
        radio.open(budget_ms=100)
    receipt = caught.value.receipt
    assert receipt.enable_acceptance is PssWriteAcceptance.ACKNOWLEDGED
    assert receipt.cleanup_verified and not receipt.complete
    assert all(not step.attempted for step in receipt.after.steps)
    assert all(0 < timeout <= 1000 for timeout in radio.client.context.timeouts)
    assert radio.made[0].close_count == 1
    radio.cleanup()


@pytest.mark.parametrize("field,value", (("timeout_ms", 0), ("budget_ms", 0),
                                         ("timeout_ms", True), ("budget_ms", 60_001),
                                         ("refill_results", 3), ("refill_results", 4097),
                                         ("queue_target", True), ("queue_target", 8)))
def test_argument_admission_precedes_context_timeout_or_attribute_io(field, value):
    radio = _Harness()
    with pytest.raises(ValueError):
        radio.open(**{field: value})
    assert not radio.calls and not radio.client.context.timeouts and not radio.made
    radio.cleanup()


def test_read_receipt_completeness_checks_raw_value_and_missing_error_evidence() -> None:
    radio = _Harness()
    receipt = radio.client.read_current_index(OBS)
    for step in (replace(receipt.steps[0], value=100_001),
                 replace(receipt.steps[0], raw="100001"),
                 replace(receipt.steps[0], attempted=False),
                 replace(receipt.steps[0], raw_characters=None)):
        assert not replace(receipt, steps=(step,)).complete
    assert not replace(receipt, errors=None).complete
    assert not replace(receipt, context_identity=()).complete
    radio.cleanup()


@pytest.mark.parametrize("change", ("request", "period", "generation", "identity", "write",
                                    "allocation", "before", "after", "missing_step", "errors",
                                    "oversized_steps", "worker_zero"))
def test_start_receipt_cannot_qualify_copied_contradictory_or_incomplete_evidence(change):
    radio = _Harness()
    receipt = radio.open()
    if change in {"request", "period", "generation", "identity"}:
        fields = {"request": {"request_base": 4}, "period": {"period_q32_32": 21_000 << 32},
                  "generation": {"coefficient_generation": 8},
                  "identity": {"observation": replace(OBS, visit_id=2)}}
        bad = replace(receipt, manifest=replace(receipt.manifest, **fields[change]))
    elif change in {"before", "after", "worker_zero"}:
        phase = "after" if change == "worker_zero" else change
        control = getattr(receipt, phase)
        steps = list(control.steps)
        index = next(index for index, step in enumerate(steps) if step.name == (
            "schedule_enable" if change == "worker_zero" else "current_index"))
        value = 0 if change == "worker_zero" else steps[index].value + 1
        steps[index] = replace(steps[index], raw=str(value), raw_characters=len(str(value)),
                               value=value)
        bad = replace(receipt, **{phase: replace(control, steps=tuple(steps))})
    elif change == "missing_step":
        bad = replace(receipt, steps=receipt.steps[1:])
    elif change == "oversized_steps":
        bad = replace(receipt, steps=receipt.steps * 100)
        assert bad.enable_acceptance is PssWriteAcceptance.UNKNOWN
    elif change == "errors":
        bad = replace(receipt, errors=None)
    else:
        steps = list(receipt.steps)
        index = next(index for index, step in enumerate(steps) if step.phase == "open"
                     and step.action == ("allocate" if change == "allocation" else "write"))
        steps[index] = replace(steps[index], returned=False)
        bad = replace(receipt, steps=tuple(steps))
    assert not bad.complete
    radio.cleanup()


@pytest.mark.parametrize("where", ("identity", "first_read", "enable"))
def test_timeout_setter_failure_is_unattempted_not_an_acknowledged_write(where):
    radio = _Harness()
    original = radio.client.context.set_timeout

    def timeout(value):
        if where == "identity" or (where == "first_read" and radio.client.context.timeouts):
            raise OSError("timeout setup failed")
        if where == "enable" and radio.made:
            raise OSError("timeout setup failed after allocation")
        original(value)

    radio.client.context.set_timeout = timeout
    with pytest.raises(PssFineStartError) as caught:
        radio.open()
    receipt = caught.value.receipt
    assert not receipt.complete
    assert receipt.enable_acceptance is PssWriteAcceptance.NOT_ATTEMPTED
    if where == "identity":
        assert not radio.calls and not radio.made
    if where == "enable":
        assert receipt.cleanup_verified is False
    radio.client.context.set_timeout = original
    if where == "enable":
        assert radio.client._fine_buffer is radio.made[0]
        assert radio.made[0].close_count == 0  # Destroy never entered native I/O.
    radio.cleanup()


@pytest.mark.parametrize("stage", ("disable_scans", "enable_scan"))
def test_scan_preparation_failure_does_not_allocate_or_claim_schedule_mutation(stage, monkeypatch):
    radio = _Harness()

    def fail(*args):
        raise KeyboardInterrupt("scan preparation interrupted")

    monkeypatch.setattr(pss_iio, "_disable_scan_channels" if stage == "disable_scans"
                        else "_find_scan_channel", fail)
    with pytest.raises(KeyboardInterrupt) as caught:
        radio.open()
    receipt = caught.value.pss_fine_start_receipt
    assert receipt.enable_acceptance is PssWriteAcceptance.NOT_ATTEMPTED
    assert not receipt.cleanup_attempted and not radio.made
    assert not any(call[0] == "write" for call in radio.calls)
    radio.cleanup()


def test_persistent_read_receipt_failure_keeps_raw_steps_and_releases_admission(monkeypatch):
    radio = _Harness()

    def fail(*args, **kwargs):
        raise KeyboardInterrupt("persistent control receipt finalization failure")

    monkeypatch.setattr(pss_control._ControlJournal, "control_receipt", fail)
    with pytest.raises(KeyboardInterrupt) as caught:
        radio.client.read_current_index(OBS)
    steps = caught.value.pss_control_steps
    assert steps[-1].raw == "100000" and steps[-1].returned
    assert caught.value.pss_control_identity[0] == ("hw_serial", OBS.serial)
    assert not radio.client._active_operations and not radio.client._batch_io_active
    radio.cleanup()


@pytest.mark.parametrize("stage", ("enable_return", "complete", "after_receipt"))
def test_interrupted_finalization_cleans_owned_buffer_even_when_rich_receipt_keeps_failing(
    stage, monkeypatch,
):
    radio = _Harness()
    if stage == "enable_return":
        real_replace = pss_control.replace
        fired = [False]

        def broken_replace(instance, **changes):
            if (not fired[0] and isinstance(instance, pss_control.PssControlStep)
                    and instance.phase == "open" and instance.name == "schedule_enable"
                    and changes.get("returned") is True):
                fired[0] = True
                raise KeyboardInterrupt("enable acknowledgment journal interrupted")
            return real_replace(instance, **changes)

        monkeypatch.setattr(pss_control, "replace", broken_replace)
    elif stage == "complete":
        def interrupted(self):
            raise KeyboardInterrupt("completeness traversal interrupted")
        monkeypatch.setattr(PssFineStartReceipt, "complete", property(interrupted))
    else:
        real_receipt = pss_control._ControlJournal.control_receipt

        def interrupted_receipt(self, phase, **kwargs):
            if phase == "after":
                raise KeyboardInterrupt("persistent after-receipt failure")
            return real_receipt(self, phase, **kwargs)

        monkeypatch.setattr(pss_control._ControlJournal, "control_receipt", interrupted_receipt)
    with pytest.raises(KeyboardInterrupt) as caught:
        radio.open()
    assert radio.client._fine_buffer is None and radio.made[0].close_count == 1
    assert not radio.made[0].cancelled and not radio.client._active_operations
    if stage == "after_receipt":
        assert caught.value.pss_control_steps and caught.value.pss_fine_manifest == _manifest()
        assert any(step.phase == "cleanup" and step.returned
                   for step in caught.value.pss_control_steps)
    else:
        receipt = caught.value.pss_fine_start_receipt
        assert receipt.errors and receipt.cleanup_verified
        assert receipt.enable_acceptance is (
            PssWriteAcceptance.UNKNOWN if stage == "enable_return"
            else PssWriteAcceptance.ACKNOWLEDGED)
    radio.cleanup()
