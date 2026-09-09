"""Pure schedule/raw-evidence tests; no IIO, hardware or RF qualification."""

from __future__ import annotations

import struct
from dataclasses import FrozenInstanceError, replace

import pytest

from pluto_plus.hardware.fine_schedule import (
    FineLedgerState,
    FineScheduleLedger,
    FineScheduleManifest,
    validate_fine_batch,
)
from pluto_plus.hardware.pss_iio import (
    PssBatchAttributes,
    PssBatchReceipt,
    PssBatchScan,
    PssFinePacket,
)
from pluto_plus.hardware.source_support import (
    DetectionState,
    JoinState,
    ObservationIdentity,
    ProcessingProfile,
    RecordState,
    SourceInterval,
    join_source_interval,
)

U32 = (1 << 32) - 1
U64 = (1 << 64) - 1
OBS = ObservationIdentity(
    serial="test-serial", boot_id="test-boot", session_id="test-session", visit_id=1,
    source_rate_hz=15_000_000, profile=ProcessingProfile.PAIRED_15_SHARED_XFFT_512_447_V1,
    frequency_plan_id="fixed-frequency", processing_fingerprint="a" * 64,
)


def _manifest(**kwargs):
    values = dict(observation=OBS, schedule_id="schedule-a", first_center=2_000_000,
                  period_q32_32=20_000 << 32, request_base=3, count=4,
                  coefficient_generation=7)
    values.update(kwargs)
    return FineScheduleManifest(**values)


def _packet(request: int, center: int, *, generation: int = 7, lag: int = -3) -> PssFinePacket:
    words = [0] * 26
    words[:3] = [0x31535350, 0x1a010001, request]
    words[3:7] = [center & U32, center >> 32] * 2
    words[7] = lag & U32
    words[8:10] = [(center + lag) & U32, (center + lag) >> 32]
    words[10:19] = [generation, 2, 0, 3, 0, 100, 0, 200, 0]
    return PssFinePacket.decode(struct.pack("<26I", *words), rate_msps=15)


def _bytes(packet: PssFinePacket) -> bytes:
    return struct.pack("<26I", *packet.words) + b"\0" * 24


def _attributes(generation: int = 7) -> PssBatchAttributes:
    return PssBatchAttributes(0, generation,
                              (("fault_flags", "0"),
                               ("active_coefficient_generation", str(generation))), ())


def _batch(ledger: FineScheduleLedger, *, count: int | None = None,
           stream_id: str = "stream-a") -> PssBatchReceipt:
    count = ledger.remaining_results if count is None else count
    plan = ledger.manifest
    packets = tuple(_packet(plan.request_at(index), plan.center_at(index),
                            generation=plan.coefficient_generation)
                    for index in range(ledger.accepted_count, ledger.accepted_count + count))
    return PssBatchReceipt(
        stream="fine", stream_id=stream_id, batch_index=ledger.next_batch_index,
        rate_msps=15, abi_version=0x10002, requested_scans=count, scan_bytes=128,
        buffer_bytes=count * 128, buffer_step=128, refill_started=True, refill_completed=True,
        native_refill_bytes=None, observed_bytes=count * 128,
        raw=b"".join(_bytes(packet) for packet in packets),
        attributes_before=_attributes(plan.coefficient_generation),
        attributes_after=_attributes(plan.coefficient_generation),
        expected_request_before=plan.request_at(ledger.accepted_count),
        remaining_results_before=ledger.remaining_results,
        scans=tuple(PssBatchScan(index, index * 128, 128, packet, ())
                    for index, packet in enumerate(packets)), errors=(),
    )


def _replace_packet(batch: PssBatchReceipt, index: int, packet: PssFinePacket) -> PssBatchReceipt:
    scans = list(batch.scans)
    scans[index] = replace(scans[index], decoded=packet)
    assert batch.raw is not None
    raw = batch.raw[:index * 128] + _bytes(packet) + batch.raw[(index + 1) * 128:]
    return replace(batch, scans=tuple(scans), raw=raw)


def _validate(ledger: FineScheduleLedger, batch: PssBatchReceipt, **kwargs):
    return validate_fine_batch(ledger, batch, observation=OBS, **kwargs)


def _assert_failed(result) -> None:
    assert not result.accepted and result.errors
    assert result.after.state is FineLedgerState.FAILED
    assert result.after.accepted_count == result.before.accepted_count
    assert result.after.next_batch_index == result.before.next_batch_index
    assert result.after.stream_id == result.before.stream_id
    assert all(row.record.state is RecordState.INCOMPLETE for row in result.scans)
    with pytest.raises(ValueError, match="failed or completed"):
        _validate(result.after, result.batch)


def test_fractional_schedule_matches_explicit_kernel_u32_carry() -> None:
    plan = _manifest(count=21, period_q32_32=(20_000 << 32) + 0xb1234567)
    center, fraction = plan.first_center, 0
    expected = []
    for _ in range(plan.count):
        expected.append(center)
        old = fraction
        center += plan.period_q32_32 >> 32
        fraction = (fraction + (plan.period_q32_32 & U32)) & U32
        if fraction < old:
            center += 1
    assert expected == [plan.center_at(index) for index in range(plan.count)]
    assert plan.center_at(0) == plan.first_center
    assert plan.capture_at(0) == SourceInterval(plan.first_center - 32, plan.first_center + 98)
    assert plan.request_at(20) == plan.request_base + 20
    assert plan.planned_anchor_separation == expected[-1] - expected[0]
    ledger = FineScheduleLedger(plan)
    first = _validate(ledger, _batch(ledger, count=8))
    last = _validate(first.after, _batch(first.after))
    assert first.accepted and last.accepted and last.after.state is FineLedgerState.COMPLETE


@pytest.mark.parametrize("field,value", (
    ("first_center", -1), ("first_center", 31), ("first_center", True),
    ("first_center", U64 + 1), ("period_q32_32", 0), ("period_q32_32", U32),
    ("period_q32_32", True), ("period_q32_32", U64 + 1),
    ("request_base", 0), ("request_base", U32 + 1), ("request_base", True),
    ("count", 0), ("count", -1), ("count", True), ("count", U32 + 1),
    ("coefficient_generation", 0), ("coefficient_generation", U32 + 1),
    ("coefficient_generation", True), ("schedule_id", ""), ("schedule_id", "has space"),
    ("schedule_id", "é"), ("schedule_id", "x" * 129), ("observation", None),
))
def test_manifest_rejects_unbounded_or_ambiguous_inputs(field: str, value) -> None:
    with pytest.raises(ValueError):
        _manifest(**{field: value})


@pytest.mark.parametrize("rate,profile", (
    (30_000_000, ProcessingProfile.PAIRED_15_SHARED_XFFT_512_447_V1),
    (60_000_000, ProcessingProfile.PAIRED_15_SHARED_XFFT_512_447_V1),
    (15_000_000, "paired-15-shared-xfft-512-447-v1"),
    (15_000_000, "legacy-15"),
))
def test_unknown_profiles_and_30_60_are_not_silently_admitted(rate: int, profile) -> None:
    with pytest.raises(ValueError, match="explicit paired"):
        _manifest(observation=replace(OBS, source_rate_hz=rate, profile=profile))


def test_u64_full_capture_endpoint_and_post_last_advance_are_distinct() -> None:
    plan = _manifest(first_center=U64 - 97, count=1, period_q32_32=1 << 32)
    assert plan.capture_at(0).stop == U64 + 1
    with pytest.raises(ValueError):
        _manifest(first_center=U64 - 96, count=1, period_q32_32=1 << 32)
    # The one EMITTED capture fits, but the driver's unused next_center would wrap.
    with pytest.raises(ValueError, match="post-last"):
        _manifest(first_center=U64 - 97, count=1, period_q32_32=98 << 32)
    with pytest.raises(ValueError):
        _manifest(first_center=U64 - 200, count=2, period_q32_32=200 << 32)


def test_nonzero_request_id_may_end_at_u32_max_but_never_wrap() -> None:
    plan = _manifest(request_base=U32 - 1, count=2, coefficient_generation=U32)
    result = _validate(FineScheduleLedger(plan), _batch(FineScheduleLedger(plan)))
    assert result.accepted and result.scans[-1].packet.request_id == U32
    with pytest.raises(ValueError, match="last request ID"):
        _manifest(request_base=U32, count=2)


def test_maximum_finite_count_uses_constant_size_arithmetic_not_a_request_list() -> None:
    plan = _manifest(request_base=1, count=U32, period_q32_32=1 << 32)
    ledger = FineScheduleLedger(plan)
    assert plan.center_at(U32 - 1) == plan.first_center + U32 - 1
    assert ledger.remaining_results == U32 and ledger.validated_anchor_separation is None
    assert not hasattr(plan, "__dict__") and not hasattr(ledger, "__dict__")
    result = _validate(ledger, _batch(ledger, count=16))
    assert result.accepted and result.after.accepted_count == 16
    assert result.after.remaining_results == U32 - 16


@pytest.mark.parametrize("index", (-1, True, 4, U32 + 1))
def test_indexing_is_finite_and_checked(index) -> None:
    for method in (_manifest().center_at, _manifest().request_at, _manifest().capture_at):
        with pytest.raises(ValueError):
            method(index)


def test_complete_accounting_is_not_continuous_coverage_or_nominal_duration() -> None:
    plan = _manifest(count=751)
    ledger = FineScheduleLedger(plan)
    result = _validate(ledger, _batch(ledger))
    assert result.accepted and result.after.state is FineLedgerState.COMPLETE
    assert result.after.validated_anchor_separation == 15_000_000
    assert result.after.remaining_results == 0
    assert plan.planned_anchor_separation == (plan.count - 1) * 20_000
    assert result.scans[1].record.support.capture_inputs.start > (
        result.scans[0].record.support.capture_inputs.stop)
    assert _manifest(count=750).planned_anchor_separation < 15_000_000
    one = FineScheduleLedger(_manifest(count=1))
    assert _validate(one, _batch(one)).after.validated_anchor_separation == 0
    with pytest.raises(ValueError, match="failed or completed"):
        _validate(result.after, result.batch)


def test_exact_schedule_centers_catch_valid_id_and_self_consistent_wrong_timestamp() -> None:
    ledger = FineScheduleLedger(_manifest())
    batch = _batch(ledger)
    original = batch.scans[1].decoded
    wrong = _packet(original.request_id, original.center_index + 1)
    batch = _replace_packet(batch, 1, wrong)
    assert batch.complete  # Native batch ABI/ID validation alone does not check schedule centers.
    result = _validate(ledger, batch)
    _assert_failed(result)
    assert "exact Q32 scheduled center" in " ".join(result.scans[1].errors)
    assert result.scans[1].packet is not None
    assert result.scans[1].record.support.center == wrong.center_index
    assert result.scans[1].expected_center == original.center_index
    assert result.batch is batch and result.batch.raw is batch.raw


@pytest.mark.parametrize("change", ("request", "generation", "raw_only", "decoded_only", "words"))
def test_ids_generations_and_copied_raw_decoded_contradictions_fail(change: str) -> None:
    ledger = FineScheduleLedger(_manifest())
    batch = _batch(ledger)
    old = batch.scans[1].decoded
    packet = _packet(old.request_id + (change == "request"), old.center_index,
                     generation=8 if change == "generation" else 7, lag=4)
    replacement = _replace_packet(batch, 1, packet)
    if change == "raw_only":
        replacement = replace(replacement, scans=batch.scans)
    elif change == "decoded_only":
        replacement = replace(replacement, raw=batch.raw)
    elif change == "words":
        scans = list(batch.scans)
        scans[1] = replace(scans[1], decoded=replace(old, words=packet.words))
        replacement = replace(batch, scans=tuple(scans))
    result = _validate(ledger, replacement)
    _assert_failed(result)
    assert result.batch is replacement


@pytest.mark.parametrize("field,value", (
    ("stream", "map"), ("stream_id", ""), ("stream_id", "x" * 257),
    ("batch_index", 1), ("batch_index", True), ("rate_msps", 30), ("rate_msps", 60),
    ("abi_version", 0x10003), ("requested_scans", 0), ("requested_scans", True),
    ("scan_bytes", 104), ("buffer_bytes", None), ("buffer_bytes", 104),
    ("buffer_step", None), ("refill_started", False), ("refill_completed", False),
    ("refill_completed", 1), ("native_refill_bytes", -1), ("native_refill_bytes", True),
    ("native_refill_bytes", 104), ("observed_bytes", None), ("observed_bytes", 511),
    ("raw", None), ("raw", b""), ("raw", bytearray(512)),
    ("expected_request_before", None), ("expected_request_before", 4),
    ("remaining_results_before", None), ("remaining_results_before", 5),
    ("scans", ()), ("errors", ("late native fault",)),
))
def test_envelope_and_native_error_receipts_fail_without_discarding_evidence(field, value) -> None:
    ledger = FineScheduleLedger(_manifest())
    batch = replace(_batch(ledger), **{field: value})
    result = _validate(ledger, batch)
    _assert_failed(result)
    assert result.batch is batch and result.batch.raw is batch.raw


@pytest.mark.parametrize("attribute", ("attributes_before", "attributes_after"))
@pytest.mark.parametrize("change", ("missing", "unknown_fault", "fault", "generation", "error",
                                    "raw_missing", "raw_wrong", "raw_duplicate", "raw_huge",
                                    "raw_invalid", "raw_malformed"))
def test_before_and_after_health_are_strict_and_raw_attributes_are_crosschecked(
    attribute: str, change: str,
) -> None:
    values = {
        "missing": None,
        "unknown_fault": replace(_attributes(), fault_flags=None),
        "fault": replace(_attributes(), fault_flags=1),
        "generation": replace(_attributes(), coefficient_generation=8),
        "error": replace(_attributes(), errors=("failed read",)),
        "raw_missing": replace(_attributes(), raw=()),
        "raw_wrong": replace(_attributes(), raw=(("fault_flags", "1"),
                                                 ("active_coefficient_generation", "7"))),
        "raw_duplicate": replace(_attributes(), raw=(("fault_flags", "0"),
                                                     ("fault_flags", "0"))),
        "raw_huge": replace(_attributes(), raw=(("fault_flags", "0" * 129),
                                                ("active_coefficient_generation", "7"))),
        "raw_invalid": replace(_attributes(), raw=(("fault_flags", "invalid"),
                                                   ("active_coefficient_generation", "7"))),
        "raw_malformed": replace(_attributes(), raw=(("fault_flags",), ("unexpected", "0"))),
    }
    ledger = FineScheduleLedger(_manifest())
    result = _validate(ledger, replace(_batch(ledger), **{attribute: values[change]}))
    _assert_failed(result)
    assert "attributes" in " ".join(result.errors)


@pytest.mark.parametrize("change", ("magic", "padding", "truncated", "extra_tail", "scan_error",
                                    "scan_offset", "scan_index", "scan_length", "scan_missing"))
def test_malformed_middle_tail_and_diagnostics_preserve_later_negatives(change: str) -> None:
    ledger = FineScheduleLedger(_manifest())
    batch = _batch(ledger)
    raw = bytearray(batch.raw)
    scans = list(batch.scans)
    if change == "magic":
        raw[128] = 0
    elif change == "padding":
        raw[128 + 104] = 1
    elif change == "truncated":
        raw = raw[:-1]
        scans[-1] = replace(scans[-1], byte_count=127, decoded=None,
                            errors=("truncated trailing scan",))
    elif change == "extra_tail":
        raw += b"x"
    elif change == "scan_error":
        scans[1] = replace(scans[1], errors=("known native error",))
    elif change == "scan_offset":
        scans[1] = replace(scans[1], byte_offset=129)
    elif change == "scan_index":
        scans[1] = replace(scans[1], index=0)
    elif change == "scan_length":
        scans[1] = replace(scans[1], byte_count=104)
    else:
        scans.pop()
    batch = replace(batch, raw=bytes(raw), observed_bytes=len(raw), scans=tuple(scans))
    result = _validate(ledger, batch, detections=(DetectionState.NO_TRIGGER,) * 4)
    _assert_failed(result)
    assert result.batch.raw == raw
    assert all(row.record.detection is DetectionState.NO_TRIGGER for row in result.scans[:4])
    assert result.scans[2].packet.request_id == ledger.manifest.request_at(2)
    assert result.scans[2].record.support is not None
    if change == "extra_tail":
        assert len(result.scans) == 5 and result.scans[-1].packet is None
        assert result.scans[-1].record.detection is DetectionState.NOT_EVALUATED


def test_whole_batch_rejection_preserves_accepted_prefix_and_cannot_resume_it() -> None:
    start = FineScheduleLedger(_manifest(count=6))
    first = _validate(start, _batch(start, count=2))
    next_batch = _batch(first.after, count=2)
    bad = _replace_packet(next_batch, 1, _packet(6, 2_060_001))
    failed = _validate(first.after, bad)
    _assert_failed(failed)
    assert failed.after.accepted_count == 2 and failed.after.next_batch_index == 1
    assert failed.after.validated_anchor_separation == 20_000
    assert failed.after.remaining_results == 4
    # Pure history is intentionally forkable; only the external owner can enforce adoption.
    alternative = _validate(first.after, next_batch)
    assert alternative.accepted and alternative.after.accepted_count == 4
    assert start.accepted_count == 0
    with pytest.raises(FrozenInstanceError):
        first.after.accepted_count = 4


@pytest.mark.parametrize("change", ("serial", "boot_id", "session_id", "visit_id",
                                    "frequency_plan_id", "processing_fingerprint"))
def test_different_observation_is_explicit_failure_not_reattributed_evidence(change: str) -> None:
    value = (2 if change == "visit_id" else
             "b" * 64 if change == "processing_fingerprint" else "other")
    other = replace(OBS, **{change: value})
    ledger = FineScheduleLedger(_manifest())
    result = validate_fine_batch(ledger, _batch(ledger), observation=other)
    _assert_failed(result)
    assert result.observation is other
    assert all(row.record.observation == other for row in result.scans)
    with pytest.raises(ValueError, match="different observation"):
        join_source_interval(result.source_records, observation=OBS,
                             comparison=SourceInterval(1_000_000, 3_000_000),
                             available_inputs=SourceInterval(0, 4_000_000))


@pytest.mark.parametrize("change", ("stream", "duplicate", "skip", "expected", "remaining"))
def test_stream_and_native_prefix_cannot_change_across_batches(change: str) -> None:
    ledger = FineScheduleLedger(_manifest())
    first = _validate(ledger, _batch(ledger, count=2))
    fields = {"stream": {"stream_id": "stream-b"}, "duplicate": {"batch_index": 0},
              "skip": {"batch_index": 2}, "expected": {"expected_request_before": 3},
              "remaining": {"remaining_results_before": 4}}
    result = _validate(first.after, replace(_batch(first.after), **fields[change]))
    _assert_failed(result)


def test_negative_labels_do_not_choose_support_or_hide_an_unobservable_boundary() -> None:
    ledger = FineScheduleLedger(_manifest())
    batch = _batch(ledger)
    plain = _validate(ledger, batch)
    negative = _validate(ledger, batch, detections=(DetectionState.NO_TRIGGER,) * 4)
    triggered = _validate(ledger, batch, detections=(DetectionState.TRIGGER,) * 4)
    assert plain.accepted and negative.accepted and triggered.accepted
    args = dict(observation=OBS, comparison=SourceInterval(1_999_997, 2_060_000),
                available_inputs=SourceInterval(1_999_997, 2_060_098))
    joined = [join_source_interval(result.source_records, **args)
              for result in (plain, negative, triggered)]
    assert all(tuple(item.state for item in rows) == (JoinState.UNOBSERVABLE,
               JoinState.INCLUDED, JoinState.INCLUDED, JoinState.INCLUDED) for rows in joined)
    assert all(row.record.detection is DetectionState.NOT_EVALUATED for row in plain.scans)
    assert [row.record.support for row in negative.scans] == [
        row.record.support for row in triggered.scans]


def test_native_bytecount_unavailable_stays_unknown_known_correct_count_is_allowed() -> None:
    ledger = FineScheduleLedger(_manifest())
    for count in (None, 512):
        result = _validate(ledger, replace(_batch(ledger), native_refill_bytes=count))
        assert result.accepted and result.batch.native_refill_bytes is count


@pytest.mark.parametrize("field", ("raw", "scans", "requested_scans"))
def test_oversized_envelope_is_retained_but_not_expanded_or_decoded(field, monkeypatch) -> None:
    ledger = FineScheduleLedger(_manifest())
    batch = _batch(ledger)
    values = {"raw": b"x" * (4096 * 128 + 1), "scans": batch.scans * 1025,
              "requested_scans": 4097}
    batch = replace(batch, **{field: values[field]})

    def forbidden(*args, **kwargs):
        pytest.fail("oversized envelope must not invoke a packet decoder")

    monkeypatch.setattr(PssFinePacket, "decode", forbidden)
    result = _validate(ledger, batch)
    _assert_failed(result)
    assert result.batch is batch and len(result.scans) == 1
    assert result.scans[0].scan_index is None and result.scans[0].packet is None


def test_maximum_native_batch_is_bounded_and_complete() -> None:
    ledger = FineScheduleLedger(_manifest(count=4096))
    result = _validate(ledger, _batch(ledger))
    assert result.accepted and result.after.state is FineLedgerState.COMPLETE
    assert len(result.scans) == 4096 and len(result.batch.raw) == 512 * 1024


def test_detection_contract_and_missing_labels_are_explicit() -> None:
    ledger = FineScheduleLedger(_manifest())
    for invalid in ([DetectionState.NO_TRIGGER], ("no_trigger",),
                    (DetectionState.NO_TRIGGER,) * 4097):
        with pytest.raises(ValueError, match="bounded tuple"):
            _validate(ledger, _batch(ledger), detections=invalid)
    result = _validate(ledger, _batch(ledger), detections=(DetectionState.NO_TRIGGER,))
    _assert_failed(result)
    assert result.detections == (DetectionState.NO_TRIGGER,)
    assert result.scans[0].record.detection is DetectionState.NO_TRIGGER
    assert result.scans[1].record.detection is DetectionState.NOT_EVALUATED


@pytest.mark.parametrize("where", ("batch", "scan", "attributes_before", "attributes_after"))
@pytest.mark.parametrize("errors", (None, []))
def test_missing_or_mutable_error_collections_are_not_qualified_as_no_errors(where, errors) -> None:
    ledger = FineScheduleLedger(_manifest())
    batch = _batch(ledger)
    if where == "batch":
        batch = replace(batch, errors=errors)
    elif where == "scan":
        batch = replace(batch, scans=(replace(batch.scans[0], errors=errors),) + batch.scans[1:])
    else:
        batch = replace(batch, **{where: replace(_attributes(), errors=errors)})
    result = _validate(ledger, batch)
    _assert_failed(result)
    assert result.batch is batch


@pytest.mark.parametrize("fields", (
    {"accepted_count": 1}, {"accepted_count": True}, {"next_batch_index": 1},
    {"accepted_count": 4, "next_batch_index": 1, "stream_id": "s"},
    {"state": FineLedgerState.COMPLETE}, {"state": FineLedgerState.FAILED},
    {"failure": "unexpected"}, {"state": "active"},
    {"accepted_count": 1, "next_batch_index": 2, "stream_id": "s"},
))
def test_manually_inconsistent_ledger_states_are_rejected(fields) -> None:
    with pytest.raises(ValueError):
        FineScheduleLedger(_manifest(), **fields)
