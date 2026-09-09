"""Pure coordinate accounting; these fixtures do not attest a radio or RF signal."""

from __future__ import annotations

import struct
from dataclasses import replace

import pytest

from pluto_plus.hardware.pilot_iio import PilotSnapshot
from pluto_plus.hardware.pss_iio import PssFinePacket, PssPhaseMap
from pluto_plus.hardware.source_support import (
    DetectionState,
    EnvelopeKind,
    JoinState,
    ObservationIdentity,
    ProcessingProfile,
    RecordKind,
    RecordState,
    SourceInterval,
    SourceLattice,
    SourceRecord,
    fine_support,
    join_source_interval,
    map_support,
    pilot_slice_support,
)

LIMIT = 1 << 64
MAP_SPAN = 1_280_000
OBS = ObservationIdentity(
    serial="1040007c4a94000211000b009186843ef2", boot_id="boot-a", session_id="session-a",
    visit_id=17, source_rate_hz=15_000_000,
    profile=ProcessingProfile.PAIRED_15_SHARED_XFFT_512_447_V1,
    frequency_plan_id="fixed-upper-a", processing_fingerprint="a" * 64,
)


def _pilot(*, count: int = 1_000_000, first: int = 540) -> PilotSnapshot:
    words = [0] * 26
    values = (first, first + 6 * (count - 1), count, count, 90, 0,
              (count + 90) * 6, count + 90)
    for index, value in enumerate(values):
        words[2 * index:2 * index + 2] = [value & 0xffffffff, value >> 32]
    words[19], words[20] = 24, 17  # stopped, armed, nonempty supported prefix
    raw = "PIL1 00010000 15000000 2500000 8 0 15000000 0 " + " ".join(
        f"{word:08x}" for word in words
    )
    return PilotSnapshot.decode(raw)


def _map(*, start: int = MAP_SPAN, generation: int = 2) -> PssPhaseMap:
    return PssPhaseMap(0x10005, generation, start, (0,) * 20_000)


def _fine(*, center: int = 2_000_000, lag: int = -3) -> PssFinePacket:
    words = [0] * 26
    words[:3] = [0x31535350, 0x1a010001, 3]
    words[3:7] = [center & 0xffffffff, center >> 32] * 2
    words[7] = lag & 0xffffffff
    words[8:10] = [(center + lag) & 0xffffffff, (center + lag) >> 32]
    words[10:19] = [7, 2, 0, 3, 0, 100, 0, 200, 0]
    return PssFinePacket.decode(struct.pack("<26I", *words), rate_msps=15)


def _pilot_support():
    return pilot_slice_support(_pilot(), observation=OBS, expected_samples=1_000_000,
                               received_bytes=4_000_000, start=0, stop=1_000_000)


def _records() -> tuple[SourceRecord, ...]:
    return (
        SourceRecord(OBS, "iq", RecordKind.PILOT, RecordState.COMPLETE, _pilot_support()),
        SourceRecord(OBS, "map-2", RecordKind.MAP, RecordState.COMPLETE,
                     map_support(_map(), observation=OBS), DetectionState.NO_TRIGGER),
        SourceRecord(OBS, "fine-3", RecordKind.FINE, RecordState.COMPLETE,
                     fine_support(_fine(), observation=OBS, coefficient_generation=7)),
    )


def _join(records: tuple[SourceRecord, ...], **kwargs):
    args = {"observation": OBS, "comparison": SourceInterval(MAP_SPAN, 2 * MAP_SPAN),
            "available_inputs": SourceInterval(MAP_SPAN - 446, 2 * MAP_SPAN + 511)}
    args.update(kwargs)
    return join_source_interval(records, **args)


def test_half_open_intervals_and_lattices_do_not_invent_full_rate_samples() -> None:
    interval = SourceInterval(100, 200)
    assert interval.samples == 100 and interval.contains(SourceInterval(100, 200))
    assert interval.intersection(SourceInterval(199, 201)) == SourceInterval(199, 200)
    assert interval.intersection(SourceInterval(200, 201)) is None
    assert not interval.contains(SourceInterval(100, 201))
    assert SourceInterval(LIMIT - 1, LIMIT).samples == 1
    lattice = SourceLattice(271, 6, 300_000)
    assert lattice.last == 1_800_265
    assert lattice.bounds.samples == 1_799_995  # N/Fs exposure is a different quantity.


@pytest.mark.parametrize("start,stop", ((-1, 1), (0, 0), (1, 0), (True, 3),
                                       (0, 1.0), (LIMIT, LIMIT + 1), (0, LIMIT + 1)))
def test_intervals_reject_underflow_wrap_empty_and_nonintegers(start, stop) -> None:
    with pytest.raises(ValueError):
        SourceInterval(start, stop)


@pytest.mark.parametrize("args", ((0, 0, 1), (0, 1, 0), (0, True, 2),
                                 (LIMIT - 2, 2, 2), (-1, 6, 2)))
def test_lattice_checks_all_u64_endpoints(args) -> None:
    with pytest.raises(ValueError):
        SourceLattice(*args)


@pytest.mark.parametrize("changes", (
    {"source_rate_hz": 30_000_000}, {"source_rate_hz": 60_000_000},
    {"source_rate_hz": 15_000_000.0}, {"profile": "paired-15-shared-xfft-512-447-v1"},
    {"profile": "legacy-15"}, {"serial": ""}, {"boot_id": "unknown boot"},
    {"session_id": "session\x00"}, {"visit_id": 0}, {"visit_id": True},
    {"processing_fingerprint": "A" * 64}, {"frequency_plan_id": ""},
))
def test_identity_requires_explicit_supported_contract_and_binding(changes) -> None:
    with pytest.raises(ValueError):
        replace(OBS, **changes)


def test_pilot_slice_maps_newest_to_center_once_and_retains_full_filter_history() -> None:
    support = pilot_slice_support(_pilot(), observation=OBS, expected_samples=1_000_000,
                                  received_bytes=4_000_000, start=10, stop=20)
    assert support.output_start == 10
    assert support.centers == SourceLattice(331, 6, 10)
    assert support.raw_inputs == SourceInterval(62, 655)
    assert support.raw_inputs.samples == 538 + 6 * 9 + 1
    assert support.observation is OBS


@pytest.mark.parametrize("arguments", (
    {"received_bytes": 3_999_996}, {"expected_samples": 1_000_001},
    {"start": -1}, {"start": True}, {"start": 20, "stop": 20}, {"stop": 1_000_001},
    {"observation": replace(OBS, visit_id=18)},
))
def test_pilot_refuses_missing_bytes_wrong_visit_or_outside_slice(arguments) -> None:
    args = {"observation": OBS, "expected_samples": 1_000_000, "received_bytes": 4_000_000,
            "start": 0, "stop": 1_000_000}
    args.update(arguments)
    with pytest.raises(ValueError):
        pilot_slice_support(_pilot(), **args)


def test_pilot_rejects_mutated_snapshot_and_support_records() -> None:
    with pytest.raises(ValueError, match="raw receipt"):
        pilot_slice_support(replace(_pilot(), first_newest_canonical_index=546),
                            observation=OBS, expected_samples=1_000_000,
                            received_bytes=4_000_000, start=0, stop=1)
    support = _pilot_support()
    with pytest.raises(ValueError, match="phase"):
        replace(support, centers=SourceLattice(272, 6, 1))
    with pytest.raises(ValueError, match="raw-input"):
        replace(support, raw_inputs=SourceInterval(0, 100))


def test_pilot_high_source_index_is_not_truncated_or_wrapped() -> None:
    first = ((LIMIT - 12) // 6) * 6
    snapshot = _pilot(count=2, first=first)
    support = pilot_slice_support(snapshot, observation=OBS, expected_samples=2,
                                  received_bytes=8, start=0, stop=2)
    assert support.centers.first == first - 269
    assert support.raw_inputs == SourceInterval(first - 538, first + 7)


def test_map_distinguishes_candidate_ideal_and_full_block_support() -> None:
    support = map_support(_map(), observation=OBS)
    assert support.candidate_starts == SourceInterval(MAP_SPAN, 2 * MAP_SPAN)
    assert support.ideal_template_inputs == SourceInterval(MAP_SPAN, 2 * MAP_SPAN + 65)
    assert support.processing_inputs == SourceInterval(MAP_SPAN - 446, 2 * MAP_SPAN + 511)
    assert support.envelope_kind is EnvelopeKind.CONSERVATIVE_BLOCK_ENVELOPE
    assert support.fft_origin is None


def test_exact_map_origin_is_epoch_relative_not_global_frame_aligned() -> None:
    support = map_support(_map(start=123, generation=1), observation=OBS, fft_origin=123)
    assert support.candidate_starts.start == 123  # No modulo-20000 epoch rebasing.
    assert support.envelope_kind is EnvelopeKind.EXACT_BLOCK_ENVELOPE
    assert support.processing_inputs.start == 123
    blocks = list(range(123, 123 + MAP_SPAN, 447))
    assert support.processing_inputs.stop == blocks[-1] + 512
    assert support.processing_inputs.contains(support.ideal_template_inputs)


def test_conservative_envelope_contains_all_447_possible_block_phases() -> None:
    residues = set()
    for skipped_frames in range(447):
        start = 1000 + skipped_frames * 20_000
        phase_map = _map(start=start)
        exact = map_support(phase_map, observation=OBS, fft_origin=1000)
        conservative = map_support(phase_map, observation=OBS)
        assert conservative.processing_inputs.contains(exact.processing_inputs)
        assert exact.processing_inputs.contains(exact.ideal_template_inputs)
        residues.add(start - exact.processing_inputs.start)
    assert residues == set(range(447))


@pytest.mark.parametrize("abi", (0x10001, 0x10002, 0x10003, 0x10004, 0x10006))
def test_old_and_unknown_map_abis_do_not_inherit_new_processing_profile(abi: int) -> None:
    with pytest.raises(ValueError, match="ABI1.5"):
        map_support(replace(_map(), abi_version=abi), observation=OBS)


@pytest.mark.parametrize("mutation", (
    {"generation": 0}, {"generation": True}, {"bins": (0,) * 19_999},
    {"bins": (-1,) * 20_000}, {"bins": (65536,) * 20_000},
    {"bins": (True,) * 20_000}, {"start_index": 445},
    {"start_index": LIMIT - MAP_SPAN - 65},
))
def test_map_rejects_incomplete_or_wrapping_support(mutation) -> None:
    with pytest.raises(ValueError):
        map_support(replace(_map(), **mutation), observation=OBS)


@pytest.mark.parametrize("origin", (-1, True, MAP_SPAN + 1, 1))
def test_map_rejects_inconsistent_attested_origin(origin) -> None:
    with pytest.raises(ValueError):
        map_support(_map(), observation=OBS, fft_origin=origin)


def test_support_dataclasses_do_not_admit_arbitrary_processing_envelopes() -> None:
    support = map_support(_map(), observation=OBS)
    with pytest.raises(ValueError, match="processing geometry"):
        replace(support, processing_inputs=support.ideal_template_inputs)
    with pytest.raises(ValueError, match="ObservationIdentity"):
        replace(support, observation=None)


@pytest.mark.parametrize("lag", (-30, -3, 0, 30))
def test_fine_winner_is_first_tap_and_full_search_support_is_separate(lag: int) -> None:
    support = fine_support(_fine(lag=lag), observation=OBS, coefficient_generation=7)
    assert support.winner == 2_000_000 + lag
    assert support.winner_inputs == SourceInterval(2_000_000 + lag, 2_000_066 + lag)
    assert support.capture_inputs == SourceInterval(1_999_968, 2_000_098)
    assert support.capture_inputs.contains(support.winner_inputs)
    assert support.request_id == 3 and support.coefficient_generation == 7


@pytest.mark.parametrize("center", (31, LIMIT - 97))
def test_fine_full_capture_underflow_and_overflow_are_not_hidden_by_valid_winner(center) -> None:
    with pytest.raises(ValueError):
        fine_support(_fine(center=center), observation=OBS, coefficient_generation=7)


def test_fine_raw_packet_and_expected_generation_are_bound() -> None:
    with pytest.raises(ValueError, match="coefficient generation"):
        fine_support(_fine(), observation=OBS, coefficient_generation=8)
    with pytest.raises(ValueError, match="raw words"):
        fine_support(replace(_fine(), winner_timestamp=10), observation=OBS,
                     coefficient_generation=7)
    with pytest.raises(ValueError, match="26 words"):
        fine_support(replace(_fine(), words=(0,) * 27), observation=OBS, coefficient_generation=7)


def test_join_returns_complete_geometric_support_and_integer_pilot_selection() -> None:
    joined = _join(_records())
    assert all(item.state is JoinState.INCLUDED for item in joined)
    selected = joined[0].pilot_selection
    assert selected is not None
    assert MAP_SPAN <= selected.centers.first < MAP_SPAN + 6
    assert 2 * MAP_SPAN - 6 <= selected.centers.last < 2 * MAP_SPAN
    assert selected.output_start * 6 + 271 == selected.centers.first
    assert selected.raw_inputs.start == selected.centers.first - 269
    assert joined[1].record.detection is DetectionState.NO_TRIGGER


def test_trigger_and_no_trigger_ledgers_select_identical_iq() -> None:
    records = _records()
    negative = _join(records)
    positive = _join((records[0], replace(records[1], detection=DetectionState.TRIGGER),
                      records[2]))
    assert [item.state for item in negative] == [item.state for item in positive]
    assert negative[0].pilot_selection == positive[0].pilot_selection
    assert negative[1].record is records[1]  # Negative maps remain in the ledger.


def test_missing_or_unobservable_records_are_explicit_and_never_filtered_out() -> None:
    records = (
        SourceRecord(OBS, "partial-iq", RecordKind.PILOT, RecordState.INCOMPLETE,
                     reason="reader timed out after 25000 samples"),
        SourceRecord(OBS, "no-fine", RecordKind.FINE, RecordState.UNOBSERVABLE,
                     detection=DetectionState.NO_TRIGGER, reason="no fine request was scheduled"),
        SourceRecord(OBS, "cfo-outside-passband", RecordKind.PILOT, RecordState.UNOBSERVABLE,
                     reason="residual CFO coverage not established"),
    )
    joined = _join(records)
    assert len(joined) == len(records)
    assert [row.state for row in joined] == [JoinState.INCOMPLETE, JoinState.UNOBSERVABLE,
                                           JoinState.UNOBSERVABLE]
    assert [row.reason for row in joined] == [record.reason for record in records]


def test_partial_overlap_or_missing_halo_is_unobservable_not_a_cropped_map() -> None:
    records = _records()
    narrow = _join(records, comparison=SourceInterval(MAP_SPAN + 1, 2 * MAP_SPAN))
    assert narrow[1].state is JoinState.UNOBSERVABLE
    no_halo = _join(records, available_inputs=SourceInterval(MAP_SPAN, 2 * MAP_SPAN))
    assert no_halo[0].state is JoinState.UNOBSERVABLE
    assert no_halo[1].state is JoinState.UNOBSERVABLE
    assert no_halo[2].state is JoinState.INCLUDED


def test_pilot_raw_support_does_not_manufacture_center_coverage() -> None:
    record = _records()[0]
    joined = _join((record,), comparison=SourceInterval(10, 300),
                   available_inputs=SourceInterval(2, 1000))
    assert joined[0].state is JoinState.UNOBSERVABLE
    assert "center lattice" in joined[0].reason
    empty_centers = _join((record,), comparison=SourceInterval(272, 276),
                          available_inputs=SourceInterval(2, 1000))
    assert empty_centers[0].state is JoinState.UNOBSERVABLE
    assert "no exported sample" in empty_centers[0].reason


@pytest.mark.parametrize("field,value", (("serial", "other-radio"), ("boot_id", "boot-b"),
                                       ("session_id", "session-b"), ("visit_id", 18),
                                       ("frequency_plan_id", "lower"),
                                       ("processing_fingerprint", "b" * 64)))
def test_join_refuses_mismatched_observation_domains(field: str, value) -> None:
    other = replace(OBS, **{field: value})
    record = SourceRecord(other, "missing", RecordKind.MAP, RecordState.INCOMPLETE,
                          reason="not received")
    with pytest.raises(ValueError, match="different observation"):
        _join((record,))


def test_record_and_join_ledgers_fail_closed_on_inconsistent_or_unbounded_input() -> None:
    record = _records()[0]
    with pytest.raises(ValueError, match="kind/observation"):
        replace(record, kind=RecordKind.MAP)
    with pytest.raises(ValueError, match="kind/observation"):
        replace(record, observation=replace(OBS, boot_id="boot-b"))
    with pytest.raises(ValueError, match="requires support"):
        replace(record, support=None)
    with pytest.raises(ValueError, match="reason"):
        replace(record, state=RecordState.INCOMPLETE)
    with pytest.raises(ValueError, match="unique"):
        _join((record, record))
    with pytest.raises(ValueError, match="bounded nonempty"):
        _join(())
    with pytest.raises(ValueError, match="bounded nonempty"):
        _join((record,) * 4097)
    with pytest.raises(ValueError, match="available inputs"):
        _join((record,), available_inputs=SourceInterval(MAP_SPAN + 1, 2 * MAP_SPAN))


def test_first_epoch_map_is_retained_as_unobservable_without_clamping() -> None:
    first_map = _map(start=0, generation=1)
    # Keep the raw map in the caller's artifact ledger; the geometry API does
    # not own or discard raw IQ/bins. Unknown origin cannot be guessed as zero.
    raw_ledger = {"raw-map-1": first_map}
    with pytest.raises(ValueError):
        map_support(first_map, observation=OBS)
    excluded = SourceRecord(OBS, "raw-map-1", RecordKind.MAP, RecordState.UNOBSERVABLE,
                            detection=DetectionState.NO_TRIGGER,
                            reason="unknown FFT origin gives a negative dependency bound")
    joined = _join((excluded,))
    assert joined[0].state is JoinState.UNOBSERVABLE
    assert raw_ledger[joined[0].record.record_id] is first_map

    # Even an externally attested origin zero does not make raw sample0 part
    # of the pilot's supported input envelope, which starts at2 when n0=540.
    known = map_support(first_map, observation=OBS, fft_origin=0)
    assert known.processing_inputs.start == 0 and _pilot_support().raw_inputs.start == 2
    record = SourceRecord(OBS, "raw-map-1", RecordKind.MAP, RecordState.COMPLETE, known,
                          DetectionState.NO_TRIGGER)
    comparison = SourceInterval(271, MAP_SPAN)
    joined = _join((record,), comparison=comparison,
                   available_inputs=SourceInterval(2, 2 * MAP_SPAN))
    assert joined[0].state is JoinState.UNOBSERVABLE
    assert raw_ledger[joined[0].record.record_id] is first_map


def test_two_second_capture_contains_twelve_complete_maps_after_excluding_first() -> None:
    snapshot = _pilot(count=5_000_000)
    pilot = pilot_slice_support(snapshot, observation=OBS, expected_samples=5_000_000,
                                received_bytes=20_000_000, start=0, stop=5_000_000)
    records = [SourceRecord(OBS, "iq-2s", RecordKind.PILOT, RecordState.COMPLETE, pilot)]
    for ordinal in range(1, 13):
        records.append(SourceRecord(
            OBS, f"map-{ordinal+1}", RecordKind.MAP, RecordState.COMPLETE,
            map_support(_map(start=ordinal * MAP_SPAN, generation=ordinal + 1), observation=OBS),
            DetectionState.NO_TRIGGER,
        ))
    comparison = SourceInterval(MAP_SPAN, 13 * MAP_SPAN)
    joined = join_source_interval(records, observation=OBS, comparison=comparison,
                                  available_inputs=pilot.raw_inputs)
    assert comparison.samples == 15_360_000  # 1.024s, not an assumed one-second duration.
    assert len(joined) == 13 and all(row.state is JoinState.INCLUDED for row in joined)
    selection = joined[0].pilot_selection
    assert selection.centers.last - selection.centers.first >= 15_000_000


def test_nominal_120ms_dwell_does_not_expand_last_exported_center_bounds() -> None:
    snapshot = _pilot(count=300_000)
    pilot = pilot_slice_support(snapshot, observation=OBS, expected_samples=300_000,
                                received_bytes=1_200_000, start=0, stop=300_000)
    record = SourceRecord(OBS, "iq-120ms", RecordKind.PILOT, RecordState.COMPLETE, pilot)
    bounds = pilot.centers.bounds
    nominal = SourceInterval(pilot.centers.first, pilot.centers.first + 300_000 * 6)
    assert bounds.samples == 1_799_995
    assert nominal.samples == 1_800_000
    assert bounds.stop == nominal.stop - 5
    strict = _join((record,), comparison=bounds, available_inputs=pilot.raw_inputs)
    assert strict[0].state is JoinState.INCLUDED
    assert strict[0].pilot_selection == pilot
    extended = _join((record,), comparison=nominal, available_inputs=pilot.raw_inputs)
    assert extended[0].state is JoinState.UNOBSERVABLE
    assert "center lattice" in extended[0].reason
