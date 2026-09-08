from __future__ import annotations

from fractions import Fraction

import pytest

from pluto_plus.hardware.pilot_iio import PilotSnapshot


def _snapshot(
    *, rate: int = 15_000_000, first: int = 540, samples: int = 300_000,
    queued: int = 0, active: bool = False, replacements: dict[int, int] | None = None,
    generation: int = 1, recovery: int = 0, actual: int | None = None, dma: int = 0,
) -> str:
    words = [0] * 26
    values = (first if samples else 0, first + 6 * (samples - 1) if samples else 0,
              samples, samples - queued, 90, 0, 6 * (samples + 90), samples + 90)
    for n, value in enumerate(values):
        words[2*n:2*n+2] = [value & 0xffffffff, value >> 32]
    words[17] = 1 << 8
    words[19] = int(active) | (2 if queued else 0) | (8 if samples else 0) | 16
    words[20:23] = [17, max(1, queued), queued]
    if replacements:
        for index, value in replacements.items():
            words[index] = value
    return (f"PIL1 00010000 {rate} 2500000 {generation} {recovery} "
            f"{rate if actual is None else actual} {dma} " +
            " ".join(f"{word:08x}" for word in words) + "\n")


def _complete(snapshot: PilotSnapshot, **kwargs: int) -> None:
    arguments = dict(expected_visit_id=17, expected_source_rate_hz=snapshot.source_rate_hz,
                     expected_samples=300_000, received_bytes=1_200_000)
    arguments.update(kwargs)
    snapshot.require_complete_prefix(**arguments)


@pytest.mark.parametrize("rate", [15_000_000, 30_000_000, 60_000_000])
def test_exact_120ms_prefix_and_full_rate_coordinate(rate: int) -> None:
    record = _snapshot(rate=rate)
    snapshot = PilotSnapshot.decode(record)
    _complete(snapshot)
    multiplier = rate // 15_000_000
    assert snapshot.raw == record
    assert snapshot.source_center(0) == (540 - 269) * multiplier
    assert snapshot.source_center(299_999) == (540 + 6*299_999 - 269) * multiplier
    assert snapshot.source_center(1) - snapshot.source_center(0) == 6 * multiplier
    assert snapshot.axis_prefix_duration_seconds == Fraction(3, 25)
    assert not hasattr(snapshot, "pss_detected")
    assert not hasattr(snapshot, "frame_lock_claim")


def test_high_counter_mapping_is_integer_exact_without_float_rounding() -> None:
    first = (1 << 63) + 4  # divisible by six
    snapshot = PilotSnapshot.decode(_snapshot(first=first))
    assert snapshot.source_center(271_829) == first + 6 * 271_829 - 269


def test_header_clock_observation_does_not_override_the_fpga_rate() -> None:
    snapshot = PilotSnapshot.decode(_snapshot(actual=2_500_000))
    assert snapshot.source_rate_hz == 15_000_000
    with pytest.raises(ValueError, match="actual PHY"):
        _complete(snapshot)


@pytest.mark.parametrize("replacement", [
    (0, "TAG2"), (1, "00010001"), (2, "2500000"), (3, "15000000"),
    (4, "0"), (4, "4294967296"), (4, "1_000"), (4, "+1"),
    (5, "2"), (6, "-1"), (7, "1"), (7, "-4096"), (8, "0x00021c"),
    (8, "000021c"), (8, "00000021c"), (8, "0000_21c"),
])
def test_rejects_malformed_or_foreign_envelopes(replacement: tuple[int, str]) -> None:
    fields = _snapshot().split()
    index, field = replacement
    fields[index] = field
    with pytest.raises(ValueError):
        PilotSnapshot.decode(" ".join(fields))


@pytest.mark.parametrize("text", ["", "PIL1", "x" * 4097, "\N{EM SPACE}" + _snapshot(),
                                  _snapshot() + " 00000000", _snapshot().rsplit(" ", 1)[0]])
def test_rejects_unbounded_non_ascii_and_wrong_field_counts(text: str) -> None:
    with pytest.raises(ValueError):
        PilotSnapshot.decode(text)


@pytest.mark.parametrize("replacements", [
    {23: 1}, {24: 1}, {25: 1}, {17: 1 << 16}, {18: 1 << 7}, {19: 1 << 5},
    {6: 300001}, {22: 1}, {21: 33}, {17: 129 << 8}, {19: 16},
    {19: 26}, {19: 28}, {19: 8}, {20: 0}, {0: 541}, {2: 1800535},
    {14: 299999}, {12: 1},
])
def test_rejects_inconsistent_atomic_counters(replacements: dict[int, int]) -> None:
    with pytest.raises(ValueError):
        PilotSnapshot.decode(_snapshot(replacements=replacements))


def test_rejects_original_source_counter_overflow() -> None:
    with pytest.raises(ValueError, match="original source counter"):
        PilotSnapshot.decode(_snapshot(rate=60_000_000, first=(1 << 63) + 4))


def test_draining_snapshot_is_valid_diagnostic_but_not_a_complete_capture() -> None:
    snapshot = PilotSnapshot.decode(_snapshot(queued=32))
    assert snapshot.axis_delivered_samples == 299968
    with pytest.raises(ValueError, match="draining"):
        _complete(snapshot)


@pytest.mark.parametrize("kwargs,reason", [
    ({"active": True}, "active"), ({"recovery": 1}, "fault"), ({"dma": -5}, "fault"),
    ({"replacements": {16: 1}}, "saturation"),
    ({"replacements": {17: 257}}, "fault"),
    ({"replacements": {18: 4, 19: 28, 10: 1800540}}, "fault"),
    ({"replacements": {14: 300091}}, "unaccounted"),
])
def test_retains_diagnostics_but_rejects_unhealthy_final_capture(kwargs: dict, reason: str) -> None:
    snapshot = PilotSnapshot.decode(_snapshot(**kwargs))
    with pytest.raises(ValueError, match=reason):
        _complete(snapshot)


@pytest.mark.parametrize("kwargs", [
    {"expected_visit_id": 18}, {"expected_source_rate_hz": 30_000_000},
    {"expected_samples": 299999}, {"expected_samples": 0}, {"expected_samples": True},
    {"expected_visit_id": 0}, {"expected_visit_id": True}, {"expected_samples": -1},
    {"received_bytes": 1199996}, {"received_bytes": 1200001}, {"received_bytes": True},
    {"expected_source_rate_hz": 15_000_000.0},
])
def test_expected_identity_and_actual_reader_bytes_are_required(kwargs: dict) -> None:
    with pytest.raises(ValueError):
        _complete(PilotSnapshot.decode(_snapshot()), **kwargs)


@pytest.mark.parametrize("index", [-1, True, 0.0, 300000, 1 << 64])
def test_unreceived_sample_cannot_get_a_valid_coordinate(index: int) -> None:
    with pytest.raises(ValueError):
        PilotSnapshot.decode(_snapshot()).source_center(index)


def test_empty_snapshot_is_diagnostic_only_and_generation_wrap_is_legal() -> None:
    snapshot = PilotSnapshot.decode(_snapshot(samples=0, generation=0xffffffff))
    assert snapshot.axis_prefix_duration_seconds == 0
    with pytest.raises(ValueError):
        _complete(snapshot)
    with pytest.raises(ValueError):
        snapshot.source_center(0)
    assert PilotSnapshot.decode(_snapshot(generation=1)).generation == 1
