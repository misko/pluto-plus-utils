"""Synthetic text fixtures only: no radio, calibration or RF qualification."""

from dataclasses import FrozenInstanceError, asdict
from hashlib import sha256

import pytest

from pluto_plus.hardware.rx_interface_evidence import assess_rx_interface_timing


def report(cells=None, rate=15_000_000):
    if cells is None:
        cells = {(data, clock) for data in range(16) for clock in range(16)}
    return (
        f"CLK: {rate} Hz 'o' = PASS\nDC0:1:2:3:4:5:6:7:8:9:a:b:c:d:e:f:\n"
        + "".join(f"{data:x}:" + " ".join(
            "o" if (data, clock) in cells else "." for clock in range(16)
        ) + " \n" for data in range(16))
        + "\n"
    )


def assess(text, **kwargs):
    options = dict(expected_sample_rate_hz=15_000_000, clock_delay=7,
                   data_delay=7, minimum_margin_steps=1, margin_axis="square")
    options.update(kwargs)
    return assess_rx_interface_timing(text, **options)


@pytest.mark.parametrize("rate", [2_500_000, 15_000_000, 25_000_000, 30_000_000, 60_000_000])
def test_complete_matrix_and_exact_rate_receipt(rate):
    raw = report(rate=rate)
    result = assess(raw, expected_sample_rate_hz=rate)
    assert result.meets_matrix_policy
    assert result.complete_margin_steps == 7
    assert result.observed_sample_rate_hz == rate
    assert result.report_sha256 == sha256(raw.encode("ascii")).hexdigest()
    assert result.raw_report == raw
    assert asdict(result)["schema"] == "ad9361-rx-interface-matrix-v1"
    with pytest.raises(FrozenInstanceError):
        result.selected_clock_delay = 3


def test_data_rows_clock_columns_are_not_transposed():
    raw = report({(1, 2)})
    assert raw.splitlines()[3] == "1:. . o . . . . . . . . . . . . . "
    correct = assess(raw, data_delay=1, clock_delay=2, minimum_margin_steps=0)
    wrong = assess(raw, data_delay=2, clock_delay=1, minimum_margin_steps=0)
    assert correct.meets_matrix_policy and correct.complete_margin_steps == 0
    assert not wrong.selected_cell_passed and wrong.complete_margin_steps is None
    assert wrong.rejection_reasons == ("selected_cell_failed",)


def test_all_fail_is_a_retained_negative_receipt_not_a_parse_error():
    raw = report(set())
    result = assess(raw)
    assert not result.meets_matrix_policy and not result.selected_cell_passed
    assert result.raw_report == raw and result.complete_margin_steps is None
    assert result.rejection_reasons == ("selected_cell_failed",)


def test_wrong_rate_cannot_pass_even_if_all_cells_pass():
    result = assess(report(rate=60_000_000))
    assert result.selected_cell_passed and result.complete_margin_steps == 7
    assert result.rejection_reasons == ("sample_rate_mismatch",)
    assert not result.meets_matrix_policy


def test_multiple_rejection_causes_are_retained():
    result = assess(report(set(), rate=30_000_000))
    assert result.rejection_reasons == ("sample_rate_mismatch", "selected_cell_failed")


@pytest.mark.parametrize("radius", range(8))
def test_exact_complete_square_margin(radius):
    cells = {(data, clock) for data in range(7 - radius, 8 + radius)
             for clock in range(7 - radius, 8 + radius)}
    result = assess(report(cells), minimum_margin_steps=radius)
    assert result.meets_matrix_policy and result.complete_margin_steps == radius
    if radius < 7:
        too_narrow = assess(report(cells), minimum_margin_steps=radius + 1)
        assert too_narrow.rejection_reasons == ("insufficient_measured_margin",)


@pytest.mark.parametrize("missing", [(6, 6), (6, 7), (6, 8), (7, 6), (7, 8),
                                      (8, 6), (8, 7), (8, 8)])
def test_every_neighbor_including_diagonals_is_required(missing):
    cells = {(data, clock) for data in range(16) for clock in range(16)} - {missing}
    result = assess(report(cells))
    assert result.complete_margin_steps == 0
    assert result.rejection_reasons == ("insufficient_measured_margin",)


@pytest.mark.parametrize("data,clock", [(0, 7), (15, 7), (7, 0), (7, 15), (0, 0), (15, 15)])
def test_grid_edges_do_not_clip_or_wrap_unmeasured_margin(data, clock):
    result = assess(report(), data_delay=data, clock_delay=clock)
    assert result.selected_cell_passed and result.complete_margin_steps == 0
    assert not result.meets_matrix_policy


@pytest.mark.parametrize("axis,data,clock,cells", [
    ("data", 7, 0, {(row, 0) for row in range(5, 10)}),
    ("clock", 0, 7, {(0, column) for column in range(5, 10)}),
])
def test_explicit_one_dimensional_margin_at_other_axis_boundary(axis, data, clock, cells):
    result = assess(report(cells), margin_axis=axis, data_delay=data,
                    clock_delay=clock, minimum_margin_steps=2)
    assert result.meets_matrix_policy and result.complete_margin_steps == 2
    square = assess(report(cells), data_delay=data, clock_delay=clock)
    assert not square.meets_matrix_policy and square.complete_margin_steps == 0


@pytest.mark.parametrize("axis,data,clock", [("data", 0, 7), ("clock", 7, 0)])
def test_one_dimensional_margin_still_requires_both_sides_of_its_axis(axis, data, clock):
    result = assess(report(), margin_axis=axis, data_delay=data, clock_delay=clock)
    assert not result.meets_matrix_policy and result.complete_margin_steps == 0


@pytest.mark.parametrize("raw", [
    "", "0\n", "calibration succeeded\n", "\n".join(report().splitlines()[:-2]),
    report() + report(), report().replace("0:1:2:3:", "1:0:2:3:", 1),
    report().replace("\n1:", "\n0:", 1), report().replace("\n2:", "\n3:", 1),
    report().replace("o ", "x ", 1), report().replace("o ", "O ", 1),
    report().replace("o ", "", 1), report().replace("o ", "o o ", 1),
    report().replace("\n1:", "\n\n1:", 1), report().replace("15000000", "0", 1),
    report().replace("15000000", "015000000", 1), report().replace("PASS", "FAIL", 1),
    report().replace("15000000", str(1 << 64), 1), report() + "é", " " * 4097,
])
def test_malformed_truncated_reordered_or_ambiguous_report_is_rejected(raw):
    with pytest.raises(ValueError):
        assess(raw)


def test_crlf_and_surrounding_whitespace_preserve_original_hash():
    raw = "\n " + report().replace("\n", "\r\n") + " \n"
    result = assess(raw)
    assert result.meets_matrix_policy
    assert result.raw_report == raw
    assert result.report_sha256 == sha256(raw.encode("ascii")).hexdigest()


@pytest.mark.parametrize("field,value", [
    ("clock_delay", -1), ("clock_delay", 16), ("clock_delay", True),
    ("data_delay", -1), ("data_delay", 16), ("data_delay", 7.0),
    ("minimum_margin_steps", -1), ("minimum_margin_steps", 8),
    ("minimum_margin_steps", True), ("expected_sample_rate_hz", 0),
    ("expected_sample_rate_hz", True), ("expected_sample_rate_hz", 15_000_000.0),
    ("margin_axis", "diagonal"), ("margin_axis", ""), ("margin_axis", None),
    ("margin_axis", True),
])
def test_policy_configuration_is_explicit_and_strict(field, value):
    with pytest.raises(ValueError):
        assess(report(), **{field: value})


def test_input_must_be_text_and_margin_policy_cannot_be_omitted():
    with pytest.raises(ValueError, match="must be text"):
        assess(b"not decoded text")
    with pytest.raises(TypeError):
        assess_rx_interface_timing(report(), expected_sample_rate_hz=15_000_000,
                                   clock_delay=7, data_delay=7)
