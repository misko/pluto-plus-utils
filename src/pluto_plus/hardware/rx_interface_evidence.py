"""Hardware-free assessment of AD9361 RX digital-interface timing reports.

This consumes the Linux driver's 16x16 ``bist_timing_analysis`` text, not a
calibration command's exit status. Rows are DATA delay; columns are CLOCK
delay. A policy pass describes only the supplied matrix and selected setting.
It does not attest a radio, perform calibration, or authorize firmware use.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from hashlib import sha256
from typing import Literal

_RATE_LINE = re.compile(r"CLK: ([1-9][0-9]*) Hz 'o' = PASS", re.ASCII)
_COLUMN_LINE = "DC0:1:2:3:4:5:6:7:8:9:a:b:c:d:e:f:"
_MAX_TEXT_BYTES = 4096


@dataclass(frozen=True, slots=True)
class RxInterfaceTimingEvidence:
    """Immutable text/decision receipt; caller must supply identity attestation.

    ``complete_margin_steps`` is the largest complete passing line/square
    around the selected cell for ``margin_axis``, with no clipping or wrapping.
    None means the selected cell failed. These steps are not nanoseconds or
    a probability bound, and measurements at one setting/rate are not a
    qualification of other hardware, temperatures, rates or firmware.
    """

    raw_report: str
    report_sha256: str
    observed_sample_rate_hz: int
    expected_sample_rate_hz: int
    selected_clock_delay: int
    selected_data_delay: int
    minimum_margin_steps: int
    margin_axis: Literal["data", "clock", "square"]
    # Tuple indexed as passing_cells[data_delay][clock_delay].
    passing_cells: tuple[tuple[bool, ...], ...]
    selected_cell_passed: bool
    complete_margin_steps: int | None
    rejection_reasons: tuple[str, ...]
    schema: Literal["ad9361-rx-interface-matrix-v1"] = "ad9361-rx-interface-matrix-v1"

    @property
    def meets_matrix_policy(self) -> bool:
        return not self.rejection_reasons


def _integer(value: int, name: str, minimum: int, maximum: int) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer in [{minimum}, {maximum}]")


def _parse(report: str) -> tuple[int, tuple[tuple[bool, ...], ...], str]:
    if not isinstance(report, str):
        raise ValueError("RX timing report must be text")
    if len(report) > _MAX_TEXT_BYTES:
        raise ValueError("RX timing report exceeds the bounded text size")
    try:
        raw = report.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("RX timing report must contain only ASCII") from error
    # Preserve raw bytes in the receipt. Only surrounding whitespace is ignored
    # for parsing; blank/missing/duplicate interior rows are never dropped.
    lines = report.strip().splitlines()
    if len(lines) != 18:
        raise ValueError("expected exactly one complete 16x16 RX timing matrix")
    rate_line = _RATE_LINE.fullmatch(lines[0].strip())
    if rate_line is None:
        raise ValueError("invalid RX timing sample-clock header")
    rate = int(rate_line.group(1))
    _integer(rate, "reported sample clock", 1, (1 << 64) - 1)
    if lines[1].strip() != _COLUMN_LINE:
        raise ValueError("RX timing columns must be clock delays 0 through f in order")
    cells: list[tuple[bool, ...]] = []
    for data_delay, line in enumerate(lines[2:]):
        label, separator, body = line.strip().partition(":")
        if separator != ":" or label != f"{data_delay:x}":
            raise ValueError("RX timing rows must be data delays 0 through f in order")
        values = body.split()
        if len(values) != 16 or any(value not in ("o", ".") for value in values):
            raise ValueError("each RX timing row must contain exactly 16 o/. cells")
        cells.append(tuple(value == "o" for value in values))
    return rate, tuple(cells), sha256(raw).hexdigest()


def assess_rx_interface_timing(
    report: str,
    *,
    expected_sample_rate_hz: int,
    clock_delay: int,
    data_delay: int,
    minimum_margin_steps: int,
    margin_axis: Literal["data", "clock", "square"],
) -> RxInterfaceTimingEvidence:
    """Assess supplied evidence against an explicit, preselected matrix policy.

    Malformed reports/configuration raise ValueError. Well-formed failures,
    wrong rates, isolated pass cells and unmeasured boundary margins return
    negative receipts retaining the original report. No I/O or setting writes
    occur. The caller must independently attest the selected delay readback,
    serial/boot/firmware, test completion and restoration. A driver return code
    or matrix from a different observation cannot substitute for those facts.
    """

    _integer(expected_sample_rate_hz, "expected sample clock", 1, (1 << 64) - 1)
    _integer(clock_delay, "clock delay", 0, 15)
    _integer(data_delay, "data delay", 0, 15)
    _integer(minimum_margin_steps, "minimum margin", 0, 7)
    if margin_axis not in ("data", "clock", "square"):
        raise ValueError("margin axis must be data, clock, or square")
    rate, cells, digest = _parse(report)
    selected = cells[data_delay][clock_delay]
    margin: int | None = None
    if selected:
        margin = 0
        # Out-of-grid cells are unmeasured, never assumed passing or wrapped.
        data_edge = min(data_delay, 15 - data_delay)
        clock_edge = min(clock_delay, 15 - clock_delay)
        edge_radius = (data_edge if margin_axis == "data" else clock_edge
                       if margin_axis == "clock" else min(data_edge, clock_edge))
        for radius in range(1, edge_radius + 1):
            rows = (range(data_delay - radius, data_delay + radius + 1)
                    if margin_axis != "clock" else (data_delay,))
            columns = (range(clock_delay - radius, clock_delay + radius + 1)
                       if margin_axis != "data" else (clock_delay,))
            if not all(
                cells[row][column]
                for row in rows for column in columns
            ):
                break
            margin = radius
    reasons: list[str] = []
    if rate != expected_sample_rate_hz:
        reasons.append("sample_rate_mismatch")
    if not selected:
        reasons.append("selected_cell_failed")
    elif margin is not None and margin < minimum_margin_steps:
        reasons.append("insufficient_measured_margin")
    return RxInterfaceTimingEvidence(
        raw_report=report,
        report_sha256=digest,
        observed_sample_rate_hz=rate,
        expected_sample_rate_hz=expected_sample_rate_hz,
        selected_clock_delay=clock_delay,
        selected_data_delay=data_delay,
        minimum_margin_steps=minimum_margin_steps,
        margin_axis=margin_axis,
        passing_cells=cells,
        selected_cell_passed=selected,
        complete_margin_steps=margin,
        rejection_reasons=tuple(reasons),
    )
