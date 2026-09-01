#!/usr/bin/env python3
"""Plot host arrival time against per-frame FPGA timestamp positions."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np


def arrays(report: dict[str, object]) -> tuple[np.ndarray, ...]:
    frames = report["frames"]
    assert isinstance(frames, list)
    elapsed = np.asarray([float(item["host_elapsed_seconds"]) for item in frames])
    source = np.asarray([float(item["source_timestamp_frame"]) for item in frames])
    recovered = np.arange(len(frames), dtype=float)
    missing = np.asarray([float(item["missing_frame_equivalents"]) for item in frames])
    return elapsed, source, recovered, missing


def add_timeline(axis: plt.Axes, report: dict[str, object], label: str) -> None:
    elapsed, source, recovered, missing = arrays(report)
    axis.plot(
        elapsed,
        recovered,
        "--",
        color="#64748b",
        linewidth=1.2,
        label="no-gap recovered order",
    )
    axis.plot(elapsed, source, color="#2563eb", linewidth=1.8, label="FPGA timestamp")
    gap_indexes = np.flatnonzero(missing > 0)
    if gap_indexes.size:
        axis.scatter(
            elapsed[gap_indexes],
            source[gap_indexes],
            color="#dc2626",
            marker="x",
            s=42,
            linewidths=1.5,
            label="gap detected",
            zorder=5,
        )
    axis.set_title(label, fontweight="bold")
    axis.set_xlabel("Host elapsed time (s)")
    axis.set_ylabel("FPGA timestamp position\n(1M-sample frames)")
    axis.grid(True, alpha=0.35)
    axis.legend(loc="upper right", fontsize=8)
    summary = (
        f"{report['payload_mbps']:.2f} MB/s | gaps {report['gap_frames']} | "
        f"missing {report['missing_samples'] / 1_000_000:.0f}M | "
        f"coverage {report['source_coverage_percent']:.2f}%"
    )
    axis.text(0.01, 0.98, summary, transform=axis.transAxes, va="top", ha="left", fontsize=8,
              bbox={"facecolor": "white", "alpha": 0.8, "edgecolor": "#cbd5e1"})


def individual(report: dict[str, object], label: str, output: Path) -> None:
    elapsed, _, _, missing = arrays(report)
    figure, (timeline_axis, gap_axis) = plt.subplots(
        2,
        1,
        figsize=(13, 8),
        dpi=160,
        sharex=True,
        gridspec_kw={"height_ratios": [2.2, 1]},
    )
    add_timeline(timeline_axis, report, label)
    gap_indexes = np.flatnonzero(missing > 0)
    if gap_indexes.size:
        gap_axis.vlines(
            elapsed[gap_indexes],
            0,
            missing[gap_indexes],
            color="#dc2626",
            linewidth=1.5,
        )
        gap_axis.scatter(elapsed[gap_indexes], missing[gap_indexes], color="#dc2626", s=24)
    gap_axis.set_xlabel("Host elapsed time (s)")
    gap_axis.set_ylabel("Missing before frame\n(frame equivalents)")
    gap_axis.grid(True, alpha=0.35)
    figure.suptitle("25 MS/s, 20-second direct-async timeline", fontsize=15, fontweight="bold")
    figure.tight_layout(rect=(0, 0, 1, 0.96))
    figure.savefig(output, bbox_inches="tight")
    plt.close(figure)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--case",
        nargs=3,
        action="append",
        metavar=("SLUG", "LABEL", "REPORT"),
        required=True,
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--combined-output", type=Path, required=True)
    args = parser.parse_args()
    if len(args.case) != 4:
        raise SystemExit("exactly four --case entries are required")
    if args.combined_output.exists():
        raise SystemExit("combined output must be absent")

    cases: list[tuple[str, str, dict[str, object]]] = []
    for case_slug, label, report_path in args.case:
        report = json.loads(Path(report_path).read_text(encoding="utf-8"))
        output = args.output_dir / f"{case_slug}-time-vs-fpga-timestamp.png"
        if output.exists():
            raise SystemExit(f"output already exists: {output}")
        individual(report, label, output)
        cases.append((case_slug, label, report))

    figure, axes = plt.subplots(2, 2, figsize=(16, 11), dpi=160)
    for axis, (_, label, report) in zip(axes.flat, cases, strict=True):
        add_timeline(axis, report, label)
    figure.suptitle(
        "Pluto .20 — host time vs FPGA timestamp frame (25 MS/s, 20 s)",
        fontsize=16,
        fontweight="bold",
    )
    figure.tight_layout(rect=(0, 0, 1, 0.96))
    figure.savefig(args.combined_output, bbox_inches="tight")
    plt.close(figure)


if __name__ == "__main__":
    main()
