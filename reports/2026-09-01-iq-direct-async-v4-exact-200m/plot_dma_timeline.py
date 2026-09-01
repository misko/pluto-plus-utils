#!/usr/bin/env python3
"""Plot host time against FPGA source time for two exact DMA profiles."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, cast

import matplotlib  # type: ignore[import-not-found]

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # type: ignore[import-not-found]
import numpy as np


def load(path: Path) -> dict[str, Any]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("schema") != "pluto-plus-utils.direct-async-exact-dma-timeline.v1":
        raise SystemExit(f"unexpected report schema: {path}")
    if document.get("kernel_buffers_requested") != document.get("kernel_buffers_allocated"):
        raise SystemExit(f"non-exact DMA report: {path}")
    return cast(dict[str, Any], document)


def arrays(report: dict[str, Any]) -> tuple[np.ndarray, ...]:
    frames = report["frames"]
    host = np.asarray([float(item["host_elapsed_seconds"]) for item in frames])
    source = np.asarray([float(item["source_position_seconds"]) for item in frames])
    frame_seconds = report["samples_per_frame"] / report["sample_rate_hz"]
    ideal = np.arange(len(frames), dtype=float) * frame_seconds
    missing = np.asarray([float(item["missing_frame_equivalents"]) for item in frames])
    return host, source, ideal, missing


def add_timeline(axis: plt.Axes, report: dict[str, Any], label: str) -> None:
    host, source, ideal, missing = arrays(report)
    axis.plot(
        host,
        ideal,
        "--",
        color="#64748b",
        linewidth=1.3,
        label="recovered frames if gapless",
    )
    axis.plot(host, source, color="#2563eb", linewidth=1.8, label="FPGA source time")
    indexes = np.flatnonzero(missing > 0)
    if indexes.size:
        axis.scatter(
            host[indexes],
            source[indexes],
            color="#dc2626",
            marker="x",
            s=38,
            linewidths=1.4,
            label="counter gap",
            zorder=5,
        )
    requested = report["kernel_buffers_requested"]
    allocated = report["kernel_buffers_allocated"]
    payload_mb = report["dma_iq_payload_bytes"] / 1_000_000
    axis.set_title(
        f"{label}: {requested}/{allocated} buffers, {payload_mb:.0f} MB IQ payload",
        fontweight="bold",
    )
    axis.set_xlabel("Host elapsed time (s)")
    axis.set_ylabel("FPGA source time (s)")
    axis.grid(True, alpha=0.35)
    axis.legend(loc="upper left", fontsize=8)
    summary = (
        f"{report['payload_mbps']:.2f} MB/s | gaps {report['gap_frames']} | "
        f"missing {report['missing_samples'] / 1_000_000:.0f}M samples | "
        f"coverage {report['source_coverage_percent']:.2f}%"
    )
    axis.text(
        0.99,
        0.02,
        summary,
        transform=axis.transAxes,
        va="bottom",
        ha="right",
        fontsize=8,
        bbox={"facecolor": "white", "alpha": 0.85, "edgecolor": "#cbd5e1"},
    )


def individual(report: dict[str, Any], label: str, output: Path) -> None:
    host, _, _, missing = arrays(report)
    figure, (timeline, gaps) = plt.subplots(
        2,
        1,
        figsize=(13, 8),
        dpi=160,
        sharex=True,
        gridspec_kw={"height_ratios": [2.3, 1]},
    )
    add_timeline(timeline, report, label)
    indexes = np.flatnonzero(missing > 0)
    if indexes.size:
        gaps.vlines(host[indexes], 0, missing[indexes], color="#dc2626", linewidth=1.3)
        gaps.scatter(host[indexes], missing[indexes], color="#dc2626", s=20)
    gaps.set_xlabel("Host elapsed time (s)")
    gaps.set_ylabel("Missing before frame\n(frame equivalents)")
    gaps.grid(True, alpha=0.35)
    figure.suptitle(
        "25 MS/s, 40-second source request — drop stale backlog",
        fontsize=15,
        fontweight="bold",
    )
    figure.tight_layout(rect=(0, 0, 1, 0.96))
    figure.savefig(output, bbox_inches="tight")
    plt.close(figure)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--default", type=Path, required=True)
    parser.add_argument("--dma-200mb", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    baseline = load(args.default)
    dma_200mb = load(args.dma_200mb)
    for field in (
        "serial",
        "firmware_version",
        "sample_rate_hz",
        "samples_per_frame",
        "requested_duration_seconds",
        "ppu_commit",
    ):
        if baseline[field] != dma_200mb[field]:
            raise SystemExit(f"comparison field differs: {field}")
    if baseline["kernel_buffers_requested"] != 15:
        raise SystemExit("default profile must use 15 DMA buffers")
    if dma_200mb["kernel_buffers_requested"] != 50:
        raise SystemExit("200 MB profile must use 50 DMA buffers")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    outputs = (
        args.output_dir / "default-15-dma-time-vs-fpga-time.png",
        args.output_dir / "exact-200mb-50-dma-time-vs-fpga-time.png",
        args.output_dir / "default-vs-exact-200mb-time-vs-fpga-time.png",
    )
    if any(path.exists() for path in outputs):
        raise SystemExit("plot output already exists")
    individual(baseline, "Default DMA", outputs[0])
    individual(dma_200mb, "Exact 200 MB DMA", outputs[1])

    figure, axes = plt.subplots(1, 2, figsize=(17, 7), dpi=160, sharex=True)
    add_timeline(axes[0], baseline, "Default DMA")
    add_timeline(axes[1], dma_200mb, "Exact 200 MB DMA")
    figure.suptitle(
        f"{baseline['serial']} — host time vs FPGA time\n"
        "25 MS/s, 40-second source request, drop stale backlog",
        fontsize=15,
        fontweight="bold",
    )
    figure.tight_layout(rect=(0, 0, 1, 0.92))
    figure.savefig(outputs[2], bbox_inches="tight")
    plt.close(figure)


if __name__ == "__main__":
    main()
