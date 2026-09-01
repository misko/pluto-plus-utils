#!/usr/bin/env python3
"""Render the retained Issue 72 recovery summary."""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parent
DATA = json.loads((ROOT / "data.json").read_text())


def main() -> None:
    figure, axes = plt.subplots(2, 2, figsize=(16, 10), constrained_layout=True)
    figure.suptitle(
        "Issue #72 — direct-async stale-metadata recovery",
        fontsize=18,
        fontweight="bold",
    )

    red_green = DATA["usb_red_green"]
    labels = [f'{row["firmware"]}\n{row["duration_seconds"]} s' for row in red_green]
    completion = [
        0
        if row["observed_frames"] is None
        else 100 * row["observed_frames"] / row["requested_frames"]
        for row in red_green
    ]
    colors = ["#d62728", "#d62728", "#2ca02c", "#2ca02c"]
    bars = axes[0, 0].bar(labels, completion, color=colors)
    axes[0, 0].set_title("USB overload: requested-frame completion")
    axes[0, 0].set_ylabel("Returned requested frames (%)")
    axes[0, 0].set_ylim(0, 112)
    for bar, row in zip(bars, red_green, strict=True):
        label = row["failure"] or f'{row["observed_frames"]}/{row["requested_frames"]}'
        axes[0, 0].text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 2,
            label,
            ha="center",
            va="bottom",
            fontweight="bold",
        )

    matrix = DATA["overload_matrix_20s"]
    matrix_labels = [
        ("DMA" if "RAM" not in row["queue"] else "DMA + RAM") + f'\n{row["policy"]}'
        for row in matrix
    ]
    gaps = [row["gap_frames"] or 0 for row in matrix]
    bars = axes[0, 1].bar(
        matrix_labels,
        gaps,
        color=["#7f7f7f", "#1f77b4", "#7f7f7f", "#1f77b4"],
    )
    axes[0, 1].set_title("25 MS/s, 20 s: gap-bearing output frames")
    axes[0, 1].set_ylabel("Frames carrying an accounted gap")
    axes[0, 1].set_ylim(0, 520)
    for bar, row in zip(bars, matrix, strict=True):
        label = (
            str(row["gap_frames"])
            if row["completed"]
            else f'{row["failure"]}\nafter {row["observed_frames"]} frames'
        )
        axes[0, 1].text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 10,
            label,
            ha="center",
            va="bottom",
            fontweight="bold",
        )

    performance = DATA["gbe_25msps_47_dma"]
    durations = [row["duration_seconds"] for row in performance]
    speeds = [row["payload_mb_s"] for row in performance]
    axes[1, 0].plot(durations, speeds, "o-", color="#2ca02c", linewidth=2.5, markersize=9)
    axes[1, 0].axhline(70, color="#d62728", linestyle="--", label="70 MB/s gate")
    axes[1, 0].set_title("25 MS/s over physical GbE: 47-frame DMA queue")
    axes[1, 0].set_xlabel("Nominal RF capture window (s)")
    axes[1, 0].set_ylabel("Application payload (MB/s, decimal)")
    axes[1, 0].set_xticks(durations)
    axes[1, 0].set_ylim(68, 77)
    axes[1, 0].legend()
    for duration, speed in zip(durations, speeds, strict=True):
        axes[1, 0].annotate(
            f"{speed:.2f}",
            (duration, speed),
            xytext=(0, 9),
            textcoords="offset points",
            ha="center",
            fontweight="bold",
        )

    fleet = DATA["fleet_smoke_5msps_3s"]
    short_serials = [
        f'R{index}\n…{row["serial"][-4:]}' for index, row in enumerate(fleet, start=1)
    ]
    fleet_speeds = [row["payload_mb_s"] for row in fleet]
    bars = axes[1, 1].bar(short_serials, fleet_speeds, color="#2ca02c")
    axes[1, 1].axhline(20, color="#555555", linestyle="--", label="20 MB/s offered")
    axes[1, 1].set_title("Four-radio USB smoke: 5 MS/s, 3 s")
    axes[1, 1].set_ylabel("Application payload (MB/s, decimal)")
    axes[1, 1].set_ylim(0, 22)
    axes[1, 1].legend()
    for bar, speed in zip(bars, fleet_speeds, strict=True):
        axes[1, 1].text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.35,
            f"{speed:.2f}\n0 gaps",
            ha="center",
            va="bottom",
            fontweight="bold",
        )

    for axis in axes.flat:
        axis.grid(axis="y", alpha=0.25)

    figure.savefig(ROOT / "issue-72-recovery-summary.png", dpi=160)


if __name__ == "__main__":
    main()
