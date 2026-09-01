#!/usr/bin/env python3
"""Capture one direct-async session and retain per-frame timing metadata only."""

from __future__ import annotations

import argparse
import json
import math
import os
import time
from pathlib import Path

from pluto_plus.hardware.base import restore_settings_exact
from pluto_plus.hardware.iio import IioRadioDevice
from pluto_plus.tandem import TandemMode, TandemSessionRequestV1

SAMPLE_RATE_HZ = 25_000_000
SAMPLES_PER_FRAME = 1_000_000
WIRE_BYTES_PER_SAMPLE = 4
FRAME_BYTES = SAMPLES_PER_FRAME * WIRE_BYTES_PER_SAMPLE


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--uri", required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--kernel-buffers", type=int, required=True)
    parser.add_argument("--ram-ring-slots", type=int, default=0)
    policy = parser.add_mutually_exclusive_group()
    policy.add_argument(
        "--drop-backlog-on-overrun",
        dest="drop_backlog_on_overrun",
        action="store_true",
        default=True,
    )
    policy.add_argument(
        "--preserve-backlog-on-overrun",
        dest="drop_backlog_on_overrun",
        action="store_false",
    )
    parser.add_argument("--duration-seconds", type=float, default=20.0)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()

    requested_frames = math.ceil(
        args.duration_seconds * SAMPLE_RATE_HZ / SAMPLES_PER_FRAME
    )
    if not 2 <= args.kernel_buffers <= 64:
        raise SystemExit("kernel buffer count must be in [2, 64]")
    if not 0 <= args.ram_ring_slots <= 50:
        raise SystemExit("RAM ring slots must be in [0, 50]")
    if args.ram_ring_slots and args.kernel_buffers < 3:
        raise SystemExit("RAM ring extension requires at least three kernel buffers")
    if not 2 <= requested_frames <= 4_096:
        raise SystemExit("single-session frame target must be in [2, 4096]")
    if args.report.exists():
        raise SystemExit("report path must be absent")

    radio = IioRadioDevice(
        args.uri,
        serial=args.serial,
        radio_id=args.serial,
        expected_metadata_abi=3,
        iq_decoder="raw-complex64",
    )
    original = None
    opened = False
    restored = False
    frames: list[dict[str, int | float | bool]] = []
    ring_status: dict[str, object] | None = None
    capture_elapsed_ns = 0
    total_started_ns = time.perf_counter_ns()

    try:
        radio.open()
        opened = True
        original = radio.read_settings()
        requested = original.model_copy(
            update={
                "sample_rate_hz": SAMPLE_RATE_HZ,
                "bandwidth_hz": SAMPLE_RATE_HZ,
                "channels": (0,),
            }
        )
        actual = radio.apply_settings(requested)
        if (
            round(actual.sample_rate_hz) != SAMPLE_RATE_HZ
            or round(actual.bandwidth_hz) != SAMPLE_RATE_HZ
            or tuple(actual.channels) != (0,)
        ):
            raise RuntimeError("RX settings did not read back exactly")

        ring_bytes = args.ram_ring_slots * FRAME_BYTES
        with radio.begin_metadata_capture(
            SAMPLES_PER_FRAME,
            kernel_buffers=args.kernel_buffers,
            direct_async_frames=requested_frames,
            ddr_ring_bytes=ring_bytes,
            drop_backlog_on_overrun=args.drop_backlog_on_overrun,
            tandem_request=TandemSessionRequestV1(mode=TandemMode.HOLD),
        ) as capture:
            if capture.kernel_buffers != args.kernel_buffers:
                raise RuntimeError("kernel-buffer readback is not exact")
            if capture.direct_async_frames != requested_frames:
                raise RuntimeError("direct-async target readback is not exact")
            if capture.direct_async_ring_extension is not bool(args.ram_ring_slots):
                raise RuntimeError("RAM-ring extension readback is not exact")
            if capture.drop_backlog_on_overrun is not args.drop_backlog_on_overrun:
                raise RuntimeError("overrun-policy readback is not exact")
            if args.ram_ring_slots and (
                capture.ddr_ring_requested_bytes != ring_bytes
                or capture.ddr_ring_admitted_bytes != ring_bytes
                or capture.ddr_ring_capacity_frames != args.ram_ring_slots
            ):
                raise RuntimeError("RAM-ring geometry readback is not exact")

            capture_started_ns = time.perf_counter_ns()
            first_sample: int | None = None
            previous_end: int | None = None
            for frame_index in range(1, requested_frames + 1):
                block = capture.read_block()
                completed_ns = time.perf_counter_ns()
                if block.samples.shape != (1, SAMPLES_PER_FRAME):
                    raise RuntimeError("unexpected RX block shape")
                if first_sample is None:
                    first_sample = block.first_sample_sequence
                if previous_end is not None:
                    expected = previous_end + block.missing_samples_before
                    if block.first_sample_sequence != expected:
                        raise RuntimeError("metadata gap does not close against FPGA counters")
                previous_end = block.last_sample_sequence_exclusive
                frames.append(
                    {
                        "recovered_frame": frame_index,
                        "first_sample_sequence": block.first_sample_sequence,
                        "last_sample_sequence_exclusive": (
                            block.last_sample_sequence_exclusive
                        ),
                        "missing_samples_before": block.missing_samples_before,
                        "missing_frame_equivalents": (
                            block.missing_samples_before / SAMPLES_PER_FRAME
                        ),
                        "overflow_observed": bool(block.overflow_observed),
                        "host_elapsed_seconds": (
                            (completed_ns - capture_started_ns) / 1_000_000_000
                        ),
                        "source_position_seconds": (
                            (block.first_sample_sequence - first_sample) / SAMPLE_RATE_HZ
                        ),
                        "source_timestamp_frame": (
                            (block.first_sample_sequence - first_sample)
                            / SAMPLES_PER_FRAME
                        ),
                    }
                )
            if args.ram_ring_slots:
                ring_status = dict(capture.ddr_ring_status())
                if (
                    ring_status.get("state") != "complete"
                    or ring_status.get("terminal_reason") != "target_complete"
                    or ring_status.get("error_code") != 0
                    or int(ring_status.get("consumed_frames", -1))
                    > int(ring_status.get("produced_frames", -1))
                    or (
                        not args.drop_backlog_on_overrun
                        and ring_status.get("produced_frames")
                        != ring_status.get("consumed_frames")
                    )
                ):
                    raise RuntimeError("RAM-ring extension did not close cleanly")
            capture_elapsed_ns = time.perf_counter_ns() - capture_started_ns
    finally:
        try:
            if opened and original is not None:
                restored = restore_settings_exact(radio, original).restored == original
        finally:
            if opened:
                radio.close()

    if len(frames) != requested_frames:
        raise RuntimeError("recovered-frame count does not match request")
    missing_samples = sum(int(item["missing_samples_before"]) for item in frames)
    gap_frames = sum(bool(item["missing_samples_before"]) for item in frames)
    overflow_frames = sum(bool(item["overflow_observed"]) for item in frames)
    recovered_samples = requested_frames * SAMPLES_PER_FRAME
    source_span_samples = recovered_samples + missing_samples
    elapsed_seconds = capture_elapsed_ns / 1_000_000_000
    report = {
        "schema": "pluto-plus-utils.direct-async-timeline-evidence.v1",
        "uri": args.uri,
        "serial": args.serial,
        "sample_rate_hz": SAMPLE_RATE_HZ,
        "samples_per_frame": SAMPLES_PER_FRAME,
        "requested_duration_seconds": args.duration_seconds,
        "requested_frames": requested_frames,
        "recovered_frames": len(frames),
        "segment_count": 1,
        "kernel_buffers": args.kernel_buffers,
        "ram_ring_slots": args.ram_ring_slots,
        "ram_ring_bytes": args.ram_ring_slots * FRAME_BYTES,
        "drop_backlog_on_overrun": args.drop_backlog_on_overrun,
        "ram_ring_status": ring_status,
        "capture_elapsed_seconds": elapsed_seconds,
        "payload_mbps": requested_frames * FRAME_BYTES / elapsed_seconds / 1_000_000,
        "gap_frames": gap_frames,
        "missing_samples": missing_samples,
        "overflow_frames": overflow_frames,
        "recovered_samples": recovered_samples,
        "source_span_samples": source_span_samples,
        "source_coverage_percent": recovered_samples / source_span_samples * 100,
        "settings_restored": restored,
        "total_elapsed_seconds": (
            time.perf_counter_ns() - total_started_ns
        ) / 1_000_000_000,
        "frames": frames,
    }
    with args.report.open("x", encoding="utf-8") as output:
        json.dump(report, output, indent=2, sort_keys=True)
        output.write("\n")
    os.chmod(args.report, 0o600)
    print(json.dumps({key: value for key, value in report.items() if key != "frames"}, indent=2))


if __name__ == "__main__":
    main()
