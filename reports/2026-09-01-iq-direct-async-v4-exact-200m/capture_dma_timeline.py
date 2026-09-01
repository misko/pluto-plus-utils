#!/usr/bin/env python3
"""Capture one exact-admission direct-async session with per-frame evidence."""

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

WIRE_BYTES_PER_SAMPLE = 4


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--uri", required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--kernel-buffers", type=int, required=True)
    parser.add_argument("--sample-rate-hz", type=int, default=25_000_000)
    parser.add_argument("--samples-per-frame", type=int, default=1_000_000)
    parser.add_argument("--duration-seconds", type=float, default=40.0)
    parser.add_argument("--ppu-commit", required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()

    if not 2 <= args.kernel_buffers <= 64:
        raise SystemExit("kernel buffer count must be in [2, 64]")
    if args.sample_rate_hz <= 0 or args.samples_per_frame <= 0:
        raise SystemExit("sample rate and frame size must be positive")
    if args.samples_per_frame % 2:
        raise SystemExit("ABI-3 single-RX frame size must be even")
    requested_frames = math.ceil(
        args.duration_seconds * args.sample_rate_hz / args.samples_per_frame
    )
    if not 2 <= requested_frames <= 4_096:
        raise SystemExit("single-session frame target must be in [2, 4096]")
    if args.report.exists():
        raise SystemExit("report path must be absent")

    frame_bytes = args.samples_per_frame * WIRE_BYTES_PER_SAMPLE
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
    identity: dict[str, object] = {}
    exact_capability: object = None
    frames: list[dict[str, int | float | bool]] = []
    capture_elapsed_ns = 0
    total_started_ns = time.perf_counter_ns()

    try:
        radio.open()
        opened = True
        original = radio.read_settings()
        facts = radio.diagnostic_facts()
        exact_capability = facts.get("buffer_direct_async_exact_kernel_queue")
        identity = {
            "firmware_version": radio.identity.firmware_version,
            "model": radio.identity.model,
            "transport": radio.identity.transport.value,
            "phy_model": facts.get("phy_model"),
            "exact_dma_admission": exact_capability,
        }
        if exact_capability is not True:
            raise RuntimeError("radio does not advertise exact DMA admission")
        requested = original.model_copy(
            update={
                "sample_rate_hz": args.sample_rate_hz,
                "bandwidth_hz": args.sample_rate_hz,
                "channels": (0,),
            }
        )
        actual = radio.apply_settings(requested)
        if (
            round(actual.sample_rate_hz) != args.sample_rate_hz
            or round(actual.bandwidth_hz) != args.sample_rate_hz
            or tuple(actual.channels) != (0,)
        ):
            raise RuntimeError("RX settings did not read back exactly")

        with radio.begin_metadata_capture(
            args.samples_per_frame,
            kernel_buffers=args.kernel_buffers,
            direct_async_frames=requested_frames,
            ddr_ring_bytes=0,
            drop_backlog_on_overrun=True,
            tandem_request=TandemSessionRequestV1(mode=TandemMode.HOLD),
        ) as capture:
            if capture.kernel_buffers != args.kernel_buffers:
                raise RuntimeError("kernel-buffer request readback is not exact")
            if capture.allocated_kernel_buffers != args.kernel_buffers:
                raise RuntimeError(
                    "DMA allocation is not exact: "
                    f"requested {args.kernel_buffers}, allocated "
                    f"{capture.allocated_kernel_buffers}"
                )
            if capture.direct_async_frames != requested_frames:
                raise RuntimeError("direct-async target readback is not exact")
            if capture.direct_async_ring_extension:
                raise RuntimeError("DMA-only capture unexpectedly enabled the RAM ring")
            if not capture.drop_backlog_on_overrun:
                raise RuntimeError("drop-backlog policy readback is not exact")

            capture_started_ns = time.perf_counter_ns()
            first_sample: int | None = None
            previous_end: int | None = None
            for frame_index in range(1, requested_frames + 1):
                block = capture.read_block()
                completed_ns = time.perf_counter_ns()
                if block.samples.shape != (1, args.samples_per_frame):
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
                        "last_sample_sequence_exclusive": (block.last_sample_sequence_exclusive),
                        "missing_samples_before": block.missing_samples_before,
                        "missing_frame_equivalents": (
                            block.missing_samples_before / args.samples_per_frame
                        ),
                        "overflow_observed": bool(block.overflow_observed),
                        "host_elapsed_seconds": (
                            (completed_ns - capture_started_ns) / 1_000_000_000
                        ),
                        "source_position_seconds": (
                            (block.first_sample_sequence - first_sample) / args.sample_rate_hz
                        ),
                    }
                )
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
    recovered_samples = requested_frames * args.samples_per_frame
    source_span_samples = recovered_samples + missing_samples
    elapsed_seconds = capture_elapsed_ns / 1_000_000_000
    report = {
        "schema": "pluto-plus-utils.direct-async-exact-dma-timeline.v1",
        "uri": args.uri,
        "serial": args.serial,
        **identity,
        "ppu_commit": args.ppu_commit,
        "sample_rate_hz": args.sample_rate_hz,
        "samples_per_frame": args.samples_per_frame,
        "requested_duration_seconds": args.duration_seconds,
        "requested_frames": requested_frames,
        "recovered_frames": len(frames),
        "segment_count": 1,
        "kernel_buffers_requested": args.kernel_buffers,
        "kernel_buffers_allocated": args.kernel_buffers,
        "dma_iq_payload_bytes": args.kernel_buffers * frame_bytes,
        "ram_ring_slots": 0,
        "drop_backlog_on_overrun": True,
        "capture_elapsed_seconds": elapsed_seconds,
        "payload_mbps": requested_frames * frame_bytes / elapsed_seconds / 1_000_000,
        "gap_frames": gap_frames,
        "missing_samples": missing_samples,
        "overflow_frames": overflow_frames,
        "recovered_samples": recovered_samples,
        "source_span_samples": source_span_samples,
        "source_coverage_percent": recovered_samples / source_span_samples * 100,
        "settings_restored": restored,
        "total_elapsed_seconds": (time.perf_counter_ns() - total_started_ns) / 1_000_000_000,
        "frames": frames,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    with args.report.open("x", encoding="utf-8") as output:
        json.dump(report, output, indent=2, sort_keys=True)
        output.write("\n")
    os.chmod(args.report, 0o600)
    print(
        json.dumps(
            {key: value for key, value in report.items() if key != "frames"},
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
