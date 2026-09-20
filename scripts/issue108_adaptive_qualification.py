#!/usr/bin/env python3
"""Run one exact adaptive-scan qualification cell over USB or physical LAN."""

from __future__ import annotations

import argparse
import dataclasses
import enum
import json
import math
import os
import tempfile
import time
from collections import Counter
from pathlib import Path

import pluto_plus.adaptive_scan_campaign as campaign_module
import pluto_plus.adaptive_scan_radio as radio_module
from pluto_plus.adaptive_scan_campaign import (
    build_adaptive_scan_setup,
    run_adaptive_scan_campaign,
)
from pluto_plus.adaptive_scan_client import AdaptiveScanClient
from pluto_plus.adaptive_scan_detector import (
    Ci16EnergyDetector,
    Ci16EnergyDetectorConfig,
)
from pluto_plus.adaptive_scan_shadow import AdaptiveScanMode
from pluto_plus.counter_utc import TimingPolicy

LOCAL_URI = "ip:192.168.2.1"
FREQUENCIES = (
    959_687_498,
    1_190_312_500,
    1_209_687_498,
    1_440_312_500,
    1_459_687_498,
    1_690_312_496,
    1_709_687_500,
    1_940_312_500,
)
EDGES = {"lower": FREQUENCIES[0::2], "upper": FREQUENCIES[1::2]}


def _local_uri(uri: str) -> str:
    if uri != LOCAL_URI:
        raise ValueError(f"qualification route is not the exact local USB endpoint: {uri}")
    return uri


def _json(value: object) -> object:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: _json(getattr(value, field.name))
            for field in dataclasses.fields(value)
        }
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (tuple, list)):
        return [_json(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json(item) for key, item in value.items()}
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value


def _summary(values: list[float]) -> dict[str, float | int | None]:
    ordered = sorted(values)
    if not ordered:
        return {"count": 0, "minimum": None, "median": None, "p95": None, "maximum": None}

    def percentile(fraction: float) -> float:
        return ordered[round((len(ordered) - 1) * fraction)]

    return {
        "count": len(ordered),
        "minimum": ordered[0],
        "median": percentile(0.5),
        "p95": percentile(0.95),
        "maximum": ordered[-1],
    }


def _publish(path: Path, document: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o640)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(document, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--serial", required=True)
    parser.add_argument("--uri", default=LOCAL_URI)
    parser.add_argument("--rate", type=int, choices=(2_500_000, 15_000_000), required=True)
    parser.add_argument("--rx-mask", type=int, choices=(1, 3), required=True)
    parser.add_argument("--duration-ms", type=int, required=True)
    parser.add_argument("--edge", choices=tuple(EDGES), default="lower")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manual-gain-db", type=float, default=40.0)
    parser.add_argument("--threshold-dbfs", type=float, default=-38.0)
    parser.add_argument(
        "--timing-policy",
        type=Path,
        help="Validated hardware timing bounds; omitted means unqualified UTC",
    )
    args = parser.parse_args()
    if (args.rate, args.rx_mask) not in ((15_000_000, 1), (2_500_000, 3)):
        parser.error("qualification admits only single 15 MS/s or dual 2.5 MS/s")
    timing_policy = (
        TimingPolicy.model_validate_json(args.timing_policy.read_text())
        if args.timing_policy
        else TimingPolicy()
    )

    # The production guard already admits canonical physical-LAN addresses.
    # Narrow the test-only exception to the directly attached USB endpoint.
    if args.uri == LOCAL_URI:
        campaign_module.require_physical_lan_uri = _local_uri
        radio_module.require_physical_lan_uri = _local_uri
    else:
        campaign_module.require_physical_lan_uri(args.uri)

    detector = Ci16EnergyDetector(Ci16EnergyDetectorConfig(args.threshold_dbfs))
    identity = f"{args.serial}\0{args.rate}\0{args.rx_mask}\0{time.time_ns()}".encode()
    session = int.from_bytes(identity[-8:], "little") or 1
    generation = time.time_ns() & ((1 << 64) - 1) or 1
    setup = build_adaptive_scan_setup(
        session=session,
        generation=generation,
        seed=(session ^ generation) or 1,
        source_rate_hz=args.rate,
        analog_bandwidth_hz=args.rate,
        duration_ms=args.duration_ms,
        dwell_ms=120,
        frequencies_hz=EDGES[args.edge],
        baseline_weights=(1, 1, 1, 1),
        analysis_digest=detector.config.analysis_digest,
        transition_budget_ms=20,
        maximum_revisit_ms=3_000,
        rx_mask=args.rx_mask,
    )
    capabilities = AdaptiveScanClient(
        args.uri.removeprefix("ip:").split(":", maxsplit=1)[0]
    ).capabilities()
    timing_rows: list[tuple[int, int, int, int, int]] = []
    counter_clock: dict[str, object] = {}

    def observe(visit) -> None:
        record = visit.record
        timing_rows.append(
            (
                record.target,
                record.transition_before,
                record.transition_after,
                record.valid_start,
                record.valid_end,
            )
        )

    started_realtime_ns = time.time_ns()
    started_monotonic_ns = time.monotonic_ns()
    try:
        receipt = run_adaptive_scan_campaign(
            args.uri,
            args.serial,
            setup,
            detector,
            mode=AdaptiveScanMode.ADAPTIVE,
            manual_gain_db=args.manual_gain_db,
            # Keep the block wider than one dwell.  At 2.5 MS/s a 300k-sample
            # block is exactly 120 ms; a visit spanning the retune boundary can
            # then lease all four Pluto DMA blocks before its first record is
            # transportable.  One million samples keeps the same bounded 8 MB
            # dual-RX block while allowing the first visit to close and drain
            # from the following block.
            samples_per_block=1_000_000,
            feedback_period_visits=8,
            visit_sink=observe,
            counter_clock_sink=lambda evidence: counter_clock.update(
                evidence.model_dump(mode="json")
            ),
            timing_policy=timing_policy,
        )
    except BaseException as error:
        _publish(
            args.output,
            {
                "schema": "org.leo.issue108-adaptive-qualification/v2",
                "radio_serial": args.serial,
                "uri": args.uri,
                "capabilities": _json(capabilities),
                "requested_setup": _json(setup),
                "counter_utc_timing": counter_clock,
                "error": {
                    "type": type(error).__name__,
                    "message": str(error),
                    "notes": list(getattr(error, "__notes__", ())),
                },
                "wall": {
                    "started_realtime_ns": started_realtime_ns,
                    "ended_realtime_ns": time.time_ns(),
                    "elapsed_seconds": (
                        time.monotonic_ns() - started_monotonic_ns
                    )
                    / 1_000_000_000,
                },
            },
        )
        raise
    ended_monotonic_ns = time.monotonic_ns()
    ended_realtime_ns = time.time_ns()

    repeated_gaps: list[float] = []
    changed_gaps: list[float] = []
    recalls: list[float] = []
    rate = setup.source_rate_hz
    for index, row in enumerate(timing_rows):
        target, before, after, _start, _end = row
        recalls.append((after - before) * 1_000 / rate)
        if index:
            gap = (_start - timing_rows[index - 1][4]) * 1_000 / rate
            (repeated_gaps if target == timing_rows[index - 1][0] else changed_gaps).append(gap)

    receipt_counts = Counter(
        "none" if item.receipt is None else item.receipt.name.lower()
        for item in receipt.run.observations
    )
    document = {
        "schema": "org.leo.issue108-adaptive-qualification/v2",
        "radio_serial": args.serial,
        "uri": args.uri,
        "capabilities": _json(capabilities),
        "setup": _json(receipt.preparation.setup),
        "terminal": _json(receipt.terminal),
        "metrics": _json(receipt.run.metrics),
        "gate": _json(receipt.run.gate),
        "classification": {
            "physical_receiver": 0,
            "observations": len(detector.observations),
            "dropped": receipt.run.classification_dropped,
            "feedback_receipts": dict(receipt_counts),
        },
        "timing_ms": {
            "recall": _summary(recalls),
            "repeated_target_gap": _summary(repeated_gaps),
            "changed_target_gap": _summary(changed_gaps),
        },
        "preparation": _json(receipt.preparation),
        "restoration": _json(receipt.restoration),
        "wall": {
            "started_realtime_ns": started_realtime_ns,
            "ended_realtime_ns": ended_realtime_ns,
            "elapsed_seconds": (ended_monotonic_ns - started_monotonic_ns) / 1_000_000_000,
        },
        "counter_utc_timing": counter_clock,
    }
    _publish(args.output, document)
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
