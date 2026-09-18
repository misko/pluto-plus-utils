#!/usr/bin/env python3
"""Run one production v0.52 adaptive cell and publish compact evidence."""

from __future__ import annotations

import argparse
import dataclasses
import enum
import hashlib
import json
import os
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

from pluto_plus.adaptive_scan_archive import AdaptiveScanArchive
from pluto_plus.adaptive_scan_campaign import build_adaptive_scan_setup, run_adaptive_scan_campaign
from pluto_plus.adaptive_scan_detector import Ci16EnergyDetector, Ci16EnergyDetectorConfig
from pluto_plus.adaptive_scan_shadow import AdaptiveScanMode

SERIAL = "104000bac4950008230026001b440a003a"
URI = "ip:192.168.1.17"
RATES = (10_000_000, 15_000_000, 20_000_000)
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
LOWER_FREQUENCIES = FREQUENCIES[0::2]
UPPER_FREQUENCIES = FREQUENCIES[1::2]


def slot_configuration(epoch_seconds: int) -> tuple[int, int, str, tuple[int, ...]]:
    ordinal = epoch_seconds // 600
    edge = "lower" if ordinal % 2 == 0 else "upper"
    frequencies = LOWER_FREQUENCIES if edge == "lower" else UPPER_FREQUENCIES
    return ordinal, RATES[ordinal % len(RATES)], edge, frequencies


def json_value(value):
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: json_value(getattr(value, field.name))
            for field in dataclasses.fields(value)
        }
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (tuple, list)):
        return [json_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): json_value(item) for key, item in value.items()}
    if isinstance(value, float) and not (-float("inf") < value < float("inf")):
        return None
    return value


def publish(path: Path, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".v052-adaptive-", dir=path.parent)
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
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--iq-spool-root", type=Path, required=True)
    parser.add_argument("--duration-ms", type=int, default=300_000)
    parser.add_argument("--epoch", type=int, default=None)
    args = parser.parse_args()
    epoch = int(time.time()) if args.epoch is None else args.epoch
    ordinal, rate, selected_edge, frequencies = slot_configuration(epoch)
    identity = hashlib.sha256(f"{SERIAL}\0{ordinal}".encode()).digest()
    detector = Ci16EnergyDetector(Ci16EnergyDetectorConfig(-38.0))
    setup = build_adaptive_scan_setup(
        session=int.from_bytes(identity[:8], "little") or 1,
        generation=ordinal + 1,
        seed=int.from_bytes(identity[8:16], "little") or 1,
        source_rate_hz=rate,
        analog_bandwidth_hz=rate,
        duration_ms=args.duration_ms,
        dwell_ms=120,
        frequencies_hz=frequencies,
        baseline_weights=(1,) * len(frequencies),
        analysis_digest=detector.config.analysis_digest,
        transition_budget_ms=20,
        maximum_revisit_ms=3_000,
    )
    stamp = datetime.fromtimestamp(ordinal * 600, UTC).strftime("%Y%m%dT%H%M%SZ")
    session_id = f"scan-fw-{identity[:8].hex()}"
    archive = AdaptiveScanArchive(args.iq_spool_root, session_id, setup)
    clock_bracket: dict[str, int] = {}

    def record_clock_bracket(
        before_realtime_ns: int,
        before_monotonic_ns: int,
        after_realtime_ns: int,
        after_monotonic_ns: int,
    ) -> None:
        clock_bracket.update(
            begin_before_realtime_ns=before_realtime_ns,
            begin_before_monotonic_ns=before_monotonic_ns,
            begin_after_realtime_ns=after_realtime_ns,
            begin_after_monotonic_ns=after_monotonic_ns,
        )
    try:
        receipt = run_adaptive_scan_campaign(
            URI,
            SERIAL,
            setup,
            detector,
            mode=AdaptiveScanMode.ADAPTIVE,
            manual_gain_db=40.0,
            samples_per_block=1_000_000,
            feedback_period_visits=8,
            visit_sink=archive.append,
            session_clock_sink=record_clock_bracket,
        )
        terminal_realtime_ns = time.time_ns()
        terminal_monotonic_ns = time.monotonic_ns()
        evidence = {
            "schema": "leo.v052-adaptive-live/v2",
            "slot_ordinal": ordinal,
            "radio_serial": SERIAL,
            "rate_hz": rate,
            "selected_edge": selected_edge,
            "omitted_frequencies_hz": [
                item for item in FREQUENCIES if item not in frequencies
            ],
            "preparation": json_value(receipt.preparation),
            "run": json_value(receipt.run),
            "restoration": json_value(receipt.restoration),
            "energy_observations": json_value(detector.observations),
            "utc_timing": {
                **clock_bracket,
                "terminal_realtime_ns": terminal_realtime_ns,
                "terminal_monotonic_ns": terminal_monotonic_ns,
            },
        }
        archive_path = archive.finish(receipt.terminal, evidence)
    except BaseException:
        archive.abort()
        raise
    path = args.evidence_root / f"adaptive-v052-{stamp}-{rate // 1_000_000}m.json"
    publish(
        path,
        {
            "schema": "leo.v052-adaptive-live/v1",
            "created_at": datetime.now(UTC).isoformat(),
            "slot_ordinal": ordinal,
            "radio_serial": SERIAL,
            "rate_hz": rate,
            "selected_edge": selected_edge,
            "omitted_frequencies_hz": [
                item for item in FREQUENCIES if item not in frequencies
            ],
            "setup": json_value(setup),
            "run": json_value(receipt.run),
            "restoration": json_value(receipt.restoration),
            "energy_observations": json_value(detector.observations),
            "iq_archive": str(archive_path),
        },
    )
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
