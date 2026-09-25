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
from pluto_plus.counter_utc import TimingPolicy
from pluto_plus.models import GainMode

SERIAL = "10400056f695001322002d0010ad1719f2"
URI = "ip:192.168.1.21"
RATES = (2_500_000, 5_000_000, 7_500_000, 10_000_000)
ACTIVE_DWELLS_MS = (120, 240, 360)
FREQUENCIES_2P5 = (
    959_687_498,
    1_190_312_500,
    1_209_687_498,
    1_440_312_500,
    1_459_687_498,
    1_690_312_496,
    1_709_687_500,
    1_940_312_500,
)
FREQUENCIES_10M = (
    960_000_000,
    1_190_000_000,
    1_210_000_000,
    1_440_000_000,
    1_460_000_000,
    1_690_000_000,
    1_710_000_000,
    1_940_000_000,
)
FREQUENCIES_BY_RATE = {
    2_500_000: FREQUENCIES_2P5,
    5_000_000: FREQUENCIES_10M,
    7_500_000: FREQUENCIES_10M,
    10_000_000: FREQUENCIES_10M,
}


def deterministic_uniform_choice(serial: str, ordinal: int, domain: str, size: int) -> int:
    """Return an exactly uniform, reproducible choice using rejection sampling."""

    if size < 1 or size > 256:
        raise ValueError("choice size must be between one and 256")
    limit = 256 - (256 % size)
    counter = 0
    while True:
        digest = hashlib.sha256(
            f"leo-feature103-dual-rx-v2\0{serial}\0{ordinal}\0{domain}\0{counter}".encode()
        ).digest()
        for value in digest:
            if value < limit:
                return value % size
        counter += 1


def slot_configuration(
    epoch_seconds: int, serial: str = SERIAL
) -> tuple[int, int, str, tuple[int, ...]]:
    ordinal = epoch_seconds // 600
    rate = RATES[deterministic_uniform_choice(serial, ordinal, "rate", len(RATES))]
    edge = "upper" if deterministic_uniform_choice(serial, ordinal, "edge", 2) else "lower"
    all_frequencies = FREQUENCIES_BY_RATE[rate]
    frequencies = all_frequencies[0::2] if edge == "lower" else all_frequencies[1::2]
    return ordinal, rate, edge, frequencies


def campaign_configuration(
    epoch_seconds: int,
    serial: str,
    sample_rate_hz: int | None,
) -> tuple[int, int, str, tuple[int, ...], bytes]:
    ordinal, scheduled_rate, edge, _ = slot_configuration(epoch_seconds, serial)
    rate = scheduled_rate if sample_rate_hz is None else sample_rate_hz
    if rate not in RATES:
        raise ValueError("sample rate must be 2.5, 5, 7.5, or 10 MS/s")
    all_frequencies = FREQUENCIES_BY_RATE[rate]
    frequencies = all_frequencies[0::2] if edge == "lower" else all_frequencies[1::2]
    identity = hashlib.sha256(f"variable-dwell-v3\0{serial}\0{ordinal}\0{rate}".encode()).digest()
    return ordinal, rate, edge, frequencies, identity


def slot_capture_settings(epoch_seconds: int, serial: str) -> tuple[int, GainMode]:
    """Independent uniform choices, fixed across retries of a scan slot."""
    ordinal = epoch_seconds // 600
    dwell = ACTIVE_DWELLS_MS[deterministic_uniform_choice(serial, ordinal, "dwell-v3", 3)]
    gain = (GainMode.MANUAL, GainMode.SLOW_ATTACK)[
        deterministic_uniform_choice(serial, ordinal, "gain-v3", 2)
    ]
    return dwell, gain


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
    parser.add_argument(
        "--dry-run", action="store_true", help="Print resolved settings without RF access"
    )
    parser.add_argument("--serial", default=SERIAL, help="exact radio serial (default: legacy R17)")
    parser.add_argument("--uri", default=URI, help="physical LAN IIO URI for that serial")
    parser.add_argument(
        "--sample-rate",
        type=int,
        choices=RATES,
        help="sample rate in samples/second; defaults to the current 10-minute slot rate",
    )
    parser.add_argument(
        "--timing-policy",
        type=Path,
        help="Validated hardware timing bounds; omitted means unqualified UTC",
    )
    args = parser.parse_args()
    timing_policy = (
        TimingPolicy.model_validate_json(args.timing_policy.read_text())
        if args.timing_policy
        else TimingPolicy()
    )
    epoch = int(time.time()) if args.epoch is None else args.epoch
    ordinal, rate, selected_edge, frequencies, identity = campaign_configuration(
        epoch, args.serial, args.sample_rate
    )
    active_dwell_ms, gain_mode = slot_capture_settings(epoch, args.serial)
    detector = Ci16EnergyDetector(Ci16EnergyDetectorConfig(-38.0))
    setup = build_adaptive_scan_setup(
        session=int.from_bytes(identity[:8], "little") or 1,
        generation=ordinal + 1,
        seed=int.from_bytes(identity[8:16], "little") or 1,
        source_rate_hz=rate,
        analog_bandwidth_hz=rate,
        duration_ms=args.duration_ms,
        dwell_ms=active_dwell_ms,
        frequencies_hz=frequencies,
        baseline_weights=(1,) * len(frequencies),
        analysis_digest=detector.config.analysis_digest,
        transition_budget_ms=20,
        maximum_revisit_ms=3_000,
        rx_mask=3,
        variable_dwell=True,
    )
    if args.dry_run:
        print(
            json.dumps(
                {
                    "slot_ordinal": ordinal,
                    "rate_hz": rate,
                    "active_dwell_ms": active_dwell_ms,
                    "quiet_dwell_ms": 120,
                    "gain_mode": gain_mode.value,
                    "selected_edge": selected_edge,
                    "setup": json_value(setup),
                },
                sort_keys=True,
            )
        )
        return 0
    stamp = datetime.fromtimestamp(ordinal * 600, UTC).strftime("%Y%m%dT%H%M%SZ")
    session_id = f"scan-fw-{identity[:8].hex()}"
    archive = AdaptiveScanArchive(args.iq_spool_root, session_id, setup)
    clock_bracket: dict[str, int] = {}
    counter_clock: dict = {}

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
            args.uri,
            args.serial,
            setup,
            detector,
            mode=AdaptiveScanMode.ADAPTIVE,
            manual_gain_db=40.0,
            gain_mode=gain_mode,
            samples_per_block=1_000_000,
            feedback_period_visits=8,
            visit_sink=archive.append,
            session_clock_sink=record_clock_bracket,
            counter_clock_sink=lambda evidence: counter_clock.update(
                evidence.model_dump(mode="json")
            ),
            timing_policy=timing_policy,
        )
        terminal_realtime_ns = time.time_ns()
        terminal_monotonic_ns = time.monotonic_ns()
        evidence = {
            "schema": "leo.feature103-dual-rx-adaptive-live/v1",
            "slot_ordinal": ordinal,
            "radio_serial": args.serial,
            "radio_uri": args.uri,
            "rate_hz": rate,
            "active_dwell_ms": active_dwell_ms,
            "quiet_dwell_ms": 120,
            "gain_mode": gain_mode.value,
            "selected_edge": selected_edge,
            "omitted_frequencies_hz": [
                item for item in FREQUENCIES_BY_RATE[rate] if item not in frequencies
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
            "counter_utc_timing": counter_clock,
        }
        archive_path = archive.finish(receipt.terminal, evidence)
    except BaseException:
        archive.abort()
        raise
    serial_key = hashlib.sha256(args.serial.encode()).hexdigest()[:12]
    path = args.evidence_root / (f"adaptive-v052-{serial_key}-{stamp}-{rate // 1_000_000}m.json")
    publish(
        path,
        {
            "schema": "leo.feature103-dual-rx-adaptive-summary/v1",
            "created_at": datetime.now(UTC).isoformat(),
            "slot_ordinal": ordinal,
            "radio_serial": args.serial,
            "radio_uri": args.uri,
            "rate_hz": rate,
            "active_dwell_ms": active_dwell_ms,
            "quiet_dwell_ms": 120,
            "gain_mode": gain_mode.value,
            "selected_edge": selected_edge,
            "omitted_frequencies_hz": [
                item for item in FREQUENCIES_BY_RATE[rate] if item not in frequencies
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
