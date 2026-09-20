#!/usr/bin/env python3
"""Run one explicit runtime-rate cell; retain metadata, never IQ, with no retries."""

from __future__ import annotations

import argparse
import dataclasses
import fcntl
import hashlib
import json
import os
import signal
import time
from collections import Counter
from contextlib import contextmanager
from pathlib import Path

from pluto_plus.adaptive_scan_campaign import build_adaptive_scan_setup, run_adaptive_scan_campaign
from pluto_plus.adaptive_scan_client import AdaptiveScanClient
from pluto_plus.adaptive_scan_detector import Ci16EnergyDetector, Ci16EnergyDetectorConfig
from pluto_plus.adaptive_scan_radio import _default_factory
from pluto_plus.adaptive_scan_shadow import AdaptiveScanMode
from pluto_plus.hardware.discovery import discover_network_iio
from pluto_plus.hardware.iio import _receiver_settings_restored

SERIAL = "10400056f695001322002d0010ad1719f2"
URI = "ip:192.168.1.21"
RADIOS = {SERIAL: URI, "1040007c4a94000211000b009186843ef2": "ip:192.168.1.18"}
BUDGET_SECONDS = 1200
CELLS = {
    "baseline-dual2p5": (2_500_000, 3, 15_000),
    "baseline-single15": (15_000_000, 1, 15_000),
    "dual5": (5_000_000, 3, 120_000),
    "dual7p5": (7_500_000, 3, 120_000),
    "dual8": (8_000_000, 3, 120_000),
    "smoke-dual7p5": (7_500_000, 3, 15_000),
    "smoke-dual8": (8_000_000, 3, 15_000),
    "target-short-dual5": (5_000_000, 3, 3_000),
    "target-short-dual7p5": (7_500_000, 3, 3_000),
    "target-short-dual8": (8_000_000, 3, 3_000),
    "unusual": (12_345_679, 1, 5_000),
}
FREQUENCIES = (959_687_498, 1_209_687_498, 1_459_687_498, 1_709_687_500)


def plain(value):
    if dataclasses.is_dataclass(value):
        return {field.name: plain(getattr(value, field.name))
                for field in dataclasses.fields(value)}
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (tuple, list)):
        return [plain(item) for item in value]
    if isinstance(value, dict):
        return {str(key): plain(item) for key, item in value.items()}
    return value


@contextmanager
def reserve_attempt(ledger: Path, cell: str, serial: str = SERIAL):
    """Charge complete worst-case wall time even for failed/interrupted attempts."""
    allowance = CELLS[cell][2] // 1000 + 60
    ledger.parent.mkdir(parents=True, exist_ok=True)
    with ledger.open("a+") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        stream.seek(0)
        rows = [json.loads(line) for line in stream if line.strip()]
        if serial not in RADIOS or any(row["serial"] not in RADIOS for row in rows):
            raise ValueError("budget ledger contains an unapproved radio")
        used = sum(row["reserved_seconds"] for row in rows)
        if used + allowance > BUDGET_SECONDS:
            raise ValueError("20-minute cumulative attempt budget exhausted")
        stream.write(json.dumps({"serial": serial, "cell": cell,
                                 "reserved_seconds": allowance, "time_ns": time.time_ns()}) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
        yield allowance


def summarize(records, terminal, rate: int, rx_mask: int):
    """Partition the complete observed source span; reject overlaps or missing bytes."""
    if not records:
        raise ValueError("no visits to account for")
    buckets = Counter()
    previous = records[0].transition_before
    gaps = {"same_target": [], "changed_target": [], "recall": []}
    previous_target = None
    for row in records:
        intervals = {
            "between_visits": row.transition_before - previous,
            "recall": row.transition_after - row.transition_before,
            "settle": row.valid_start - row.transition_after,
            row.result.name.lower(): row.valid_end - row.valid_start,
        }
        if any(value < 0 for value in intervals.values()):
            raise ValueError("source intervals overlap or run backwards")
        buckets.update(intervals)
        if previous_target is not None:
            key = "same_target" if row.target == previous_target else "changed_target"
            gaps[key].append((row.valid_start - previous) * 1000 / rate)
        gaps["recall"].append((row.transition_after - row.transition_before) * 1000 / rate)
        previous, previous_target = row.valid_end, row.target
    buckets["terminal_tail"] = terminal.final_counter - previous
    span = terminal.final_counter - records[0].transition_before
    if buckets["terminal_tail"] < 0 or sum(buckets.values()) != span:
        raise ValueError("source-counter partition is inconsistent")
    counts = Counter(row.result.name.lower() for row in records)
    if (len(records), counts["complete"], counts["skip_capacity"] + counts["skip_age"],
        counts["invalid_gap"], counts["cancelled"]) != (
        terminal.planned, terminal.delivered, terminal.skipped, terminal.invalid, terminal.cancelled
    ):
        raise ValueError("terminal visit accounting mismatch")
    expected = buckets["complete"] * 4 * rx_mask.bit_count()
    if expected != terminal.iq_bytes or sum(row.iq_bytes for row in records) != expected:
        raise ValueError("IQ byte accounting mismatch")
    return {"source_span_samples": span, "partition_samples": dict(buckets),
            "visit_counts": dict(counts), "iq_bytes": expected,
            "full_session_retained_duty": buckets["complete"] / span,
            "gaps_ms": gaps}


def ordinary_settings(rx_mask, uri=URI, serial=SERIAL):
    radio = _default_factory(uri, serial, rx_mask)
    try:
        radio.open()
        return radio.read_receiver_settings_readback()
    finally:
        radio.close()


def run_cell(cell, *, utc=False, serial=SERIAL):
    uri = RADIOS[serial]
    rate, rx_mask, duration = CELLS[cell]
    client = AdaptiveScanClient(uri.removeprefix("ip:"))
    caps = client.runtime_capabilities()
    if caps.protocol_version != 2:
        raise ValueError("candidate does not advertise runtime-rate capabilities")
    detector = Ci16EnergyDetector(Ci16EnergyDetectorConfig(-38.0))
    identity = time.time_ns()
    setup = build_adaptive_scan_setup(
        session=identity, generation=identity + 1, seed=identity + 2,
        source_rate_hz=rate, analog_bandwidth_hz=min(rate, 56_000_000),
        duration_ms=duration, dwell_ms=120, frequencies_hz=FREQUENCIES,
        baseline_weights=(1, 1, 1, 1), analysis_digest=detector.config.analysis_digest,
        transition_budget_ms=20, rx_mask=rx_mask,
    )
    records, timing = [], {}
    report = {"cell": cell, "capabilities": plain(caps), "requested_setup": plain(setup)}
    original = ordinary_settings(rx_mask, uri, serial)
    report["ordinary_libiio_before"] = plain(original)
    try:
        receipt = run_adaptive_scan_campaign(
            uri, serial, setup, detector, mode=AdaptiveScanMode.ADAPTIVE,
            samples_per_block=1_000_000, feedback_period_visits=8,
            visit_sink=lambda visit: records.append(visit.record),
            counter_clock_sink=(lambda evidence: timing.update(evidence.model_dump(mode="json")))
            if utc else None,
        )
        # Preserve terminal and restoration evidence even when validation fails.
        report["receipt"] = plain(receipt)
        restoration = receipt.restoration
        exact_restore = (
            _receiver_settings_restored(restoration.expected, restoration.observed)
            and restoration.expected_kernel_buffers == restoration.observed_kernel_buffers
            and restoration.fastlock_inactive
        )
        if receipt.preparation.configured.sample_rate_hz != rate or not exact_restore:
            raise ValueError("exact requested rate or restoration check failed")
        report.update({"status": "completed", "receipt": plain(receipt),
                       "accounting": summarize(records, receipt.terminal, rate, rx_mask),
                       "planned_valid_delivery": receipt.run.metrics.planned_valid_delivery})
    except Exception as error:
        report.update({"status": "rejected_or_failed", "error": type(error).__name__,
                       "message": str(error), "notes": getattr(error, "__notes__", [])})
        if (cell == "unusual" and not records
                and type(error).__name__ in ("RadioConfigurationError", "ValueError")
                and "rate" in str(error).lower()):
            report["status"] = "rate_rejected"
    try:
        observed = ordinary_settings(rx_mask, uri, serial)
        report["ordinary_libiio_readback"] = plain(observed)
        report["restored_to_pre_attempt"] = _receiver_settings_restored(original, observed)
        if not report["restored_to_pre_attempt"]:
            report["status"] = "rejected_or_failed"
    except Exception as error:
        report.update({"status": "rejected_or_failed", "post_access_error": str(error)})
    report.update({"visits": plain(records), "counter_utc": timing})
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cell", choices=("caps", *CELLS), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True,
                        help="Reuse this same durable ledger for every attempt; never reset it.")
    parser.add_argument("--utc", action="store_true")
    parser.add_argument("--serial", choices=tuple(RADIOS), default=SERIAL)
    parser.add_argument("--candidate", type=Path,
                        help="Candidate manifest binding evidence to the deployed exact image.")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists; retain prior evidence")
    binding = {}
    if args.candidate:
        raw = args.candidate.read_bytes()
        candidate = json.loads(raw)
        host = RADIOS[args.serial][3:]
        devices = discover_network_iio([f"{host}/32"], max_hosts=1, workers=1)
        if len(devices) != 1 or devices[0].serial != args.serial:
            parser.error("candidate binding did not attest the exact serial")
        if devices[0].firmware_version != candidate["firmware"]:
            parser.error("live firmware differs from candidate manifest")
        binding = {"firmware": devices[0].firmware_version,
                   "image_sha256": candidate["asset_sha256"],
                   "manifest_sha256": hashlib.sha256(raw).hexdigest(),
                   "observed_realtime_ns": time.time_ns()}
    if args.cell == "caps":
        report = {"capabilities": plain(
            AdaptiveScanClient(RADIOS[args.serial][3:]).runtime_capabilities()
        )}
    else:
        def timeout(_signum, _frame):
            raise TimeoutError("bounded qualification deadline exceeded")

        with reserve_attempt(args.ledger, args.cell, args.serial) as allowance:
            previous = signal.signal(signal.SIGALRM, timeout)
            signal.alarm(allowance)
            try:
                report = run_cell(args.cell, utc=args.utc, serial=args.serial)
            except Exception as error:
                report = {"cell": args.cell, "status": "rejected_or_failed",
                          "error": type(error).__name__, "message": str(error),
                          "notes": getattr(error, "__notes__", [])}
            finally:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, previous)
    report.update({"schema": "org.leo.issue111-adaptive-qualification/v1",
                   "serial": args.serial, "uri": RADIOS[args.serial],
                   "candidate_binding": binding})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as stream:
        json.dump(report, stream, sort_keys=True)
        stream.write("\n")
    return int(report.get("status") == "rejected_or_failed")


if __name__ == "__main__":
    raise SystemExit(main())
