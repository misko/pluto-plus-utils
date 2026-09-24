#!/usr/bin/env python3
"""Bounded v0.56 adaptive RX qualification with immutable evidence only.

No deployment, reboot, power operation, or discovery sweep is provided.  A
single explicit inventory URI is used only after it is bound to the requested
allowlisted serial and the candidate manifest's live firmware identity.
"""

from __future__ import annotations

import argparse
import dataclasses
import fcntl
import hashlib
import json
import os
import re
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

SERIALS = {"1040007c4a94000211000b009186843ef2", "104000b29905000e17000800065934759d"}
RATES = {2_500_000, 5_000_000, 7_500_000, 8_000_000, 10_000_000, 15_000_000, 20_000_000}
MINIMUM_BUDGET_SECONDS = 11_520
FREQUENCIES = (959_687_498, 1_209_687_498, 1_459_687_498, 1_709_687_500)


def plain(value):
    if dataclasses.is_dataclass(value):
        return {
            field.name: plain(getattr(value, field.name)) for field in dataclasses.fields(value)
        }
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (tuple, list)):
        return [plain(item) for item in value]
    if isinstance(value, dict):
        return {str(key): plain(item) for key, item in value.items()}
    return value


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory_uri(path: Path, serial: str, uri: str) -> str:
    document = json.loads(path.read_text(encoding="utf-8"))
    radios = document.get("radios") if isinstance(document, dict) else None
    if document.get("schema") != "plutosdr-fw.v056-radio-inventory/v1" or not isinstance(
        radios, dict
    ):
        raise ValueError("inventory schema is not v0.56")
    if set(radios) != SERIALS or radios.get(serial) != uri:
        raise ValueError("inventory does not bind this exact serial/URI pair")
    if not uri.startswith("ip:") or not uri[3:]:
        raise ValueError("URI must use nonempty ip: form")
    return digest(path)


def candidate_binding(path: Path, serial: str, uri: str) -> dict[str, object]:
    raw = path.read_bytes()
    candidate = json.loads(raw)
    source = candidate.get("firmware_source_commit")
    if (
        not isinstance(candidate, dict)
        or candidate.get("firmware") != "v0.56-plutoplus-spf-adaptive-runtime-rates"
        or not isinstance(candidate.get("asset_sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", candidate["asset_sha256"])
        or not isinstance(source, str)
        or not re.fullmatch(r"[0-9a-f]{40}", source)
    ):
        raise ValueError("candidate lacks exact v0.56 firmware, image SHA-256, or source commit")
    devices = discover_network_iio([f"{uri[3:]}/32"], max_hosts=1, workers=1)
    if (
        len(devices) != 1
        or devices[0].serial != serial
        or devices[0].firmware_version != candidate["firmware"]
    ):
        raise ValueError("live radio does not attest the candidate serial and firmware")
    return {
        "firmware": candidate["firmware"],
        "image_sha256": candidate["asset_sha256"],
        "candidate_manifest_sha256": hashlib.sha256(raw).hexdigest(),
        "observed_realtime_ns": time.time_ns(),
    }


@contextmanager
def reserve_attempt(
    ledger: Path,
    *,
    campaign_id: str,
    budget_seconds: int,
    serial: str,
    cell: str,
    duration_seconds: int,
):
    if budget_seconds < MINIMUM_BUDGET_SECONDS:
        raise ValueError("budget must be at least 11520 seconds")
    # Charge the complete worst-case wall time even on interruption or failure.
    charge = duration_seconds + 60
    ledger.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with ledger.open("a+", encoding="utf-8") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        stream.seek(0)
        rows = [json.loads(line) for line in stream if line.strip()]
        if any(
            row.get("schema") != "org.leo.issue111.adaptive-ledger-row/v1"
            or row.get("campaign_id") != campaign_id
            for row in rows
        ):
            raise ValueError("ledger is not a fresh append-only campaign ledger")
        used = sum(row.get("reserved_seconds", -1) for row in rows)
        if type(used) is not int or used + charge > budget_seconds:
            raise ValueError("campaign budget exhausted")
        stream.write(
            json.dumps(
                {
                    "schema": "org.leo.issue111.adaptive-ledger-row/v1",
                    "campaign_id": campaign_id,
                    "serial": serial,
                    "cell": cell,
                    "reserved_seconds": charge,
                    "time_ns": time.time_ns(),
                },
                sort_keys=True,
            )
            + "\n"
        )
        stream.flush()
        os.fsync(stream.fileno())
        yield charge


def summarize(records, terminal, rate: int, rx_mask: int) -> dict[str, object]:
    if not records:
        raise ValueError("no visits to account for")
    buckets = Counter()
    previous = records[0].transition_before
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
        previous = row.valid_end
    buckets["terminal_tail"] = terminal.final_counter - previous
    if (
        buckets["terminal_tail"] < 0
        or sum(buckets.values()) != terminal.final_counter - records[0].transition_before
    ):
        raise ValueError("source-counter partition is inconsistent")
    counts = Counter(row.result.name.lower() for row in records)
    if (
        len(records),
        counts["complete"],
        counts["skip_capacity"] + counts["skip_age"],
        counts["invalid_gap"],
        counts["cancelled"],
    ) != (
        terminal.planned,
        terminal.delivered,
        terminal.skipped,
        terminal.invalid,
        terminal.cancelled,
    ):
        raise ValueError("terminal visit accounting mismatch")
    if (
        terminal.state != 1
        or terminal.error != 0
        or terminal.skipped
        or terminal.invalid
        or terminal.cancelled
    ):
        raise ValueError("terminal did not complete without skipped, invalid, or cancelled visits")
    expected = buckets["complete"] * 4 * rx_mask.bit_count()
    if expected != terminal.iq_bytes or sum(row.iq_bytes for row in records) != expected:
        raise ValueError("IQ byte accounting mismatch")
    return {
        "source_span_samples": sum(buckets.values()),
        "partition_samples": dict(buckets),
        "iq_bytes": expected,
        "counter_continuity_passed": True,
        "iq_geometry_passed": True,
    }


def ordinary_settings(rx_mask: int, uri: str, serial: str):
    radio = _default_factory(uri, serial, rx_mask)
    try:
        radio.open()
        return radio.read_receiver_settings_readback()
    finally:
        radio.close()


def run_cell(
    *, cell: str, serial: str, uri: str, rate_hz: int, rx_mask: int, duration_seconds: int
) -> dict[str, object]:
    if rate_hz not in RATES or rx_mask not in (1, 3) or not 1 <= duration_seconds <= 300:
        raise ValueError("unsupported bounded cell geometry")
    caps = AdaptiveScanClient(uri[3:]).runtime_capabilities()
    if caps.protocol_version != 2:
        raise ValueError("candidate does not advertise runtime-rate capabilities")
    detector = Ci16EnergyDetector(Ci16EnergyDetectorConfig(-38.0))
    identity = time.time_ns()
    setup = build_adaptive_scan_setup(
        session=identity,
        generation=identity + 1,
        seed=identity + 2,
        source_rate_hz=rate_hz,
        analog_bandwidth_hz=min(rate_hz, 56_000_000),
        duration_ms=duration_seconds * 1000,
        dwell_ms=120,
        frequencies_hz=FREQUENCIES,
        baseline_weights=(1, 1, 1, 1),
        analysis_digest=detector.config.analysis_digest,
        transition_budget_ms=20,
        rx_mask=rx_mask,
    )
    records = []
    report: dict[str, object] = {
        "cell": cell,
        "capabilities": plain(caps),
        "requested_setup": plain(setup),
    }
    before = ordinary_settings(rx_mask, uri, serial)
    report["ordinary_libiio_before"] = plain(before)
    try:
        receipt = run_adaptive_scan_campaign(
            uri,
            serial,
            setup,
            detector,
            mode=AdaptiveScanMode.ADAPTIVE,
            samples_per_block=1_000_000,
            feedback_period_visits=8,
            visit_sink=lambda visit: records.append(visit.record),
        )
        restoration = receipt.restoration
        restored = (
            _receiver_settings_restored(restoration.expected, restoration.observed)
            and restoration.expected_kernel_buffers == restoration.observed_kernel_buffers
            and restoration.fastlock_inactive
        )
        accounting = summarize(records, receipt.terminal, rate_hz, rx_mask)
        exact_delivery = receipt.run.metrics.planned_valid_delivery == 1
        report.update(
            {
                "status": "completed"
                if receipt.preparation.configured.sample_rate_hz == rate_hz
                and restored
                and exact_delivery
                else "rejected_or_failed",
                "receipt": plain(receipt),
                "accounting": accounting,
                "receiver_restored": restored,
                "counter_continuity_passed": accounting["counter_continuity_passed"],
                "iq_geometry_passed": accounting["iq_geometry_passed"],
                "planned_valid_delivery": receipt.run.metrics.planned_valid_delivery,
            }
        )
    except Exception as error:
        report.update(
            {"status": "rejected_or_failed", "error": type(error).__name__, "message": str(error)}
        )
    try:
        observed = ordinary_settings(rx_mask, uri, serial)
        report["restored_to_pre_attempt"] = _receiver_settings_restored(before, observed)
        if not report["restored_to_pre_attempt"]:
            report["status"] = "rejected_or_failed"
    except Exception as error:
        report.update({"status": "rejected_or_failed", "post_access_error": str(error)})
    report["visits"] = plain(records)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cell", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--campaign-id", required=True)
    parser.add_argument("--budget-seconds", type=int, required=True)
    parser.add_argument("--serial", required=True, choices=SERIALS)
    parser.add_argument("--uri", required=True)
    parser.add_argument("--rate-hz", type=int, required=True)
    parser.add_argument("--rx-mask", type=int, required=True, choices=(1, 3))
    parser.add_argument("--duration-seconds", type=int, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists; retain prior evidence")
    try:
        inventory_sha = inventory_uri(args.inventory, args.serial, args.uri)
        binding = candidate_binding(args.candidate, args.serial, args.uri)

        def timeout(_signum, _frame):
            raise TimeoutError("bounded qualification deadline exceeded")

        with reserve_attempt(
            args.ledger,
            campaign_id=args.campaign_id,
            budget_seconds=args.budget_seconds,
            serial=args.serial,
            cell=args.cell,
            duration_seconds=args.duration_seconds,
        ):
            previous = signal.signal(signal.SIGALRM, timeout)
            signal.alarm(args.duration_seconds + 60)
            try:
                report = run_cell(
                    cell=args.cell,
                    serial=args.serial,
                    uri=args.uri,
                    rate_hz=args.rate_hz,
                    rx_mask=args.rx_mask,
                    duration_seconds=args.duration_seconds,
                )
            finally:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, previous)
    except Exception as error:
        report = {
            "status": "rejected_or_failed",
            "error": type(error).__name__,
            "message": str(error),
        }
        inventory_sha = None
        binding = {}
    passed = (
        report.get("status") == "completed"
        and report.get("receiver_restored") is True
        and report.get("restored_to_pre_attempt") is True
        and report.get("counter_continuity_passed") is True
        and report.get("iq_geometry_passed") is True
        and report.get("planned_valid_delivery") == 1
    )
    report.update(
        {
            "schema": "org.leo.issue111.adaptive-capture/v1",
            "passed": passed,
            "serial": args.serial,
            "uri": args.uri,
            "rate_hz": args.rate_hz,
            "rx_mask": args.rx_mask,
            "duration_seconds": args.duration_seconds,
            "inventory_sha256": inventory_sha,
            "ledger_sha256": digest(args.ledger) if args.ledger.exists() else None,
            **binding,
            "counter_continuity_passed": report.get("counter_continuity_passed") is True,
            "iq_geometry_passed": report.get("iq_geometry_passed") is True,
        }
    )
    args.output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, sort_keys=True)
        stream.write("\n")
    return int(not passed)


if __name__ == "__main__":
    raise SystemExit(main())
