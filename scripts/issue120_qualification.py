#!/usr/bin/env python3
"""Bounded RX-only issue-120 qualification on the explicitly authorized LAN radio."""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import signal
import time
from pathlib import Path

from pluto_plus.adaptive_scan import ScanOutcome
from pluto_plus.adaptive_scan_campaign import build_adaptive_scan_setup, run_adaptive_scan_campaign
from pluto_plus.adaptive_scan_client import AdaptiveScanClient
from pluto_plus.adaptive_scan_radio import _default_factory
from pluto_plus.adaptive_scan_shadow import AdaptiveScanMode
from pluto_plus.bootstrap_firmware import BoundSshBootstrapTransport
from pluto_plus.hardware.iio import _receiver_settings_restored
from pluto_plus.hardware.preflight import verify_metadata_runtime
from pluto_plus.radio_lock import acquire_radio_lock

SERIAL = "104000b29905000e17000800065934759d"
HOST = "192.168.1.15"
ROOT = Path("/home/mouse9911/release-evidence/issue-120")
FREQUENCIES = (959_687_498, 1_209_687_498, 1_459_687_498, 1_709_687_500)


def plain(value):
    if dataclasses.is_dataclass(value):
        return {f.name: plain(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {str(k): plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [plain(v) for v in value]
    return value


def settings():
    radio = _default_factory(f"ip:{HOST}", SERIAL, 3)
    try:
        radio.open()
        return radio.read_receiver_settings_readback()
    finally:
        radio.close()


def ordinary_capture():
    verify_metadata_runtime(3)
    import iio

    context = iio.Context(f"ip:{HOST}")
    context.set_timeout(3000)
    device = context.find_device("cf-ad9361-lpc")
    for channel in device.channels:
        if channel.scan_element:
            channel.enabled = channel.id in ("voltage0", "voltage1", "voltage2", "voltage3")
    buffer = iio.Buffer(device, 4096)
    try:
        buffer.refill()
        data = bytes(buffer.read())
        assert len(data) == 4096 * 8
        return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    finally:
        del buffer
        del context


def run(args):
    output = ROOT / args.name
    output.mkdir(parents=True, exist_ok=False)
    before = settings()
    identity = time.time_ns()
    setup = build_adaptive_scan_setup(
        session=identity,
        generation=identity + 1,
        seed=120,
        source_rate_hz=args.rate,
        analog_bandwidth_hz=args.rate,
        duration_ms=10_000,
        dwell_ms=120,
        frequencies_hz=FREQUENCIES,
        baseline_weights=(1, 1, 1, 1),
        analysis_digest=hashlib.sha256(b"issue120").digest(),
        transition_budget_ms=20,
        maximum_revisit_ms=3000,
        rx_mask=3,
        variable_dwell=args.protocol == 3,
    )
    setup = dataclasses.replace(setup, protocol_version=args.protocol)
    report = {"setup": plain(setup), "before": plain(before), "serial": SERIAL, "host": HOST}
    transport = BoundSshBootstrapTransport(
        interface=None,
        password="analog",
        host=HOST,
        known_hosts_file=ROOT / "private/radio15.known_hosts",
    )
    attestation = transport.run("sha256sum /usr/sbin/iiod; cat /opt/VERSIONS")
    report["daemon_attestation"] = attestation
    rows, timing, sessions = [], {}, []
    started = time.monotonic()

    def visit(v):
        row = plain(v.record)
        row["received_after_seconds"] = time.monotonic() - started
        row["actual_iq_bytes"] = len(v.iq)
        row["iq_sha256"] = hashlib.sha256(v.iq).hexdigest()
        if v.iq:
            assert v.record.source_rate_hz == args.rate
            assert v.record.valid_end - v.record.valid_start == args.rate * 120 // 1000
            assert len(v.iq) == args.rate * 120 // 1000 * 8 == v.record.iq_bytes
            if args.save_iq:
                (output / f"visit-{v.record.visit:04d}.ci16").write_bytes(v.iq)
        rows.append(row)
        if args.cancel and len(rows) == 3:
            raise RuntimeError("intentional client cancellation after three visits")

    def session_hook(session):
        sessions.append(session)
        if args.dma_fault:
            transport = BoundSshBootstrapTransport(
                interface=None,
                password="analog",
                host=HOST,
                known_hosts_file=ROOT / "private/radio15.known_hosts",
            )
            report["fault_injection"] = transport.run(
                'test "$(cat /sys/kernel/config/usb_gadget/'
                'composite_gadget/strings/0x409/serialnumber)"'
                f' = "{SERIAL}" && echo 0 > /sys/bus/iio/devices/iio:device5/buffer/enable'
            )

    try:
        receipt = run_adaptive_scan_campaign(
            f"ip:{HOST}",
            SERIAL,
            setup,
            lambda v: ScanOutcome.ACTIVE if v.record.target == 0 else ScanOutcome.QUIET,
            mode=AdaptiveScanMode.ADAPTIVE,
            manual_gain_db=40,
            samples_per_block=args.samples_per_block,
            client_factory=lambda host: AdaptiveScanClient(host, timeout_s=10),
            visit_sink=visit,
            feedback_period_visits=1,
            session_hook=session_hook,
            counter_clock_sink=lambda e: timing.update(e.model_dump(mode="json")),
        )
        report["receipt"] = plain(receipt)
        report["status"] = "completed"
    except Exception as exc:
        report.update(status="failed", error=repr(exc), notes=getattr(exc, "__notes__", []))
    finally:
        report.update(visits=rows, timing=timing, elapsed_seconds=time.monotonic() - started)
        if sessions:
            report["terminal"] = plain(sessions[0].terminal)
        try:
            after = settings()
            report["after"] = plain(after)
            report["settings_restored"] = _receiver_settings_restored(before, after)
            report["ordinary_capture_after"] = ordinary_capture()
        except Exception as exc:
            report["readback_error"] = repr(exc)
        (output / "report.json").write_text(json.dumps(report, indent=2, default=str) + "\n")
    print(
        json.dumps(
            {
                k: v
                for k, v in report.items()
                if k
                in ("status", "error", "elapsed_seconds", "settings_restored", "readback_error")
            }
        )
    )
    print(f"visits={len(rows)} evidence={output}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True)
    parser.add_argument("--rate", type=int, choices=(1_250_000, 2_500_000), required=True)
    parser.add_argument("--protocol", type=int, choices=(2, 3), required=True)
    parser.add_argument("--save-iq", action="store_true")
    parser.add_argument(
        "--samples-per-block", type=int, choices=(500_000, 1_000_000), default=1_000_000
    )
    parser.add_argument("--cancel", action="store_true")
    parser.add_argument("--dma-fault", action="store_true")
    args = parser.parse_args()
    ROOT.mkdir(parents=True, exist_ok=True)
    with acquire_radio_lock(SERIAL):
        ledger = ROOT / "attempts.jsonl"
        rows = (
            [json.loads(line) for line in ledger.read_text().splitlines()]
            if ledger.exists()
            else []
        )
        if sum(r["reserved_seconds"] for r in rows) + 60 > 1800:
            raise RuntimeError("30-minute cumulative hardware budget exhausted")
        with ledger.open("a") as stream:
            stream.write(
                json.dumps(
                    {"name": args.name, "reserved_seconds": 60, "started_ns": time.time_ns()}
                )
                + "\n"
            )
            stream.flush()
            os.fsync(stream.fileno())
        signal.signal(
            signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError("attempt deadline"))
        )
        signal.alarm(55)
        try:
            run(args)
        finally:
            signal.alarm(0)


if __name__ == "__main__":
    main()
