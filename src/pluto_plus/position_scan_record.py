"""Bounded v6 recorder. Keep native wire receipts alongside unmodified CI16 IQ."""

from __future__ import annotations

import argparse
import dataclasses
import enum
import hashlib
import json
import os
import secrets
import struct
import time
from collections.abc import Callable
from pathlib import Path
from threading import Timer
from typing import Any

from .position_scan import build_position_setup
from .position_scan_radio import PositionRadioOwner
from .radio_lock import acquire_radio_lock

FREQUENCIES = tuple(
    x + delta
    for x in (
        1_081_328_125,
        1_331_328_125,
        1_581_328_125,
        1_831_328_125,
        1_231_328_125,
        1_481_328_125,
        1_731_328_125,
        1_981_328_125,
    )
    for delta in (0, 15_000_000, 30_000_000)
)


def json_value(value: Any) -> Any:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {key: json_value(item) for key, item in dataclasses.asdict(value).items()}
    if isinstance(value, dict):
        return {key: json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_value(item) for item in value]
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, enum.Enum):
        return value.value
    return value


def _record_position_scan(
    uri: str,
    serial: str,
    output: Path,
    *,
    duration: float = 60,
    gain_db: float = 40,
    before_start_hook: Callable[[Any], None] | None = None,
    on_visit: Callable[[Any, dict[str, Any]], None] | None = None,
    owner_factory: Callable[..., Any] = PositionRadioOwner.start,
    shutdown_timeout: float = 30,
) -> dict[str, Any]:
    if not 0 < duration <= 1800 or shutdown_timeout <= 0:
        raise ValueError("capture must be bounded to at most 30 minutes")
    if output.resolve() == Path("/mnt/qnap01") or Path("/mnt/qnap01") in output.resolve().parents:
        raise ValueError("recording cannot write beneath QNAP")
    output.mkdir(parents=True, exist_ok=False)
    plan = {
        "schema": "spf.position-plan/v1",
        "frequencies_hz": FREQUENCIES,
        "target_labels": [f"ch{channel}-{axis}" for channel in range(1, 9) for axis in "XYZ"],
        "source_rate_hz": 10_000_000,
        "bandwidth_hz": 8_000_000,
        "rx_mask": 3,
        "guard_samples": 200_000,
        "window_samples": 200_000,
        "rf_mapping_authority": "hypothesis",
        "analysis_path": "interior-position",
    }
    plan_bytes = json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()
    (output / "plan.json").write_bytes(plan_bytes)
    setup = build_position_setup(
        session=secrets.randbits(63) or 1,
        generation=secrets.randbits(63) or 1,
        seed=secrets.randbits(32) or 1,
        frequencies_hz=FREQUENCIES,
        analysis_digest=hashlib.sha256(plan_bytes).digest(),
    )
    report: dict[str, Any] = {
        "schema": "spf.position-capture/v1",
        "uri": uri,
        "serial": serial,
        "duration_requested_s": duration,
        "host_restoration": None,
        "terminal": None,
        "error": None,
        "stop_error": None,
    }
    owner = None
    timer = abort_timer = None
    preparation_started = time.monotonic()

    def prepared(preparation: Any) -> None:
        (output / "setup.bin").write_bytes(preparation.setup.pack())
        report["preparation"] = json_value(preparation)
        report["preparation_wall_s"] = time.monotonic() - preparation_started
        if before_start_hook is not None:
            before_start_hook(preparation)

    try:
        owner = owner_factory(uri, serial, setup, gain_db=gain_db, before_start_hook=prepared)
        # A fixture owner may invoke neither preparation hook nor a hardware context.
        if not (output / "setup.bin").exists():
            prepared(owner.preparation)

        def bounded_stop() -> None:
            nonlocal abort_timer
            abort_timer = Timer(shutdown_timeout, owner.abort_read)
            abort_timer.daemon = True
            abort_timer.start()
            try:
                report["stop_ack"] = json_value(owner.stop())
            except Exception as error:
                report["stop_error"] = repr(error)

        timer = Timer(duration, bounded_stop)
        timer.daemon = True
        timer.start()
        with (
            (output / "visits.bin").open("xb") as stream,
            (output / "iq-hashes.jsonl").open("x") as hashes,
        ):
            for item in owner.visits():
                raw = item.record.pack()
                stream.write(struct.pack("<I", len(raw)) + raw + struct.pack("<Q", len(item.iq)))
                offset = stream.tell()
                stream.write(item.iq)
                hashes.write(
                    json.dumps(
                        {
                            "visit": item.record.visit,
                            "iq_offset": offset,
                            "iq_bytes": len(item.iq),
                            "sha256": hashlib.sha256(item.iq).hexdigest(),
                        }
                    )
                    + "\n"
                )
                if on_visit is not None:
                    on_visit(item, plan)
            terminal = owner.session.terminal
            if terminal is None:
                raise RuntimeError("v6 recorder did not obtain a terminal")
            raw = terminal.pack()
            stream.write(struct.pack("<I", len(raw)) + raw + struct.pack("<Q", 0))
            stream.flush()
            os.fsync(stream.fileno())
            hashes.flush()
            os.fsync(hashes.fileno())
            report["terminal"] = json_value(terminal)
            if terminal.error or terminal.state.value == 3:
                raise RuntimeError(f"device scan failed: {terminal!r}")
    except BaseException as error:
        report["error"] = repr(error)
        raise
    finally:
        if timer is not None:
            timer.cancel()
        if abort_timer is not None:
            abort_timer.cancel()
        if owner is not None:
            try:
                receipt = owner.close()
                report["host_restoration"] = json_value(receipt.restoration)
            except BaseException as cleanup:
                report["restoration_error"] = repr(cleanup)
                if report["error"] is None:
                    report["error"] = repr(cleanup)
        report["wall_s"] = time.monotonic() - preparation_started
        (output / "capture.json").write_text(json.dumps(report, indent=2) + "\n")
    if report["error"]:
        raise RuntimeError(report["error"])
    return report


def record_position_scan(
    uri: str,
    serial: str,
    output: Path,
    *,
    after_close_hook: Callable[[], None] | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Hold the same station lock through preparation, capture and restoration."""
    with acquire_radio_lock(serial):
        try:
            return _record_position_scan(uri, serial, output, **kwargs)
        finally:
            if after_close_hook is not None:
                try:
                    after_close_hook()
                except BaseException as error:
                    receipt = output / "capture.json"
                    if receipt.exists():
                        report = json.loads(receipt.read_text())
                        report["fixture_cleanup_error"] = repr(error)
                        report["error"] = report["error"] or repr(error)
                        receipt.write_text(json.dumps(report, indent=2) + "\n")
                    raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--uri", required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--duration", type=float, default=60)
    parser.add_argument("--gain-db", type=float, default=40)
    args = parser.parse_args()
    report = record_position_scan(
        args.uri, args.serial, args.output, duration=args.duration, gain_db=args.gain_db
    )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
