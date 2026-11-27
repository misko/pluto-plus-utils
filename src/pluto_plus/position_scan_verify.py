"""Independent saved v6 IQ checker: stdlib structs, never the acquisition codec."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import struct
import zlib
from collections import Counter
from pathlib import Path
from typing import Any


def checked(raw: bytes, magic: bytes, size: int) -> bytes:
    if len(raw) != size or struct.unpack_from("<4sHHI", raw) != (magic, 6, size, 0xFF):
        raise ValueError("wire identity or size changed")
    if zlib.crc32(raw[:-4]) & 0xFFFF_FFFF != struct.unpack_from("<I", raw, size - 4)[0]:
        raise ValueError("wire CRC mismatch")
    flags = struct.unpack_from("<I", raw, 12)[0]
    if flags not in ((1, 3) if magic == b"SPVR" else (1,)):
        raise ValueError("wire header flags changed")
    return raw


def distribution(values: list[int]) -> dict[str, Any]:
    if not values:
        return {"count": 0, "unit": "ms", "median": None, "p95": None, "maximum": None}
    ordered = sorted(value / 10_000 for value in values)
    return {
        "count": len(ordered),
        "unit": "ms",
        "median": ordered[len(ordered) // 2],
        "p95": ordered[math.ceil(len(ordered) * 0.95) - 1],
        "maximum": ordered[-1],
    }


def verify_position_scan(path: Path, *, minimum_sweeps: int = 2) -> dict[str, Any]:
    if minimum_sweeps < 1:
        raise ValueError("at least one complete sweep required")
    setup = checked((path / "setup.bin").read_bytes(), b"SPSQ", 1120)
    if any(setup[108:112]) or any(setup[1104:1116]):
        raise ValueError("setup reserved bytes changed")
    plan_bytes = (path / "plan.json").read_bytes()
    plan_digest = hashlib.sha256(plan_bytes).digest()
    plan = json.loads(plan_bytes)
    if setup[112:144] != plan_digest:
        raise ValueError("saved plan digest changed")
    session, generation = struct.unpack_from("<QQ", setup, 16)
    if not session or not generation:
        raise ValueError("zero session identity")
    rate, bandwidth, duration, dwell, guard = struct.unpack_from("<IIIII", setup, 40)
    if (rate, bandwidth, duration, dwell, guard) != (10_000_000, 8_000_000, 0, 20, 20):
        raise ValueError("setup geometry changed")
    if struct.unpack_from("<II", setup, 96) != (24, 3):
        raise ValueError("setup target count or RX mask changed")
    targets = []
    for i in range(24):
        target, slot, hz, weight, crc, image = struct.unpack_from("<IIQII16s", setup, 144 + i * 40)
        if (
            (target, slot, weight) != (i, i % 8, 1)
            or hz != plan["frequencies_hz"][i]
            or not crc
            or zlib.crc32(image) & 0xFFFF_FFFF != crc
        ):
            raise ValueError("setup profile identity changed")
        targets.append((hz, crc))
    capture = json.loads((path / "capture.json").read_text())
    if capture.get("error") or not capture.get("host_restoration"):
        raise ValueError("capture failed or host restoration not attested")
    if not capture["host_restoration"].get("fastlock_inactive"):
        raise ValueError("Fast Lock restoration not attested")
    counts: Counter[int] = Counter()
    target_counts: Counter[int] = Counter()
    slot_generations = [1] * 8
    previous_end = None
    starts: dict[int, int] = {}
    metrics: dict[str, list[int]] = {
        name: []
        for name in (
            "profile_load",
            "recall_lock",
            "guard",
            "gap",
            "x_to_z",
            "revisit",
            "window_start_spacing",
        )
    }
    visits = iq_total = 0
    terminal = None
    with (path / "visits.bin").open("rb") as stream, (path / "iq-hashes.jsonl").open() as hashes:
        while prefix := stream.read(4):
            if len(prefix) != 4:
                raise ValueError("truncated record length")
            size = struct.unpack("<I", prefix)[0]
            if size not in (224, 128):
                raise ValueError("unexpected record size")
            raw = checked(stream.read(size), b"SPVR" if size == 224 else b"SPFT", size)
            count_raw = stream.read(8)
            if len(count_raw) != 8:
                raise ValueError("truncated IQ length")
            count = struct.unpack("<Q", count_raw)[0]
            if count > 1_600_000:
                raise ValueError("unbounded IQ count")
            if size == 128:
                if any(raw[120:124]):
                    raise ValueError("terminal reserved bytes changed")
                if count or stream.read(1) or hashes.readline():
                    raise ValueError("data after terminal")
                terminal = struct.unpack_from("<QQQQQQQQQQQIIiI", raw, 16)
                break
            sid, gen, visit, selected, before, after, start, end, hz, iq_bytes, missing = (
                struct.unpack_from("<11Q", raw, 16)
            )
            bw, fs, target, slot, result, eligible, weight, post_crc, flags = struct.unpack_from(
                "<9I", raw, 104
            )
            loaded, recall, sweep, slot_gen, verified, original_crc, rxmask, digest = (
                struct.unpack_from("<QQQQQII32s", raw, 140)
            )
            if (sid, gen, visit, sweep, target, slot) != (
                session,
                generation,
                visits,
                visits // 24,
                visits % 24,
                visits % 8,
            ):
                raise ValueError("visit identity/order changed")
            if digest != plan_digest or hz != targets[target][0]:
                raise ValueError("visit plan or requested IF mislabeled")
            if (bw, fs, rxmask) != (bandwidth, rate, 3):
                raise ValueError("visit geometry changed")
            if not before <= loaded <= recall <= after <= start <= end:
                raise ValueError("transition counters regressed")
            if end - start > 200_000 or count != iq_bytes or count != (end - start) * 8:
                raise ValueError("IQ support or byte count changed")
            if previous_end is not None and before < previous_end:
                raise ValueError("source counter intervals overlap")
            if result == 1:  # COMPLETE in the published VisitResult enum.
                if (
                    end - start != 200_000
                    or start < max(selected, after) + 200_000
                    or missing
                    or abs(verified - hz) > 2
                    or original_crc != targets[target][1]
                    or not post_crc
                    or slot_gen != slot_generations[slot] + int(visit >= 8)
                ):
                    raise ValueError("complete IQ lacks verified tuning, generation or guard")
                target_counts[target] += 1
                metrics["profile_load"].append(loaded - before)
                metrics["recall_lock"].append(after - recall)
                metrics["guard"].append(start - after)
                if previous_end is not None:
                    metrics["gap"].append(start - previous_end)
                if visit - 1 in starts:
                    metrics["window_start_spacing"].append(start - starts[visit - 1])
                if target % 3 == 2 and visit - 2 in starts:
                    metrics["x_to_z"].append(start - starts[visit - 2])
                if visit - 24 in starts:
                    metrics["revisit"].append(start - starts[visit - 24])
                starts[visit] = start
                starts.pop(visit - 25, None)
            if slot_gen:
                slot_generations[slot] = slot_gen
            iq_offset = stream.tell()
            iq = stream.read(count)
            saved = json.loads(hashes.readline())
            expected = {
                "visit": visit,
                "iq_offset": iq_offset,
                "iq_bytes": count,
                "sha256": hashlib.sha256(iq).hexdigest(),
            }
            if len(iq) != count or saved != expected:
                raise ValueError("IQ hash or offset mismatch")
            if result not in (1, 2, 3, 4, 5):
                raise ValueError("unknown visit outcome")
            counts[result] += 1
            iq_total += count
            previous_end = end
            visits += 1
    if terminal is None:
        raise ValueError("missing terminal")
    (
        sid,
        gen,
        final,
        restore_before,
        restore_after,
        planned,
        delivered,
        skipped,
        invalid,
        cancelled,
        iqbytes,
        state,
        reason,
        error,
        flags,
    ) = terminal
    if (sid, gen, planned, delivered, skipped, invalid, cancelled, iqbytes) != (
        session,
        generation,
        visits,
        counts[1],
        counts[2] + counts[3],
        counts[4],
        counts[5],
        iq_total,
    ):
        raise ValueError("terminal accounting changed")
    if (
        error
        or state not in (1, 2)
        or flags != 1
        or final < (previous_end or 0)
        or restore_after < restore_before
        or restore_before < final
    ):
        raise ValueError("terminal failure or restoration counter changed")
    summary = capture.get("terminal")
    for key, expected in {
        "session": session,
        "generation": generation,
        "planned": planned,
        "delivered": delivered,
        "skipped": skipped,
        "invalid": invalid,
        "cancelled": cancelled,
        "iq_bytes": iqbytes,
        "error": error,
    }.items():
        if not isinstance(summary, dict) or summary.get(key) != expected:
            raise ValueError("capture terminal summary disagrees with binary terminal")
    if any(target_counts[i] < minimum_sweeps for i in range(24)):
        raise ValueError("not enough independently verified complete visits at all 24 targets")
    return {
        "schema": "spf.position-verification/v1",
        "verified": True,
        "physical_signature_verified": False,
        "visits": visits,
        "complete": counts[1],
        "outcomes": dict(counts),
        "iq_bytes": iq_total,
        "complete_by_target": dict(target_counts),
        "host_restoration": True,
        "preparation_wall_s": capture.get("preparation_wall_s"),
        "timing": {name: distribution(values) for name, values in metrics.items()},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--minimum-sweeps", type=int, default=2)
    args = parser.parse_args()
    print(
        json.dumps(
            verify_position_scan(args.directory, minimum_sweeps=args.minimum_sweeps), indent=2
        )
    )


if __name__ == "__main__":
    main()
