"""Compare archived counter/UTC evidence against independent RF marker times.

Usage: python -m pluto_plus.counter_utc_verify manifest.json reference.json
This verifier never controls a radio or derives calibration from its test set.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Literal

from pydantic import Field

from .counter_utc import U64, CounterUtcEvidence, EvidenceModel, Nonnegative, Positive


class ReferenceMarker(EvidenceModel):
    counter: U64
    utc_ns: Positive
    uncertainty_ns: Nonnegative


class IndependentReference(EvidenceModel):
    schema_version: Literal[1] = 1
    source: str = Field(min_length=1)
    instrument_receipt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    radio_serial: str
    boot_id: str
    session: Positive
    generation: Positive
    sample_rate_hz: Positive
    first_counter: U64
    final_counter: U64
    markers: tuple[ReferenceMarker, ...]


def verify_reference(
    evidence: CounterUtcEvidence, reference: IndependentReference
) -> dict[str, object]:
    first, last, rate = reference.first_counter, reference.final_counter, reference.sample_rate_hz
    failures = []
    if (reference.session, reference.generation, reference.radio_serial) != (
        evidence.session,
        evidence.generation,
        evidence.radio_serial,
    ):
        failures.append("independent reference belongs to another capture")
    if not evidence.anchors or evidence.anchors[0].observation.boot_id != reference.boot_id:
        failures.append("independent reference boot identity mismatch")
    qualified, reason, bound = evidence.qualification(first, last, rate)
    if not qualified:
        failures.append(reason)
    markers = reference.markers
    margin = rate * 10
    if (
        len(markers) < 2
        or markers[0].counter - first > margin
        or last - markers[-1].counter > margin
    ):
        failures.append("independent markers do not cover capture endpoints")
    previous = None
    rows = []
    try:
        low, high = evidence.interval(first)
        origin = (low + high) // 2
    except ValueError:
        origin = None
    for marker in markers:
        if not first <= marker.counter <= last:
            failures.append("independent marker lies outside capture")
        if previous is not None and (
            not 0 < marker.counter - previous.counter <= margin or marker.utc_ns <= previous.utc_ns
        ):
            failures.append("independent marker gap, order or UTC is invalid")
        previous = marker
        if origin is not None:
            estimate = origin + (marker.counter - first) * 10**9 // rate
            residual = estimate - marker.utc_ns
            passed = bound is not None and abs(residual) + marker.uncertainty_ns <= bound
            rows.append(
                {
                    "counter": marker.counter,
                    "residual_ns": residual,
                    "reference_uncertainty_ns": marker.uncertainty_ns,
                    "passed": passed,
                }
            )
            if not passed:
                failures.append("RF marker residual exceeds the declared whole-capture UTC bound")
    return {
        "schema_version": 1,
        "passed": not failures,
        "qualified": qualified,
        "maximum_error_ns": bound,
        "failures": sorted(set(failures)),
        "markers": rows,
        "maximum_query_width_ns": max(
            (a.receive_monotonic_ns - a.send_monotonic_ns for a in evidence.anchors), default=None
        ),
        "reference_source": reference.source,
        "instrument_receipt_sha256": reference.instrument_receipt_sha256,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("reference", type=Path)
    args = parser.parse_args()
    manifest_bytes, reference_bytes = args.manifest.read_bytes(), args.reference.read_bytes()
    document = json.loads(manifest_bytes)
    evidence = CounterUtcEvidence.model_validate(document["evidence"]["counter_utc_timing"])
    reference = IndependentReference.model_validate_json(reference_bytes)
    report = verify_reference(evidence, reference)
    report["manifest_sha256"] = hashlib.sha256(manifest_bytes).hexdigest()
    report["reference_sha256"] = hashlib.sha256(reference_bytes).hexdigest()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
