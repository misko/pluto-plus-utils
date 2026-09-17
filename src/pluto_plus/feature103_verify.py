"""Fail-closed release-matrix verification for feature request #103."""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import math
import os
import stat
import sys
from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any, cast

from .adaptive_scan_evidence import (
    AUTHORIZED_FEATURE_103_SERIALS,
    FEATURE_103_RC14_DFU_SHA256,
    FEATURE_103_RC14_FIT_SHA256,
    SCHEMA,
    AdaptiveScanEvidenceError,
    AdaptiveScanEvidenceIdentity,
    Feature103RamBootIdentity,
    attest_feature103_rc14_ram_boot_receipt,
)

MATRIX_RATES = (10_000_000, 15_000_000, 20_000_000, 30_000_000)
ACTIVE_TARGET = 1
TARGET_FREQUENCIES_HZ = (960_000_000, 1_190_312_500)
RELEASE_EVIDENCE_SHA256: Mapping[tuple[str, int], str] = {
    (AUTHORIZED_FEATURE_103_SERIALS[0], 10_000_000):
        "114beef6e7bc43ea0b0500335e2e57f2dab169ad60f7bdb17b53698cfdf6b0da",
    (AUTHORIZED_FEATURE_103_SERIALS[0], 15_000_000):
        "4ca0173b179d6457067be3052bb9da3b04671401a944085056ccdfb4711dd7d9",
    (AUTHORIZED_FEATURE_103_SERIALS[0], 20_000_000):
        "fba438897f03066d0e8a87731348aad99ef818df78ce9d746dcd462f05d86747",
    (AUTHORIZED_FEATURE_103_SERIALS[0], 30_000_000):
        "270861e218d728ea7740948069d2c9385485237e27066c4581a979cc4638b82f",
    (AUTHORIZED_FEATURE_103_SERIALS[1], 10_000_000):
        "85fb3e5f2cbf8ac134ae28ba60660ddf00b942a022881c327ba10a3744a9c35e",
    (AUTHORIZED_FEATURE_103_SERIALS[1], 15_000_000):
        "27974eeaed663d963d28e52faf8c28e3c34488076a84c9034c97a9b3bbdcfb86",
    (AUTHORIZED_FEATURE_103_SERIALS[1], 20_000_000):
        "953784c24338ecc120f2308d60f499da0135a5005fddb19635df2e71e80a3c49",
    (AUTHORIZED_FEATURE_103_SERIALS[1], 30_000_000):
        "b5578716a78b523ec6af078ff963dec356e4ec6c2fd8332eb7503aeda4696039",
}

_EXPECTED_DURATION_MS = {10_000_000: 30_000, 15_000_000: 30_000,
                         20_000_000: 10_000, 30_000_000: 10_000}
_EXPECTED_BANDWIDTH_HZ = {10_000_000: 8_000_000, 15_000_000: 12_000_000,
                          20_000_000: 18_000_000, 30_000_000: 18_000_000}
_MAX_EVIDENCE_BYTES = 16 * 1024 * 1024


@dataclasses.dataclass(frozen=True, slots=True)
class Feature103CellVerification:
    serial: str
    source_rate_hz: int
    evidence: AdaptiveScanEvidenceIdentity
    retained_duty: float
    planned: int
    delivered: int
    skipped: int
    applied_acknowledgements: int
    active_share_before: float
    active_share_after: float


@dataclasses.dataclass(frozen=True, slots=True)
class Feature103MatrixVerification:
    schema: str
    candidate_dfu_sha256: str
    candidate_fit_sha256: str
    boot_receipts: tuple[Feature103RamBootIdentity, ...]
    cells: tuple[Feature103CellVerification, ...]
    passed: bool = True


def _fail(message: str) -> None:
    raise AdaptiveScanEvidenceError(message)


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        _fail(f"{label} must be an object")
    return cast(dict[str, Any], value)


def _list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        _fail(f"{label} must be an array")
    return cast(list[Any], value)


def _integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _fail(f"{label} must be an integer")
    return cast(int, value)


def _number(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _fail(f"{label} must be a number")
    result = float(value)
    if not math.isfinite(result):
        _fail(f"{label} must be finite")
    return result


def _exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        _fail(f"{label} fields are not exact")


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"JSON contains duplicate field {key!r}")
        result[key] = value
    return result


def _read_private_canonical_json(path: Path) -> tuple[Path, bytes, dict[str, Any]]:
    selected = path.expanduser().absolute()
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(selected, flags)
    except OSError as error:
        raise AdaptiveScanEvidenceError("campaign evidence is unreadable") from error
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            _fail("campaign evidence must be a private regular file")
        if info.st_size <= 0 or info.st_size > _MAX_EVIDENCE_BYTES:
            _fail("campaign evidence size is unsafe")
        chunks: list[bytes] = []
        remaining = info.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                _fail("campaign evidence was truncated while reading")
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
    finally:
        os.close(descriptor)
    try:
        payload = json.loads(raw, object_pairs_hook=_reject_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AdaptiveScanEvidenceError("campaign evidence is not valid JSON") from error
    root = _mapping(payload, "campaign evidence")
    canonical = (json.dumps(root, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if raw != canonical:
        _fail("campaign evidence is not canonical")
    return selected, raw, root


def _verify_feedback(run: dict[str, Any], setup: dict[str, Any]) -> tuple[int, float, float]:
    observations = _list(run.get("observations"), "observations")
    acknowledgements = _list(run.get("acknowledgements"), "acknowledgements")
    accepted: dict[int, tuple[int, int, int]] = {}
    normalized: list[tuple[int, int]] = []
    session = _integer(setup.get("session"), "setup.session")
    generation = _integer(setup.get("generation"), "setup.generation")
    digest = setup.get("analysis_digest")
    for index, raw_observation in enumerate(observations):
        observation = _mapping(raw_observation, f"observation {index}")
        _exact_keys(observation, {"visit", "target", "outcome", "feedback", "receipt"},
                    f"observation {index}")
        visit = _integer(observation["visit"], "observation.visit")
        target = _integer(observation["target"], "observation.target")
        outcome = _integer(observation["outcome"], "observation.outcome")
        if target not in (0, 1) or outcome != (1 if target == ACTIVE_TARGET else 2):
            _fail("controlled detector observation is inconsistent")
        feedback = _mapping(observation["feedback"], "observation.feedback")
        _exact_keys(feedback, {"analysis_digest", "generation", "outcome", "sequence",
                               "session", "target", "valid_end", "valid_start", "visit"},
                    "observation.feedback")
        if (feedback["session"] != session or feedback["generation"] != generation
                or feedback["analysis_digest"] != digest or feedback["visit"] != visit
                or feedback["target"] != target or feedback["outcome"] != outcome
                or _integer(feedback["valid_end"], "feedback.valid_end")
                <= _integer(feedback["valid_start"], "feedback.valid_start")):
            _fail("feedback is not bound to its observation")
        sequence = _integer(feedback["sequence"], "feedback.sequence")
        receipt = _integer(observation["receipt"], "observation.receipt")
        if receipt not in (0, 4):
            _fail("feedback receipt is not ACCEPTED or bounded-race REJECTED")
        if receipt == 0:
            if sequence in accepted:
                _fail("accepted feedback sequence is duplicated")
            accepted[sequence] = (visit, target, outcome)
        normalized.append((visit, target))
    if [visit for visit, _target in normalized] != sorted({visit for visit, _target in normalized}):
        _fail("observation visits are not unique and increasing")
    ack_by_sequence: dict[int, dict[str, Any]] = {}
    applied = 0
    for index, raw_ack in enumerate(acknowledgements):
        ack = _mapping(raw_ack, f"acknowledgement {index}")
        _exact_keys(
            ack,
            {"application_counter", "first_visit", "new_boost", "old_boost",
             "received_counter", "result", "sequence", "source_visit", "target"},
            f"acknowledgement {index}",
        )
        sequence = _integer(ack.get("sequence"), "acknowledgement.sequence")
        if sequence in ack_by_sequence:
            _fail("acknowledgement sequence is duplicated")
        if _integer(ack.get("result"), "acknowledgement.result") not in (5, 7, 8):
            _fail("terminal acknowledgement result is invalid")
        ack_by_sequence[sequence] = ack
        applied += ack["result"] == 7
    if set(ack_by_sequence) != set(accepted):
        _fail("acknowledgements do not exactly reconcile accepted feedback")
    for sequence, (visit, target, _outcome) in accepted.items():
        ack = ack_by_sequence[sequence]
        if ack.get("source_visit") != visit or ack.get("target") != target:
            _fail("acknowledgement is not bound to accepted feedback")
    active_applied = [
        ack_by_sequence[sequence]
        for sequence, (_visit, target, outcome) in accepted.items()
        if target == ACTIVE_TARGET and outcome == 1 and ack_by_sequence[sequence]["result"] == 7
    ]
    if not active_applied:
        _fail("active target has no applied acknowledgement")
    first = min(active_applied, key=lambda item: _integer(item.get("first_visit"),
                                                          "acknowledgement.first_visit"))
    boundary = _integer(first.get("first_visit"), "acknowledgement.first_visit")
    before = [target for visit, target in normalized if visit < boundary]
    after = [target for visit, target in normalized if visit >= boundary]
    if not before or not after:
        _fail("weighting evidence does not straddle first application")
    before_share = before.count(ACTIVE_TARGET) / len(before)
    after_share = after.count(ACTIVE_TARGET) / len(after)
    if after_share <= before_share:
        _fail("active-target selection share did not increase")
    return applied, before_share, after_share


def _verify_cell(path: Path) -> tuple[tuple[str, int], Feature103CellVerification]:
    selected, raw, payload = _read_private_canonical_json(path)
    _exact_keys(payload, {"schema", "schema_version", "created_at", "candidate", "campaign",
                          "rf_observations"}, "campaign evidence")
    if payload["schema"] != SCHEMA or payload["schema_version"] != 1:
        _fail("campaign evidence schema is not feature-103 v1")
    try:
        created = datetime.fromisoformat(str(payload["created_at"]))
    except ValueError as error:
        raise AdaptiveScanEvidenceError("campaign evidence timestamp is invalid") from error
    if created.tzinfo is None:
        _fail("campaign evidence timestamp must include a timezone")
    if payload["rf_observations"] != []:
        _fail("release matrix must use the controlled detector")
    candidate = _mapping(payload["candidate"], "candidate")
    if candidate != {"dfu_sha256": FEATURE_103_RC14_DFU_SHA256,
                      "fit_sha256": FEATURE_103_RC14_FIT_SHA256}:
        _fail("campaign is not bound to exact RC14 candidate bytes")
    campaign = _mapping(payload["campaign"], "campaign")
    _exact_keys(campaign, {"uri", "serial", "preparation", "run", "restoration"}, "campaign")
    serial = str(campaign["serial"])
    if serial not in AUTHORIZED_FEATURE_103_SERIALS:
        _fail("campaign serial is not authorized")
    preparation = _mapping(campaign["preparation"], "preparation")
    _exact_keys(
        preparation,
        {"configured", "configured_kernel_buffers", "original", "original_kernel_buffers",
         "profile_words", "serial", "setup", "uri"},
        "preparation",
    )
    setup = _mapping(preparation.get("setup"), "preparation.setup")
    _exact_keys(
        setup,
        {"analog_bandwidth_hz", "analysis_digest", "application_delay_ms", "decay_ms",
         "duration_ms", "dwell_ms", "feedback_age_ms", "flags", "format", "generation",
         "maximum_boost", "maximum_queue_age_ms", "maximum_queue_bytes",
         "maximum_queue_visits", "maximum_revisit_ms", "rx_mask", "seed", "session",
         "source_rate_hz", "targets", "transition_budget_ms"},
        "preparation.setup",
    )
    rate = _integer(setup.get("source_rate_hz"), "setup.source_rate_hz")
    if rate not in MATRIX_RATES:
        _fail("campaign rate is not in the release matrix")
    expected_bandwidth = _EXPECTED_BANDWIDTH_HZ[rate]
    if (setup.get("duration_ms") != _EXPECTED_DURATION_MS[rate] or setup.get("dwell_ms") != 240
            or setup.get("analog_bandwidth_hz") != expected_bandwidth
            or setup.get("seed") != 103 or setup.get("generation") != 1
            or setup.get("rx_mask") != 1 or setup.get("format") != 1
            or setup.get("flags") != 1 or setup.get("application_delay_ms") != 1_000
            or setup.get("decay_ms") != 5_000 or setup.get("feedback_age_ms") != 1_000
            or setup.get("maximum_boost") != 3
            or setup.get("maximum_queue_age_ms") != 5_000
            or setup.get("maximum_queue_bytes") != 200_000_000
            or setup.get("maximum_queue_visits") != 50
            or setup.get("maximum_revisit_ms") != 3_000
            or setup.get("transition_budget_ms") != 10):
        _fail("campaign setup does not match the frozen release cell")
    targets = _list(setup.get("targets"), "setup.targets")
    if len(targets) != 2:
        _fail("campaign must contain exactly two targets")
    for index, raw_target in enumerate(targets):
        target = _mapping(raw_target, f"target {index}")
        _exact_keys(target, {"baseline_weight", "channel", "frequency_hz", "profile",
                             "profile_crc32"}, f"target {index}")
        if (target.get("channel") != index
                or target.get("frequency_hz") != TARGET_FREQUENCIES_HZ[index]
                or target.get("profile") != index + 1 or target.get("baseline_weight") != 1
                or _integer(target.get("profile_crc32"), "target.profile_crc32") <= 0):
            _fail("campaign target geometry is not frozen")
    configured = _mapping(preparation.get("configured"), "preparation.configured")
    _exact_keys(configured, {"bandwidth_hz", "center_frequency_hz", "channels", "gain_db",
                             "gain_modes", "sample_rate_hz"}, "preparation.configured")
    if (_number(configured.get("sample_rate_hz"), "configured.sample_rate_hz") != rate
            or _number(configured.get("bandwidth_hz"), "configured.bandwidth_hz")
            != expected_bandwidth or configured.get("channels") != [0]
            or configured.get("gain_modes") != ["manual"]
            or configured.get("gain_db") != [40.0]
            or preparation.get("configured_kernel_buffers") != 16
            or preparation.get("serial") != serial or preparation.get("uri") != campaign["uri"]):
        _fail("prepared radio geometry does not match the release cell")
    profile_words = _list(preparation.get("profile_words"), "preparation.profile_words")
    if (len(profile_words) != 2
            or any(not isinstance(words, list) or len(words) != 16 for words in profile_words)):
        _fail("campaign does not contain two complete Fast Lock profiles")
    restoration = _mapping(campaign["restoration"], "restoration")
    _exact_keys(restoration, {"expected", "expected_kernel_buffers", "fastlock_inactive",
                              "observed", "observed_kernel_buffers"}, "restoration")
    if (restoration.get("expected") != restoration.get("observed")
            or restoration.get("expected") != preparation.get("original")
            or restoration.get("expected_kernel_buffers") != 4
            or restoration.get("observed_kernel_buffers") != 4
            or preparation.get("original_kernel_buffers") != 4
            or restoration.get("fastlock_inactive") is not True):
        _fail("campaign did not restore exact RF/buffer state and exit Fast Lock")
    run = _mapping(campaign["run"], "run")
    _exact_keys(run, {"mode", "feedback_period_visits", "observations", "acknowledgements",
                      "metrics", "gate"}, "run")
    if run["mode"] != "adaptive" or run["feedback_period_visits"] != 1:
        _fail("release cell did not run periodic adaptive feedback")
    metrics = _mapping(run["metrics"], "metrics")
    _exact_keys(
        metrics,
        {"cancelled", "deadline_forced", "delivered", "delivered_valid_samples", "dwell_ms",
         "final_counter", "first_counter", "invalid", "iq_bytes", "planned",
         "planned_valid_samples", "skipped", "source_rate_hz", "source_span_samples",
         "target_visits"},
        "metrics",
    )
    planned = _integer(metrics.get("planned"), "metrics.planned")
    delivered = _integer(metrics.get("delivered"), "metrics.delivered")
    skipped = _integer(metrics.get("skipped"), "metrics.skipped")
    invalid = _integer(metrics.get("invalid"), "metrics.invalid")
    cancelled = _integer(metrics.get("cancelled"), "metrics.cancelled")
    dwell_samples = rate * 240 // 1_000
    source_span = _integer(metrics.get("source_span_samples"), "metrics.source_span_samples")
    delivered_samples = _integer(metrics.get("delivered_valid_samples"),
                                 "metrics.delivered_valid_samples")
    first_counter = _integer(metrics.get("first_counter"), "metrics.first_counter")
    final_counter = _integer(metrics.get("final_counter"), "metrics.final_counter")
    target_visits = metrics.get("target_visits")
    if (metrics.get("source_rate_hz") != rate or metrics.get("dwell_ms") != 240
            or planned != delivered + skipped + invalid + cancelled
            or metrics.get("planned_valid_samples") != planned * dwell_samples
            or delivered_samples != delivered * dwell_samples
            or metrics.get("iq_bytes") != delivered_samples * 4 or source_span <= 0
            or final_counter - first_counter != source_span
            or not isinstance(target_visits, list) or len(target_visits) != 2
            or sum(_integer(item, "metrics.target_visits") for item in target_visits) != planned
            or len(run["observations"]) != delivered):
        _fail("campaign metric accounting is inconsistent")
    duty = delivered_samples / source_span
    gate = _mapping(run["gate"], "gate")
    _exact_keys(gate, {"comparison", "name", "observed", "passed", "threshold"}, "gate")
    if not math.isclose(_number(gate.get("observed"), "gate.observed"), duty,
                        rel_tol=0.0, abs_tol=1e-15) or gate.get("passed") is not True:
        _fail("stored acceptance gate is inconsistent")
    if rate == 10_000_000:
        if (not duty > 0.95 or gate.get("name") != "10MSs-full-session-duty"
                or gate.get("comparison") != ">" or gate.get("threshold") != 0.95):
            _fail("10 MS/s duty gate did not pass strictly above 95%")
    elif rate == 15_000_000:
        if (not duty >= 0.90 or gate.get("name") != "15MSs-full-session-duty"
                or gate.get("comparison") != ">=" or gate.get("threshold") != 0.90):
            _fail("15 MS/s duty gate did not pass at or above 90%")
    elif (gate.get("name") != "20-30MSs-integrity-only"
          or gate.get("comparison") != "informational" or gate.get("threshold") is not None):
        _fail("upper-rate cell must use the integrity-only gate")
    if rate <= 15_000_000:
        if (planned, delivered, skipped, invalid, cancelled) != (119, 119, 0, 0, 0):
            _fail("mandatory duty cell is not a lossless 119-visit run")
    elif planned != 39 or delivered <= 0 or invalid != 0 or cancelled != 0:
        _fail("overload cell does not explicitly account for 39 complete visits")
    applied, before_share, after_share = _verify_feedback(run, setup)
    identity = AdaptiveScanEvidenceIdentity(
        selected, hashlib.sha256(raw).hexdigest(), len(raw)
    )
    return (serial, rate), Feature103CellVerification(
        serial=serial,
        source_rate_hz=rate,
        evidence=identity,
        retained_duty=duty,
        planned=planned,
        delivered=delivered,
        skipped=skipped,
        applied_acknowledgements=applied,
        active_share_before=before_share,
        active_share_after=after_share,
    )


def verify_feature103_matrix(
    ram_receipts: Mapping[str, Path],
    evidence_paths: Sequence[Path],
    *,
    expected_evidence_sha256: Mapping[tuple[str, int], str] | None = None,
) -> Feature103MatrixVerification:
    """Verify exactly one RC14 boot and four independent cells per authorized radio."""

    if set(ram_receipts) != set(AUTHORIZED_FEATURE_103_SERIALS):
        _fail("matrix requires one named boot receipt for each authorized radio")
    boots = tuple(
        attest_feature103_rc14_ram_boot_receipt(
            ram_receipts[serial], expected_serial=serial
        )
        for serial in AUTHORIZED_FEATURE_103_SERIALS
    )
    if (len({item.receipt_id for item in boots}) != 2
            or len({item.usb_sysfs_path for item in boots}) != 2):
        _fail("matrix boot receipts are not distinct")
    if len(evidence_paths) != 8:
        _fail("matrix requires exactly eight campaign evidence files")
    cells: dict[tuple[str, int], Feature103CellVerification] = {}
    for path in evidence_paths:
        key, cell = _verify_cell(path)
        if key in cells:
            _fail("matrix contains a duplicate radio/rate cell")
        cells[key] = cell
    expected_cells = {(serial, rate) for serial in AUTHORIZED_FEATURE_103_SERIALS
                      for rate in MATRIX_RATES}
    if set(cells) != expected_cells:
        _fail("matrix does not cover both radios at every fixed rate")
    if expected_evidence_sha256 is not None:
        if set(expected_evidence_sha256) != expected_cells:
            _fail("expected evidence identity map is incomplete")
        for key, cell in cells.items():
            if cell.evidence.sha256 != expected_evidence_sha256[key]:
                _fail("campaign evidence identity is not the pinned RC14 release record")
    return Feature103MatrixVerification(
        schema="pluto-plus-utils.feature-103-release-matrix.v1",
        candidate_dfu_sha256=FEATURE_103_RC14_DFU_SHA256,
        candidate_fit_sha256=FEATURE_103_RC14_FIT_SHA256,
        boot_receipts=boots,
        cells=tuple(cells[(serial, rate)] for serial in AUTHORIZED_FEATURE_103_SERIALS
                    for rate in MATRIX_RATES),
    )


def _named_paths(values: Sequence[str]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for value in values:
        serial, separator, raw_path = value.partition("=")
        if not separator or serial in result or not raw_path:
            raise ValueError("--ram-receipt must be a unique SERIAL=PATH")
        result[serial] = Path(raw_path)
    return result


def _json_value(value: Any) -> Any:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {field.name: _json_value(getattr(value, field.name))
                for field in dataclasses.fields(value)}
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    return value


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pluto-feature103-verify",
        description="Verify the exact two-radio RC14 feature-103 release matrix.",
    )
    parser.add_argument("--ram-receipt", action="append", required=True,
                        metavar="SERIAL=PATH")
    parser.add_argument("--evidence", action="append", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = verify_feature103_matrix(
            _named_paths(args.ram_receipt), args.evidence,
            expected_evidence_sha256=RELEASE_EVIDENCE_SHA256,
        )
    except Exception as error:
        print(json.dumps({"error": f"{type(error).__name__}: {error}"}), file=sys.stderr)
        return 4
    print(json.dumps(_json_value(result), sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
