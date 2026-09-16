"""Exact, receipt-gated feature-request #103 hardware qualification command."""

from __future__ import annotations

import argparse
import dataclasses
import enum
import json
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from .adaptive_scan_campaign import (
    AdaptiveScanCampaignReceipt,
    build_adaptive_scan_setup,
    run_adaptive_scan_campaign,
)
from .adaptive_scan_detector import (
    Ci16EnergyDetector,
    Ci16EnergyDetectorConfig,
    TargetMaskDetector,
    TargetMaskDetectorConfig,
)
from .adaptive_scan_evidence import (
    AUTHORIZED_FEATURE_103_SERIALS,
    AdaptiveScanEvidenceIdentity,
    attest_feature103_ram_boot_receipt,
    write_adaptive_scan_evidence,
)
from .adaptive_scan_shadow import AdaptiveScanMode

CampaignRunner = Callable[..., AdaptiveScanCampaignReceipt]
EvidenceWriter = Callable[..., AdaptiveScanEvidenceIdentity]


class Feature103Detector(enum.StrEnum):
    CONTROLLED = "controlled"
    ENERGY = "energy"


@dataclasses.dataclass(frozen=True, slots=True)
class Feature103QualificationRequest:
    serial: str
    uri: str
    ram_receipt: Path
    evidence_path: Path
    mode: AdaptiveScanMode
    detector: Feature103Detector
    session: int
    generation: int
    seed: int
    source_rate_hz: int
    analog_bandwidth_hz: int
    duration_ms: int
    dwell_ms: int
    frequencies_hz: tuple[int, ...]
    baseline_weights: tuple[int, ...]
    active_targets: tuple[int, ...] = ()
    energy_threshold_dbfs: float | None = None
    feedback_period_visits: int = 1
    manual_gain_db: float = 40.0
    samples_per_block: int = 1_000_000

    @property
    def confirmation_phrase(self) -> str:
        return f"QUALIFY FEATURE 103 {self.serial}"


def _detector(request: Feature103QualificationRequest) -> TargetMaskDetector | Ci16EnergyDetector:
    if request.detector is Feature103Detector.CONTROLLED:
        if request.energy_threshold_dbfs is not None:
            raise ValueError("controlled detector cannot have an energy threshold")
        return TargetMaskDetector(TargetMaskDetectorConfig(request.active_targets))
    if request.active_targets:
        raise ValueError("energy detector cannot have controlled active targets")
    if request.energy_threshold_dbfs is None:
        raise ValueError("energy detector requires --energy-threshold-dbfs")
    return Ci16EnergyDetector(Ci16EnergyDetectorConfig(request.energy_threshold_dbfs))


def _json_value(value: Any) -> Any:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: _json_value(getattr(value, field.name))
            for field in dataclasses.fields(value)
        }
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    return value


def run_feature103_qualification(
    request: Feature103QualificationRequest,
    *,
    execute: bool,
    confirmation: str | None = None,
    campaign_runner: CampaignRunner = run_adaptive_scan_campaign,
    evidence_writer: EvidenceWriter = write_adaptive_scan_evidence,
) -> dict[str, Any]:
    """Validate a deterministic plan, then optionally execute exactly one bounded cell."""

    if request.serial not in AUTHORIZED_FEATURE_103_SERIALS:
        raise ValueError("serial is not authorized for feature 103 qualification")
    if request.evidence_path.expanduser().absolute().exists():
        raise ValueError("evidence path already exists")
    if not 1 <= request.feedback_period_visits <= 1_000:
        raise ValueError("feedback period must be in 1..1000 visits")
    if not 0 <= request.manual_gain_db <= 73:
        raise ValueError("manual gain must be in 0..73 dB")
    if request.samples_per_block <= 0 or request.samples_per_block % 2:
        raise ValueError("samples per block must be positive and even")
    boot = attest_feature103_ram_boot_receipt(
        request.ram_receipt, expected_serial=request.serial
    )
    detector = _detector(request)
    setup = build_adaptive_scan_setup(
        session=request.session,
        generation=request.generation,
        seed=request.seed,
        source_rate_hz=request.source_rate_hz,
        analog_bandwidth_hz=request.analog_bandwidth_hz,
        duration_ms=request.duration_ms,
        dwell_ms=request.dwell_ms,
        frequencies_hz=request.frequencies_hz,
        baseline_weights=request.baseline_weights,
        analysis_digest=detector.config.analysis_digest,
    )
    plan = {
        "serial": request.serial,
        "uri": request.uri,
        "mode": request.mode,
        "detector": request.detector,
        "setup": setup,
        "feedback_period_visits": request.feedback_period_visits,
        "manual_gain_db": request.manual_gain_db,
        "samples_per_block": request.samples_per_block,
        "ram_boot": boot,
        "evidence_path": request.evidence_path.expanduser().absolute(),
        "confirmation_phrase": request.confirmation_phrase,
        "will_mutate_radio_settings": execute,
        "will_write_qspi": False,
    }
    if not execute:
        return {"mode": "dry_run", "plan": _json_value(plan)}
    if confirmation != request.confirmation_phrase:
        raise ValueError(f"confirmation must be exactly {request.confirmation_phrase!r}")
    receipt = campaign_runner(
        request.uri,
        request.serial,
        setup,
        detector,
        mode=request.mode,
        manual_gain_db=request.manual_gain_db,
        samples_per_block=request.samples_per_block,
        feedback_period_visits=request.feedback_period_visits,
    )
    identity = evidence_writer(
        request.evidence_path,
        receipt,
        candidate_dfu_sha256=boot.dfu_sha256,
        candidate_fit_sha256=boot.fit_sha256,
        rf_observations=(
            tuple(detector.observations) if isinstance(detector, Ci16EnergyDetector) else ()
        ),
    )
    return {
        "mode": "executed",
        "serial": request.serial,
        "gate": _json_value(receipt.run.gate),
        "restoration": _json_value(receipt.restoration),
        "evidence": _json_value(identity),
        "passed": receipt.run.gate.passed and receipt.restoration.fastlock_inactive,
        "will_write_qspi": False,
    }


def _csv_ints(value: str) -> tuple[int, ...]:
    try:
        result = tuple(int(item) for item in value.split(",") if item)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected comma-separated integers") from error
    if not result:
        raise argparse.ArgumentTypeError("list must not be empty")
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pluto-feature103-qualify",
        description="Run one exact RC11-full-gated adaptive-scan qualification cell.",
    )
    parser.add_argument("--serial", required=True, choices=AUTHORIZED_FEATURE_103_SERIALS)
    parser.add_argument("--uri", required=True)
    parser.add_argument("--ram-receipt", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--mode", required=True, choices=tuple(AdaptiveScanMode))
    parser.add_argument("--detector", required=True, choices=tuple(Feature103Detector))
    parser.add_argument("--session", required=True, type=int)
    parser.add_argument("--generation", required=True, type=int)
    parser.add_argument("--seed", required=True, type=int)
    parser.add_argument(
        "--rate", required=True, type=int, choices=(10_000_000, 15_000_000, 20_000_000, 30_000_000)
    )
    parser.add_argument("--bandwidth", required=True, type=int)
    parser.add_argument("--duration-ms", required=True, type=int)
    parser.add_argument("--dwell-ms", required=True, type=int)
    parser.add_argument("--frequencies", required=True, type=_csv_ints)
    parser.add_argument("--weights", required=True, type=_csv_ints)
    parser.add_argument("--active-targets", type=_csv_ints, default=())
    parser.add_argument("--energy-threshold-dbfs", type=float)
    parser.add_argument("--feedback-period-visits", type=int, default=1)
    parser.add_argument("--manual-gain-db", type=float, default=40.0)
    parser.add_argument("--samples-per-block", type=int, default=1_000_000)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirm")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        request = Feature103QualificationRequest(
            serial=args.serial,
            uri=args.uri,
            ram_receipt=args.ram_receipt,
            evidence_path=args.evidence,
            mode=AdaptiveScanMode(args.mode),
            detector=Feature103Detector(args.detector),
            session=args.session,
            generation=args.generation,
            seed=args.seed,
            source_rate_hz=args.rate,
            analog_bandwidth_hz=args.bandwidth,
            duration_ms=args.duration_ms,
            dwell_ms=args.dwell_ms,
            frequencies_hz=args.frequencies,
            baseline_weights=args.weights,
            active_targets=args.active_targets,
            energy_threshold_dbfs=args.energy_threshold_dbfs,
            feedback_period_visits=args.feedback_period_visits,
            manual_gain_db=args.manual_gain_db,
            samples_per_block=args.samples_per_block,
        )
        result = run_feature103_qualification(
            request,
            execute=args.execute,
            confirmation=args.confirm,
        )
    except Exception as error:
        print(json.dumps({"error": f"{type(error).__name__}: {error}"}), file=sys.stderr)
        return 4
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result.get("passed", True) else 5


if __name__ == "__main__":
    raise SystemExit(main())
