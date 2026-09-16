"""Deterministic CI16 energy detector for adaptive-scan qualification."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import math

import numpy as np

from .adaptive_scan import ScanOutcome, VisitResult
from .adaptive_scan_client import AdaptiveScanVisit


@dataclasses.dataclass(frozen=True, slots=True)
class Ci16EnergyDetectorConfig:
    active_threshold_dbfs: float

    def __post_init__(self) -> None:
        if (
            not math.isfinite(self.active_threshold_dbfs)
            or not -120 <= self.active_threshold_dbfs <= 0
        ):
            raise ValueError("energy threshold must be finite and between -120 and 0 dBFS")

    @property
    def analysis_digest(self) -> bytes:
        payload = json.dumps(
            {
                "algorithm": "ci16-mean-complex-power-v1",
                "active_threshold_dbfs": self.active_threshold_dbfs,
            },
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
        return hashlib.sha256(payload).digest()


@dataclasses.dataclass(frozen=True, slots=True)
class Ci16EnergyObservation:
    visit: int
    target: int
    power_dbfs: float
    outcome: ScanOutcome


class Ci16EnergyDetector:
    """Classify complete RX0 CI16 visits and retain compact RF evidence."""

    def __init__(self, config: Ci16EnergyDetectorConfig) -> None:
        self.config = config
        self.observations: list[Ci16EnergyObservation] = []

    def __call__(self, visit: AdaptiveScanVisit) -> ScanOutcome:
        record = visit.record
        if record.result is not VisitResult.COMPLETE or not visit.iq:
            raise ValueError("energy detector requires one complete nonempty visit")
        raw = np.frombuffer(visit.iq, dtype="<i2")
        if raw.size % 2 or raw.size // 2 != record.valid_end - record.valid_start:
            raise ValueError("CI16 payload geometry disagrees with the visit")
        components = raw.astype(np.float64)
        mean_component_power = float(np.mean(components * components))
        power_dbfs = (
            float("-inf")
            if mean_component_power == 0
            else 10.0 * math.log10(mean_component_power / (32768.0**2))
        )
        outcome = (
            ScanOutcome.ACTIVE
            if power_dbfs >= self.config.active_threshold_dbfs
            else ScanOutcome.QUIET
        )
        self.observations.append(
            Ci16EnergyObservation(record.visit, record.target, power_dbfs, outcome)
        )
        return outcome


@dataclasses.dataclass(frozen=True, slots=True)
class TargetMaskDetectorConfig:
    """Controlled-feedback detector used to isolate scheduler behavior from RF."""

    active_targets: tuple[int, ...]

    def __post_init__(self) -> None:
        if (
            not self.active_targets
            or len(set(self.active_targets)) != len(self.active_targets)
            or any(type(target) is not int or not 0 <= target < 8 for target in self.active_targets)
        ):
            raise ValueError("active targets must be unique indices in 0..7")

    @property
    def analysis_digest(self) -> bytes:
        payload = json.dumps(
            {
                "algorithm": "controlled-target-mask-v1",
                "active_targets": self.active_targets,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return hashlib.sha256(payload).digest()


class TargetMaskDetector:
    """Emit deterministic active/quiet feedback while still consuming complete IQ."""

    def __init__(self, config: TargetMaskDetectorConfig) -> None:
        self.config = config

    def __call__(self, visit: AdaptiveScanVisit) -> ScanOutcome:
        if visit.record.result is not VisitResult.COMPLETE or not visit.iq:
            raise ValueError("target-mask detector requires one complete nonempty visit")
        return (
            ScanOutcome.ACTIVE
            if visit.record.target in self.config.active_targets
            else ScanOutcome.QUIET
        )
