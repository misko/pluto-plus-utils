from __future__ import annotations

import dataclasses

import numpy as np
import pytest

from pluto_plus.adaptive_scan import ScanOutcome, ScanVisit, VisitResult
from pluto_plus.adaptive_scan_client import AdaptiveScanVisit
from pluto_plus.adaptive_scan_detector import (
    Ci16EnergyDetector,
    Ci16EnergyDetectorConfig,
    TargetMaskDetector,
    TargetMaskDetectorConfig,
)


def _visit(amplitude: int, *, samples: int = 1024) -> AdaptiveScanVisit:
    components = np.empty(samples * 2, dtype="<i2")
    components[0::2] = amplitude
    components[1::2] = -amplitude
    iq = components.tobytes()
    return AdaptiveScanVisit(
        ScanVisit(
            session=1,
            generation=2,
            visit=0,
            selection_counter=0,
            transition_before=0,
            transition_after=1,
            valid_start=2,
            valid_end=2 + samples,
            frequency_hz=2_400_000_000,
            iq_bytes=len(iq),
            missing_samples_before=0,
            analog_bandwidth_hz=8_000_000,
            source_rate_hz=10_000_000,
            target=0,
            profile=0,
            result=VisitResult.COMPLETE,
            eligible_mask=1,
            effective_weight=65_536,
            profile_crc32=0x12345678,
        ),
        iq,
    )


def test_detector_digest_is_canonical_and_classification_is_repeatable() -> None:
    config = Ci16EnergyDetectorConfig(active_threshold_dbfs=-20.0)
    assert config.analysis_digest == Ci16EnergyDetectorConfig(-20.0).analysis_digest
    assert config.analysis_digest != Ci16EnergyDetectorConfig(-21.0).analysis_digest
    detector = Ci16EnergyDetector(config)

    assert detector(_visit(10_000)) is ScanOutcome.ACTIVE
    assert detector(_visit(1_000)) is ScanOutcome.QUIET
    assert detector.observations[0].power_dbfs == pytest.approx(-10.3087, abs=0.001)
    assert detector.observations[1].power_dbfs == pytest.approx(-30.309, abs=0.001)


def test_detector_rejects_bad_threshold_and_ci16_geometry() -> None:
    with pytest.raises(ValueError, match="threshold"):
        Ci16EnergyDetectorConfig(active_threshold_dbfs=float("nan"))
    detector = Ci16EnergyDetector(Ci16EnergyDetectorConfig(-20.0))
    visit = _visit(1_000)
    with pytest.raises(ValueError, match="geometry"):
        detector(AdaptiveScanVisit(visit.record, visit.iq[:-2]))


def test_controlled_target_mask_is_hash_bound_and_not_rf_dependent() -> None:
    config = TargetMaskDetectorConfig((1, 3))
    assert config.analysis_digest == TargetMaskDetectorConfig((1, 3)).analysis_digest
    assert config.analysis_digest != TargetMaskDetectorConfig((3, 1)).analysis_digest
    detector = TargetMaskDetector(config)
    quiet = _visit(0)
    active = AdaptiveScanVisit(
        dataclasses.replace(quiet.record, target=1),
        quiet.iq,
    )
    assert detector(quiet) is ScanOutcome.QUIET
    assert detector(active) is ScanOutcome.ACTIVE

    with pytest.raises(ValueError, match="unique"):
        TargetMaskDetectorConfig((1, 1))
