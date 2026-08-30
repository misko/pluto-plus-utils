from __future__ import annotations

import pytest
from pydantic import ValidationError

from pluto_plus.ddr_ring import DdrRingFinalStatus, DdrRingStatusSnapshot


def _status(**updates: object) -> dict[str, object]:
    status: dict[str, object] = {
        "version": 1,
        "state": "complete",
        "terminal_reason": "target_complete",
        "error_code": 0,
        "requested_capacity_iq_bytes": 65,
        "admitted_capacity_iq_bytes": 64,
        "target_frames": 4,
        "produced_frames": 4,
        "consumed_frames": 4,
        "high_water_frames": 2,
        "wrap_count": 2,
        "producer_position": 0,
        "consumer_position": 0,
        "last_contiguous_sample_sequence": 1_024,
        "first_unavailable_sample_sequence": None,
        "failure_frame_index": None,
        "failure_sample_sequence": None,
    }
    status.update(updates)
    return status


def test_status_v1_and_v2_are_strict_typed_contracts() -> None:
    complete = DdrRingFinalStatus.model_validate(_status())
    assert complete.version == 1

    failed = DdrRingStatusSnapshot.model_validate(
        _status(
            version=2,
            state="failed",
            terminal_reason="gain_event_gap",
            error_code=-5,
            produced_frames=3,
            consumed_frames=2,
            failure_frame_index=0,
            failure_sample_sequence=0,
        )
    )
    assert failed.failure_frame_index == 0
    assert failed.failure_sample_sequence == 0


@pytest.mark.parametrize(
    "updates",
    (
        {"version": 1, "failure_frame_index": 0},
        {"version": 1, "terminal_reason": "gain_event_overflow"},
        {"version": 2, "failure_frame_index": 1},
        {"version": 2, "state": "failed", "terminal_reason": "none", "error_code": -5},
        {"version": 2, "state": "failed", "terminal_reason": "dma_error", "error_code": 0},
        {"consumed_frames": 5},
        {"requested_capacity_iq_bytes": "65"},
        {"unexpected": 1},
    ),
)
def test_status_contract_rejects_invalid_or_untyped_mappings(
    updates: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        DdrRingStatusSnapshot.model_validate(_status(**updates))
