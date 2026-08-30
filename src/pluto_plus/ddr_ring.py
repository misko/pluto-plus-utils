"""Strict host contracts for atomic device DDR ring status snapshots."""

from __future__ import annotations

from typing import Literal

from pydantic import ConfigDict, Field, model_validator

from pluto_plus.models import ApiModel

DdrRingState = Literal[
    "off",
    "reserved",
    "running",
    "draining",
    "complete",
    "failed",
    "cancelled",
]
DdrRingTerminalReason = Literal[
    "none",
    "target_complete",
    "client_cancelled",
    "client_disconnected",
    "consumer_stall",
    "dma_error",
    "counter_gap",
    "transport_error",
    "internal_error",
    "gain_event_gap",
    "gain_event_overflow",
    "metadata_protocol",
]

_U64_MAX = (1 << 64) - 1
_FAILURE_REASONS = {
    "consumer_stall",
    "dma_error",
    "counter_gap",
    "transport_error",
    "internal_error",
    "gain_event_gap",
    "gain_event_overflow",
    "metadata_protocol",
}
_V2_ONLY_REASONS = {"gain_event_gap", "gain_event_overflow", "metadata_protocol"}


class DdrRingStatusSnapshot(ApiModel):
    """One strict pylibiio mapping of the versioned 128-byte status wire record."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    version: Literal[1, 2]
    state: DdrRingState
    terminal_reason: DdrRingTerminalReason
    error_code: int = Field(ge=-(1 << 31), le=(1 << 31) - 1)
    requested_capacity_iq_bytes: int = Field(gt=0, le=_U64_MAX)
    admitted_capacity_iq_bytes: int = Field(gt=0, le=_U64_MAX)
    target_frames: int = Field(ge=0, le=_U64_MAX)
    produced_frames: int = Field(ge=0, le=_U64_MAX)
    consumed_frames: int = Field(ge=0, le=_U64_MAX)
    high_water_frames: int = Field(ge=0, le=_U64_MAX)
    wrap_count: int = Field(ge=0, le=_U64_MAX)
    producer_position: int = Field(ge=0, le=_U64_MAX)
    consumer_position: int = Field(ge=0, le=_U64_MAX)
    last_contiguous_sample_sequence: int | None = Field(default=None, ge=0, le=_U64_MAX)
    first_unavailable_sample_sequence: int | None = Field(default=None, ge=0, le=_U64_MAX)
    failure_frame_index: int | None = Field(default=None, ge=0, le=_U64_MAX)
    failure_sample_sequence: int | None = Field(default=None, ge=0, le=_U64_MAX)

    @model_validator(mode="after")
    def validate_wire_relations(self) -> DdrRingStatusSnapshot:
        if self.admitted_capacity_iq_bytes > self.requested_capacity_iq_bytes:
            raise ValueError("DDR ring admitted capacity exceeds its request")
        if self.consumed_frames > self.produced_frames:
            raise ValueError("DDR ring consumed count exceeds its produced count")
        if self.high_water_frames > self.produced_frames:
            raise ValueError("DDR ring high-water count exceeds its produced count")

        has_failure_coordinates = (
            self.failure_frame_index is not None or self.failure_sample_sequence is not None
        )
        if self.version == 1 and has_failure_coordinates:
            raise ValueError("DDR ring status v1 cannot contain v2 failure coordinates")
        if self.version == 1 and self.terminal_reason in _V2_ONLY_REASONS:
            raise ValueError("DDR ring status v1 cannot contain a v2 terminal reason")

        if self.state in {"off", "reserved", "running", "draining"}:
            valid_terminal = self.terminal_reason == "none" and self.error_code == 0
        elif self.state == "complete":
            valid_terminal = self.terminal_reason == "target_complete" and self.error_code == 0
        elif self.state == "failed":
            valid_terminal = self.terminal_reason in _FAILURE_REASONS and self.error_code < 0
        else:
            valid_terminal = (
                self.terminal_reason in {"client_cancelled", "client_disconnected"}
                and self.error_code < 0
            )
        if not valid_terminal:
            raise ValueError("DDR ring state/reason/error relation is inconsistent")
        if self.state != "failed" and has_failure_coordinates:
            raise ValueError("only a failed DDR ring status may contain failure coordinates")
        return self


class DdrRingFinalStatus(DdrRingStatusSnapshot):
    """A terminal ring status that proves every requested host frame arrived."""

    @model_validator(mode="after")
    def validate_complete_capture(self) -> DdrRingFinalStatus:
        if (
            self.state != "complete"
            or self.terminal_reason != "target_complete"
            or self.error_code != 0
        ):
            raise ValueError("DDR ring did not reach a clean target-complete state")
        if self.target_frames <= 0:
            raise ValueError("finite DDR ring capture has no target frames")
        if not (self.produced_frames == self.consumed_frames == self.target_frames):
            raise ValueError("DDR ring producer/consumer frame counts do not close")
        if self.high_water_frames < 1:
            raise ValueError("DDR ring did not report occupied storage")
        return self
