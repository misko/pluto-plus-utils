"""Native 10 MS/s single-RX reconstruction from major-3 actual visit evidence."""

from __future__ import annotations

import dataclasses

import numpy as np
import numpy.typing as npt

from .adaptive_hop import AdaptiveHopChoiceV2
from .adaptive_hop_stream import (
    AdaptiveHopVisitV2,
    _AdaptiveHopStream,
    _AdaptiveHopStreamReceipt,
)
from .direct_radio.samples import ci16_single_rx
from .host_adaptive_hop import (
    HostAdaptiveHopEvidenceV3,
    HostAdaptiveHopRequestV3,
    HostAdaptiveHopRequestV4,
    HostAdaptiveHopStatusV3,
)
from .persistent_hop import PersistentHopClientError, PersistentHopEvidenceV1


@dataclasses.dataclass(frozen=True, slots=True)
class HostAdaptiveHopSampledVisitV3:
    visit: AdaptiveHopVisitV2
    samples: npt.NDArray[np.complex64]
    receiver_id: int

    def __post_init__(self) -> None:
        if (
            type(self.receiver_id) is not int
            or self.receiver_id not in (0, 1)
            or self.samples.dtype != np.complex64
            or self.samples.shape != (1, self.visit.valid_sample_count)
        ):
            raise ValueError("host adaptive IQ disagrees with selected physical RX/valid interval")


@dataclasses.dataclass(frozen=True, slots=True)
class HostAdaptiveHopStreamReceiptV3(
    _AdaptiveHopStreamReceipt[HostAdaptiveHopRequestV3, HostAdaptiveHopStatusV3]
):
    """Actual native sample spans; selected physical RX is bound by request."""


def _decode_v3(
    payload: bytes, request: HostAdaptiveHopRequestV3
) -> tuple[PersistentHopEvidenceV1, tuple[AdaptiveHopChoiceV2, ...]]:
    evidence = HostAdaptiveHopEvidenceV3.unpack(payload)
    evidence.validate_binding(request)
    return evidence.geometry, evidence.choices


class HostAdaptiveHopStreamV3(
    _AdaptiveHopStream[
        HostAdaptiveHopRequestV3,
        HostAdaptiveHopStatusV3,
        HostAdaptiveHopSampledVisitV3,
        HostAdaptiveHopStreamReceiptV3,
    ]
):
    """One native payload row for either RX, with exact uint64 source counters."""

    def __init__(
        self,
        request: HostAdaptiveHopRequestV3 | HostAdaptiveHopRequestV4,
        *,
        samples_per_block: int,
        minimum_valid_duty_ppm: int = 950_000,
        maximum_event_lag_blocks: int = 2,
    ) -> None:
        if type(request) not in (HostAdaptiveHopRequestV3, HostAdaptiveHopRequestV4):
            raise PersistentHopClientError("adaptive stream request major mismatch")
        super().__init__(
            request,
            request_type=type(request),
            status_type=HostAdaptiveHopStatusV3,
            decode_evidence=_decode_v3,
            decode_samples=ci16_single_rx,
            bytes_per_sample=4,
            sampled_visit=lambda visit, samples: HostAdaptiveHopSampledVisitV3(
                visit, samples, request.decision.receiver_id
            ),
            receipt=HostAdaptiveHopStreamReceiptV3,
            samples_per_block=samples_per_block,
            minimum_valid_duty_ppm=minimum_valid_duty_ppm,
            maximum_event_lag_blocks=maximum_event_lag_blocks,
        )
