"""Major-3 host feedback over the existing serial-attested single-RX lifecycle."""

from types import ModuleType
from typing import Any

from pluto_plus.hardware.iio_persistent_hop import IioPersistentHopBackend
from pluto_plus.host_adaptive_hop import (
    HOST_ADAPTIVE_REQUEST_BYTES,
    HostAdaptiveHopEvidenceV3,
    HostAdaptiveHopRequestV3,
    HostFeedbackV1,
    require_host_adaptive_capabilities,
)
from pluto_plus.host_adaptive_hop_client import HostAdaptiveHopClient
from pluto_plus.persistent_hop import (
    PersistentHopClientError,
    PersistentHopEvidenceV1,
    PersistentHopRequestV1,
    SingleRxPersistentHopPlanV2,
)


class IioHostAdaptiveHopBackend(IioPersistentHopBackend):
    """One buffer owns IQ, status and feedback; the radio detector stays disabled."""

    _host_request: HostAdaptiveHopRequestV3 | None = None

    def _request_geometry(self, request: bytes) -> PersistentHopRequestV1:
        if len(request) != 104 + HOST_ADAPTIVE_REQUEST_BYTES:
            raise PersistentHopClientError("host adaptive OPEN request has the wrong size")
        decoded = HostAdaptiveHopRequestV3.unpack(request[104:])
        require_host_adaptive_capabilities(self.context_attributes(), decoded.policy)
        plan = self._prepared_plan
        if (
            not isinstance(plan, SingleRxPersistentHopPlanV2)
            or plan.receiver_id != decoded.decision.receiver_id
            or self.metadata_extension is not None
        ):
            raise PersistentHopClientError("host adaptive physical RX/detector ownership mismatch")
        self._host_request = decoded
        return decoded.geometry

    def _evidence_geometry(self, payload: bytes) -> PersistentHopEvidenceV1:
        if self._host_request is None:
            raise PersistentHopClientError("host adaptive evidence before request negotiation")
        decoded = HostAdaptiveHopEvidenceV3.unpack(payload)
        decoded.validate_binding(self._host_request)
        return decoded.geometry

    def submit_metadata_feedback(self, payload: bytes) -> None:
        HostFeedbackV1.unpack(payload)
        self._require_capture().submit_metadata_feedback(payload)


def iio_host_adaptive_hop_client(
    uri: str,
    *,
    expected_serial: str,
    adi_module: ModuleType | Any | None = None,
    iio_module: ModuleType | Any | None = None,
) -> HostAdaptiveHopClient:
    return HostAdaptiveHopClient(
        uri,
        expected_serial=expected_serial,
        backend_factory=lambda selected: IioHostAdaptiveHopBackend(
            selected,
            expected_serial=expected_serial,
            adi_module=adi_module,
            iio_module=iio_module,
        ),
    )
