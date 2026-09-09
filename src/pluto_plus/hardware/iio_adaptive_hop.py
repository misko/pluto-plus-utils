"""Explicit adaptive V2 backend using the existing physical-LAN radio lifecycle."""

from types import ModuleType
from typing import Any

from pluto_plus.adaptive_hop import (
    ADAPTIVE_HOP_REQUEST_BYTES,
    AdaptiveHopEvidenceV2,
    AdaptiveHopRequestV2,
    require_adaptive_capabilities,
)
from pluto_plus.adaptive_hop_client import AdaptiveHopClient
from pluto_plus.hardware.iio_persistent_hop import IioPersistentHopBackend
from pluto_plus.metadata_extension import PersistentHopMetadataExtension
from pluto_plus.persistent_hop import (
    PersistentHopClientError,
    PersistentHopEvidenceV1,
    PersistentHopRequestV1,
)


class IioAdaptiveHopBackend(IioPersistentHopBackend):
    """V2 is required explicitly; V1 fallback is never mislabeled adaptive.

    Source-stream validation belongs to AdaptiveHopStreamV2. Shared base
    methods own attested identity, settings/profile preparation, raw capture,
    exact base-header binding, clock brackets, and settings restoration.
    """

    _requires_negotiated_extension = True
    _adaptive_request: AdaptiveHopRequestV2 | None = None

    def _request_geometry(self, request: bytes) -> PersistentHopRequestV1:
        if len(request) != 104 + ADAPTIVE_HOP_REQUEST_BYTES:
            raise PersistentHopClientError("adaptive OPEN request has the wrong size")
        decoded = AdaptiveHopRequestV2.unpack(request[104:])
        decoded.policy.require_pinned_policy()
        require_adaptive_capabilities(self.context_attributes(), decoded.policy)
        self._adaptive_request = decoded
        return decoded.geometry

    def _evidence_geometry(self, payload: bytes) -> PersistentHopEvidenceV1:
        if self._adaptive_request is None:
            raise PersistentHopClientError("adaptive evidence before request negotiation")
        decoded = AdaptiveHopEvidenceV2.unpack(payload)
        decoded.validate_binding(self._adaptive_request)
        return decoded.geometry


def iio_adaptive_hop_client(
    uri: str,
    *,
    expected_serial: str,
    metadata_extension: PersistentHopMetadataExtension,
    adi_module: ModuleType | Any | None = None,
    iio_module: ModuleType | Any | None = None,
) -> AdaptiveHopClient:
    """Explicit userspace V2 client; never changes the fixed-scan default."""
    return AdaptiveHopClient(
        uri,
        expected_serial=expected_serial,
        backend_factory=lambda selected: IioAdaptiveHopBackend(
            selected,
            expected_serial=expected_serial,
            metadata_extension=metadata_extension,
            adi_module=adi_module,
            iio_module=iio_module,
        ),
    )
