"""Optional, narrow port for frame-carried persistent-hop analysis evidence.

The acquisition library owns IIO and validates legacy IQ/HOPS. The extension
owns its negotiated envelope and advisory result semantics. No detector or
application storage implementation is imported by the transport.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from pluto_plus.persistent_hop import PersistentHopEvidenceV1, PersistentHopStatusV1


class PersistentHopMetadataExtension(Protocol):
    def negotiate(
        self, request: bytes, attributes: Mapping[str, str], *, drain_supported: bool
    ) -> bytes:
        """Wrap explicitly, or return the unchanged request if unsupported."""
        ...

    def unwrap(self, metadata: bytes) -> bytes:
        """Return legacy metadata. Unrecoverable framing errors must raise."""
        ...

    def consume(
        self, metadata: bytes, iq_payload: bytes, *, evidence: PersistentHopEvidenceV1
    ) -> None:
        """Called only after normal HOPS, stream and IQ validation."""
        ...

    def finish(
        self, status: PersistentHopStatusV1, drain: Callable[[int], bytes]
    ) -> None:
        """Boundedly drain after validated terminal status, before buffer close."""
        ...

    def fail(self, reason: str) -> None:
        """Retain an explicit failure; never change acquisition policy."""
        ...
