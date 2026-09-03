"""Bounded child-process probe for a persistent-hop iiOD endpoint.

This private module is launched only by :mod:`pluto_plus.userspace_iiod`.  It
opens one exact physical-LAN libiio context, reads its immutable identity and
capability attributes, then closes it without opening a buffer or changing RF
settings.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence

from pluto_plus.hardware.iio_persistent_hop import IioPersistentHopBackend
from pluto_plus.persistent_hop import (
    PERSISTENT_HOP_CAPABILITIES,
    PERSISTENT_HOP_METADATA_ABI,
    require_allowed_serial,
    require_physical_lan_uri,
)


def probe_report(host: str, port: int, expected_serial: str) -> bytes:
    """Return a strict report only after exact persistent-hop attestation."""

    if port not in {30_431, 30_432}:
        raise ValueError("iiOD probe port must be 30431 or 30432")
    uri = require_physical_lan_uri(f"ip:{host}:{port}")
    serial = require_allowed_serial(expected_serial)
    backend = IioPersistentHopBackend(uri, expected_serial=serial)
    try:
        backend.open()
        attributes = dict(backend.context_attributes())
        if attributes.get("hw_serial") != serial:
            raise RuntimeError("iiOD probe serial readback changed")
        if attributes.get("iio,buffer-metadata") != PERSISTENT_HOP_METADATA_ABI:
            raise RuntimeError("iiOD probe requires exact metadata ABI 3")
        if port == 30_432:
            missing = tuple(
                capability
                for capability in PERSISTENT_HOP_CAPABILITIES
                if attributes.get(capability) != "1"
            )
            if missing:
                raise RuntimeError(
                    "iiOD probe lacks persistent-hop capabilities: " + ", ".join(missing)
                )
    finally:
        backend.close()
    lines = [
        f"PPU\tserial\t{serial}",
        f"PPU\tmetadata_abi\t{PERSISTENT_HOP_METADATA_ABI}",
        *(
            f"PPU\tcapability_{index}\t{capability}"
            for index, capability in enumerate(PERSISTENT_HOP_CAPABILITIES)
            if port == 30_432
        ),
    ]
    return ("\n".join(lines) + "\n").encode()


def main(argv: Sequence[str] | None = None) -> int:
    arguments = tuple(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 3:
        return 2
    host, raw_port, expected_serial = arguments
    try:
        port = int(raw_port)
        if str(port) != raw_port:
            return 2
        report = probe_report(host, port, expected_serial)
    except BaseException as error:
        print(
            f"persistent-hop endpoint probe failed: {type(error).__name__}: {error}",
            file=sys.stderr,
        )
        return 1
    sys.stdout.buffer.write(report)
    return 0


if __name__ == "__main__":  # pragma: no cover - subprocess entry point
    raise SystemExit(main())
