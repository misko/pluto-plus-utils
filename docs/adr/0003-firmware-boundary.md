# ADR 0003: firmware mutation is a separate privileged boundary

Status: accepted

The web/API process remains unprivileged. Firmware mutation is expressed as an
immutable plan bound to the exact radio serial, physical USB path, observed
firmware, image digest, operation mode, and expiration. Execution rechecks all
of those facts and consumes a one-time confirmation before invoking a narrow
privileged backend.

Volatile RAM loading is the qualification path. Persistent QSPI promotion is a
separate operation after RAM acceptance. It accepts only a validated
`pluto.frm`, writes only that filename through the selected radio's updater
volume, and refuses archives or `boot.frm` so the bootloader partitions are not
part of the operation.
