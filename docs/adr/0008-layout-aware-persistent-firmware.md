# ADR 0008: Persistent firmware transitions name both IIO layouts

## Status

Accepted.

## Context

The original standalone persistent updater assumed a paired-RX, TX-capable
runtime on both sides of every transition. That assumption cannot safely
describe a 1R1T source or firmware that deliberately removes the DDS, TX DMA,
and tandem devices. Relaxing the old checks globally would make the updater
less useful as a safety boundary.

## Decision

Every exceptional topology-changing profile names an exact source and return
IIO layout. The shipped layouts currently cover profile-matched 2R2T,
TX-capable 1R1T, and RX-only 1R1T. A layout binds:

- the exact RX scan channels;
- DDS and tandem presence;
- TX gain, DDS scan, and DDS tone control counts;
- the minimum buffer inventory and required idle values;
- the shared TX-LO powerdown inventory where applicable; and
- the device-tree contract for the 1R1T TX-capable or RX-only topology.

Profiles may also enumerate exact admissible source firmware versions. The
plan records both layout identifiers, and execution rejects a plan if either
identifier no longer matches the selected shipped profile.

The RX-only return gate is affirmative: one TX gain must be at or below -80 dB,
the shared TX LO must be powered down, every buffer must be idle, DDS and tandem
must be absent from IIO, the RX-only root marker must exist, RX DMA must be
enabled, and DDS, TX DMA, and tandem device-tree nodes must be disabled.

A hardware-unqualified persistent canary is local-USB only. A distinct policy
with the same immutable DFU/FIT bytes may authorize LAN persistence only after
the local persistent return, deterministic workload, reboot/cold-return, and
rollback gates pass. This is a policy change, not a caller-supplied override.

The 15 MS/s Starlink PSS RX-only v7 promotion satisfied that boundary on the
dedicated local canary serial `1040007c4a94000211000b009186843ef2`. The exact
DFU SHA-256 is `dfd38e9e687f881599a3e4dea0070430e3731193debda64e313305a90dfd833d`.
Persistent return and exact-topology reboot retained the same firmware and
RX-only layout; deterministic phases `0`, `19999`, and `7311` each produced a
unique peak at the requested phase across nine continuous, fault-free maps;
the exact v0.48 recovery image returned successfully; and restoring the same
v7 bytes also returned successfully. LAN use is therefore authorized only by
the distinct `starlink-pss-15m-rx-only-dnm-v7-persistent-promotion` profile;
the original `persistent-canary` profile remains hardware-unqualified and
local-only.

## Consequences

- Existing paired-RX profiles retain their prior behavior.
- One-radio RX-only deployments use the same guarded updater and durable receipt
  machinery instead of a direct SSH or MTD bypass.
- A source-version or topology mismatch fails before staging firmware.
- LAN receipts schema v2 include both layouts and a post-key-rotation, read-only
  return attestation of QSPI identity, device-tree state, and TX safety.
