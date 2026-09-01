# ADR 0007: Isolate RX-only RAM qualification in v2 contracts

## Status

Accepted for implementation on 2026-09-01. This contract does not authorize a
specific firmware image or persistent firmware write.

## Context

The release-candidate v1 lifecycle proves a TX-capable, paired-RX, tandem-AGC
runtime. An RX-only FPGA image intentionally removes the DDS, TX DMA, and tandem
devices which v1 requires. Making those fields optional in v1 would allow a
weaker topology to be mistaken for previously qualified tandem firmware.

AD936x 1R1T also has a different observable safety ABI: it exposes exactly one
TX hardware-gain control and one shared TX-LO powerdown control. Duplicating the
shared value or expecting two TX-gain controls would create false evidence or an
unreachable contract.

## Decision

RX-only RAM deployment uses four new literal schemas:

- `pluto-plus-utils.release-candidate-plan.v2`;
- `pluto-plus-utils.release-candidate-operation-plan.v2`;
- `pluto-plus-utils.release-candidate-ram-receipt.v2`; and
- `pluto-plus-utils.release-candidate-recovery-receipt.v2`.

The strict USB inventory remains `release-usb-inventory.v1` because its physical
serial/topology/interface facts do not describe FPGA capability. CLI dispatch
accepts only an exact known schema literal; it never converts between versions.

## Prerequisite and transition

The ordinary PPU setup lifecycle must first persist, reboot, and verify exactly
`ad9361-1r1t` or `ad9363a-1r1t`. The v2 operation plan records that explicit
target and uses confirmation:

`RAM BOOT RX-ONLY RELEASE CANDIDATE <serial> <runtime-target>`

Preboot attestation accepts only `tx-capable-1r1t-v1`: the selected target's
exact U-Boot attr pair/compatible/mode, matching live PHY, exact two-element RX
scan geometry, RX DMA, DDS, TX DMA, and tandem devices, and no RX-only marker.
Canonical 2R2T and an implicit/default target are rejected before DFU.

The backend first proves the exact gain, RX-LO/shared-TX-LO powerdown, and DDS
control inventories, then performs the bounded `tx-quiesce-v1` safe-direction
mutation. It sets the one exposed gain to the mute limit, powers down the shared
TX LO, disables four DDS raw/scale controls, and selects the two safe DAC
sources. Readback then proves those values and tandem idle/FIFO/fault state
before DFU begins. The receipt records the control names and successful
readback. Failure never authorizes restoring TX; safe values remain until
reboot.

After the sealed RAM-only DFU transition, `rx-only-v1` requires the same physical
target, hardware model, U-Boot/PHY target, and RX scan geometry, plus:

- RX DMA present and enabled;
- DDS absent from IIO and disabled in the device tree;
- TX DMA disabled in the device tree;
- tandem absent from IIO and disabled in the device tree;
- exact root marker `misko,rx-only-fpga`;
- the exact one-gain/one-shared-LO inventory in the safe state;
- a new boot ID; and
- unchanged byte count and SHA-256 of `qspi-linux`.

Metadata ABI may be null and the capability tuple may be empty, but both remain
exact candidate-plan fields rather than inferred defaults.

## Recovery

Recovery is rollback, not observation of whichever runtime happens to answer.
A route-released PASS receipt is the ordinary source after every successful RAM
trial. A route-released UNKNOWN is eligible only after its sealed transition
started; its download and detach facts may be incomplete. A reconciled UNKNOWN
may have `cleanup.verified=true` with an exact candidate RX-only or original
persistent TX-capable observation. That is safe-state evidence, not proof that
rollback occurred. FAILED pre-transition receipts and unstarted UNKNOWN
receipts are never eligible.

Recovery always invokes the fixed persistent reset, even when a runtime is
already present. A DFU-state device is first detached at the exact topology,
then reset through persistent QSPI. The pre-reset USB runtime must first depart;
only its subsequent return may be attested. Success requires the operation
plan's original current firmware, TX-capable 1R1T layout, unchanged setup target,
a boot ID different from every available source pre/post observation, unchanged QSPI
identity, verified quiesce readback, and released host route. The v2 recovery
receipt records the bound source outcome and verified pre-reset USB departure;
its schema cannot express `rx-only` as a successful return layout.

## Compatibility and migration

All v1 model classes, schema literals, serializers, lifecycle functions, Linux
attestor, and confirmation phrases remain unchanged. Legacy tandem qualification
continues to load only v1 operation/receipt models and therefore rejects v2.

The rollout order is:

1. merge target-aware PPU setup support;
2. merge this reusable v2 lifecycle to PPU main;
3. make the experimental firmware branch emit and validate exact v2 documents;
4. set up one canary radio to the chosen 1R1T target and retain its receipt;
5. RAM boot, qualify, and use its PASS/eligible-UNKNOWN receipt to produce a
   persistent-rollback receipt;
6. repeat that complete boot/qualify/rollback sequence for staged 15/30/60 MS/s
   trials; and
7. restore the normal PPU 2R2T target only after all trials finish.

Starlink-specific algorithms and FPGA images remain outside PPU. PPU owns only
the reusable target setup, exact device operation, safety, and evidence contracts.
