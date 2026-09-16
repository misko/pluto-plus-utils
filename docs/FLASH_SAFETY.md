PPU persistent flash safety (#113)
==================================

PPU validates the physical write and erase footprint independently of release
profile approval. For the usual firmware offset `0x200000`, an unqualified
writer may install at most `0xE00000` FIT bytes (14,680,064), ending exactly at
physical address `0x1000000`. The 33-byte FRM checksum trailer is excluded.
The incident FIT of 14,744,943 bytes is refused before update dispatch.

The shared policy is `pluto_plus.flash_safety`, revision
`ppu-physical-flash-v1`. It uses observed offsets, partition sizes, uniform erase
geometry and actual flash identity. It checks payload, rounded firmware erase
span and the separate environment write. Unknown or inconsistent observations
block persistence. Manufacturer, transport, profile approval and the incoming
kernel version cannot raise the limit.

**Supported execution boundaries**

- Standalone LAN and USB-bound SSH use an attested physical plan, one remote
  lock, private recovery evidence, final target/image checks, and protected-region
  verification before PPU dispatches reboot.
- The daemon's SSH executor uses the same policy and session. Planning and
  execution independently validate authoritative image bytes and observations.
- Legacy mass-storage/eject and helper protocol v1 persistence are refused before
  staging or updater execution. They cannot provide the required integrity gate
  before reboot. Select the SSH transport explicitly; PPU does not switch it for
  you. Existing `force-flash` naming does not bypass physical safety. A blank
  serial is currently insufficient for the implemented SSH flash observer.
- Concrete DFU subprocess runners check the exact USB path and full RAM alternate
  inventory immediately before downloading. The reviewed RAM mode exposes only
  `dummy.dfu` and `firmware.dfu`; SF mode and ambiguous inventories are refused.
  The filename `firmware.dfu` by itself grants no permission to write flash.

Credential-free standalone CLI dry runs are now labelled `inspection`, with
`executable=false` and `requires_flash_attestation=true`. Execution builds an
authenticated physical plan before invoking the existing confirmation-bound
executor. Programmatic planners can supply `flash_transport` for an attested plan.
Persisted or caller-constructed plans without the new evidence cannot execute.

**Initial compatibility contract**

This release supports the reviewed synchronous Linux `update_frm.sh` artifact
SHA-256 `d8a3693f88ca9f3f7e4f9e7b4ac4a62abb8976d610df058fc74bbd6a6ee915f0`,
its reviewed `device_config`, four physical MTD partitions, firmware at `mtd3`,
and a single 128 KiB environment at `mtd1`. Offsets are discovered, not assumed.
The environment config must name `/dev/mtd1 0x0000 0x20000 0x20000` after removing
comments and normalizing whitespace. Variable erase regions, nested/ambiguous
layouts, unsupported JEDEC density encodings and unavailable sysfs/FDT/build
evidence are refused. This is intentionally a narrow compatibility contract;
it is not a declaration that every Pluto+ variant is supported.

The qualification registry is empty. Future reviewed records must match board
evidence, flash identity/capacity/layout, running kernel, updater/utilities and
bootloader digest, with both write and cold-boot evidence. Tests inject synthetic
records; users and image manifests cannot supply a capability flag or ordinary
force option. Real extended-range enablement still requires firmware #99's
hardware qualification.

**Evidence and failure behavior**

Each supported update saves a private recovery directory next to its receipt:
boot/environment/spare backups, the previous validated FIT, a manifest of their
digests and the full applied decision. Files are mode 0600 and the directory is
0700. These files may contain device-specific information; they are local recovery
artifacts, not public test fixtures.

After update and flush, PPU reads the FIT and protected partitions through MTD,
checks lengths and bytes, verifies the environment CRC, and permits exactly the
planned hexadecimal `fit_size` change. All other environment variables must match.
The result records observed protected digests and the verified checkpoint.
Logical FIT verification is retained but is not treated as proof of physical
addressing. Legacy source/reconciliation reads are bounded below physical 16 MiB.

The remote `/tmp/ppu-physical-flash.lock` excludes overlapping PPU SSH updates.
PPU releases it after a pre-dispatch failure. After possible dispatch it retains
the lock until reboot, including verification/connection failures. An uncertain
write never triggers automatic reboot, retry or reflash. A definite protected
integrity failure is recorded separately from the existing `unknown` deployment
outcome; a later matching logical FIT cannot clear that failure. Keep the radio
running and use the retained evidence for explicit recovery.

Successful update still requires the existing same-radio firmware/service/layout
and RF-safety return attestation. A failed return remains `unknown`. Neither
offline tests nor an online software reboot establishes cold-boot qualification.
