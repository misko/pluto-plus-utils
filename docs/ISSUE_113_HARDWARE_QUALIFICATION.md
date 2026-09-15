# PPU #113 hardware qualification handoff

Status, 2026-09-15: the `.14` incident recovery is complete. Extended-address
qualification remains pending. This document is a bench procedure, not a grant
to widen the production flash policy.

## Verified inputs

The recovered `.14` baseline and retained evidence are recorded in
[the recovery report](ISSUE_114_IMPLEMENTATION_REPORT.md). Preserve that session
unchanged; use a new private session for qualification. The old `original` image
is the damaged incident image, not the new pre-test baseline. Capture a fresh
complete physical backup of the recovered device before scratch testing.

Firmware #99 has an unqualified candidate in the local firmware checkout at
`build/issue99/candidate`. On 2026-09-15, all ten files matched the byte lengths
and SHA-256 values in `reports/issue-99-candidate.json`.

| Input | Value |
|---|---|
| Candidate version | `v0.50-counter-rx-v1-flash-safety-rc1` |
| FIT bytes | 13,008,423 |
| FIT SHA-256 | `c08feb750cc7c13729d2209f20a2515ef266ea0d04e3a79c8fd5ed4aa938d968` |
| FRM SHA-256 | `daa546db4a0651a3308a6b97a701dd61e12d733f8772cbb16462eb2f5d2f48b1` |
| FIT physical start | `0x00200000` |
| Exclusive payload end | `0x00E67E27` |
| Exclusive erase end | `0x00E70000` |
| Production address limit | `0x01000000` |

The candidate's FRM does not replace the installed bootloader. Its repaired
kernel cannot fix an old writer used to install it. PPU currently accepts only
the reviewed legacy updater fingerprint; the candidate's new updater contract
requires separate integration review before subsequent PPU persistence. Do not
add its hash alone to bypass that review.

## Bench sequence and required evidence

1. Dedicate an explicitly identified bench radio and stop its workloads. Bind
   serial/flash UID, board/SoC, geometry and UART/SD recovery path. Confirm the
   recovery card and an operator are available before any disruptive operation.
2. Independently capture and hash the recovered device's complete physical
   flash, protected regions and environment. Record running and installed
   software identities and validate the exact rollback artifacts. Retain the
   known working recovery path and its previous restoration evidence.
3. Prepare and verify an exact candidate SD/RAM boot recipe, including FIT
   configuration, FPGA/device-tree compatibility, RAM layout and RF inactivity.
   The existing incident recipe pins the recovered GLRT image; it does not
   authorize this different counter-runtime candidate. Re-attest after boot.
4. Construct a reviewable scratch-sector plan on both sides of 16 MiB. Identify
   every affected erase sector and its saved original bytes. Exercise distinct
   patterns, page/erase boundaries, high-to-low access and error handling using
   the repaired running writer. Compare through the independently validated
   physical reader, restore the originals and verify the complete flash image.
   Production update limits remain in place during controlled bench work.
5. Qualify recovery and installed U-Boot separately: bank selection, actual boot
   read commands and fallback lengths, environment writes, reset and handoff.
   Persistent DFU needs its own evidence if it is to be supported.
6. Only after those checks, exercise a controlled crossing FIT with warm reset,
   full power removal, identity/services/protected-region checks and rollback.
   Repeat for the additional Winbond sample and every hardware/software
   combination proposed for a qualification record.
7. Review the complete evidence before integrating a qualification record shared
   by PPU and the firmware updater. Match actual hardware, layout, running writer
   and installed bootloader; keep all untested combinations restricted.

At preparation time, no bench target has been confirmed for this new sequence.
No candidate boot, scratch write, new bootloader installation or extended-range
qualification was performed by this handoff. Artifact hash verification and the
successful GLRT incident recovery do not establish candidate compatibility.
