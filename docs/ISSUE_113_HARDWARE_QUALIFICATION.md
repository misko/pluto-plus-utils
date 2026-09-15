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

## Radio .14 bench preparation, 2026-09-15

The user dedicated recovered `.14` to disruptive qualification testing with its
SD recovery card and UART. Read-only probes on the bound FTDI console confirmed
its recovered GLRT firmware, QSPI power-on boot, expected partition geometry and
disabled IIO buffer. A new private directory, `~/pluto-qualification-99-radio14`,
retains the probe transcript separately from the completed recovery session.

The prepared `issue99-radio14-sd.zip` contains the unchanged, pinned console-only
SD bootstrap, the candidate under `issue99-candidate.itb`, the recovered rollback
FIT under `radio14-rollback.itb`, and a manifest verifier. No automatic candidate
boot or flash command is added. Candidate FIT `config@9`, selected component
hashes, Z7010 FPGA part metadata, load bounds and the 47,270,912-byte expanded
ramdisk passed offline validation. This is preparation evidence, not a new
production qualification profile.

ZIP SHA-256: `fec62345b5674a3552b742924cb03c8884bba2fa3d2445af420557416015d284`.
Manifest SHA-256: `65376df534aa2e69c9cc556497e5754caf1365fd8337bc617736b466d847e801`.

Next, transfer and verify the bundle on the recovery SD card with the radio
powered off. Keep existing backups. Once the card is ready, acquire UART before
powering on in SD mode, then independently capture the fresh recovered flash
baseline. No candidate boot, scratch write, bootloader installation or extended
qualification has yet been performed. The old Linux writer must not be used for
unbounded full-flash reads.

## First live candidate RAM/read milestone, 2026-09-15

The exact SD bootstrap and target passed live re-attestation. A fresh complete
32 MiB physical capture, with independent native-address boundary checks, matched
the repaired baseline `70ab950899687290560e3bfe86044bd26fa462a5abc37f4277c1687648889afa`.
The host backup and its SD export/reload round trip passed. The completed incident
recovery session remains unchanged; new evidence is in the qualification directory.

The candidate passed exact SD-to-RAM hashing and booted `config@9` using
`rdinit=/bin/sh`. Normal init, automatic updaters, JFFS mounting and watchdog startup
were bypassed. Its kernel and updater artifact hashes matched; IIO buffers were
disabled and TX sources were disabled before flash-read verification.

The live NOR is on `spi2.0` rather than the initially assumed `spi0.0`; its UID
attribute is binary and was inspected as hexadecimal. After correcting those
probe assumptions, identity matched the bound Winbond device and the addressing
attribute reported `verified-ear-v1`. The candidate's complete 32 MiB Linux
readback and protected-region hashes matched the independently captured baseline.

This qualifies neither erase/program behavior nor persistent candidate boot.
No flash writes were issued during this milestone. Next: return to SD with full
power removal, independently verify unchanged flash, then construct the exact
scratch-sector write/restore experiment. All extended production grants remain
disabled.

## Two-sector Linux erase/program milestone

After full power removal and SD return, the independent complete flash hash
remained equal to the recovered baseline. The exact candidate was RAM-booted
again. The controlled test staged and verified both 64 KiB patterns and both
original restoration payloads before the first erase.

Physical sectors `0x00FF0000` and `0x01000000` were erased and programmed
separately through the repaired kernel's raw MTD interface. Each erase and
program was followed by a complete flash comparison against the exact expected
intermediate image. Both sectors passed; no bytes outside the two planned
sectors changed according to this Linux readback. These sectors lie beyond the
installed GLRT FIT. This is a dedicated bench operation, not a production
qualification or a change to PPU's update limit.

The expected patterned image SHA-256 is
`0b95dd4d195a501cf33bc8aaf9633e025fe8711c9d8683011da2ac27c123ef4c`.
The private `scratch-plan.json`, original sector files, expected full image and
fsynced intent/verification journal retain the exact operation and restoration
evidence. The patterns remain installed pending independent SD comparison;
restoration is not yet complete.

A pre-write UID check initially timed out because a kernel informational message
split the console protocol's BEGIN marker. The retained transcript proves the
read completed; no erase/program intent existed at that point. Suppressing
informational UART printk messages with `dmesg -n 1` for the RAM bench session
allowed re-attestation to complete. Kernel messages remain available in dmesg.
No uncertain flash operation was retried.

## Independent placement check and Linux restoration

After full power removal, SD U-Boot independently read the complete patterned
flash image as
`0b95dd4d195a501cf33bc8aaf9633e025fe8711c9d8683011da2ac27c123ef4c`.
Both sector hashes and representative native four-byte reads at each sector's
start and end matched. Replacing the two planned sectors in that image with the
saved originals reconstructed the exact recovered baseline, proving no changes
outside the planned sectors.

The first native endpoint implementation attempted every byte through 16-byte
SPI console transactions. It was interrupted during read-only verification
because it was unnecessarily slow; no mutation command was active. The bounded
endpoint version retained the full-image SF hash and used independent native
reads at the four relevant endpoints.

The candidate was then RAM-booted again. Both original sector payloads were
transferred and hash-verified before restoration began. Each sector at
`0x00FF0000` and `0x01000000` passed erase verification, program verification and
a complete expected-image comparison after every mutation. The final candidate
Linux readback returned the recovered baseline hash
`70ab950899687290560e3bfe86044bd26fa462a5abc37f4277c1687648889afa`.

An independent SD physical comparison after full power removal remains required
before returning the target to normal QSPI boot. Extended production access is
still disabled.
