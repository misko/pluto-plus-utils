# Firmware #99: recent PPU review and continuation

Reviewed PPU main at `0ae626c7daad7f60d2e416ddb776e2576ef445ea`, particularly
`d201971` (physical flash safety), `0ae626c` (guided SD recovery), `d85199a`
(v0.50 qualification), and `fe032e5` (BusyBox network encoding compatibility).
Firmware candidate remains draft PR https://github.com/misko/plutosdr-fw/pull/100.

## Findings

1. **Fixed: protected backups required an absent applet.**
   `FlashSession._read` used `head ... | base64`. The released ARM BusyBox in
   the #99 candidate has `uuencode` and `uudecode`, but no `base64`. The network
   path already accommodated this; the new flash path did not. The pipeline
   also discarded the reader's failure status. Read into a private, lock-owned
   temporary file, check the read status and byte count, then encode with
   `base64` or `uuencode -m`. Keep the existing strict host decoder and length
   check. Clean the temporary file on success and failure. This does not change
   permitted ranges or write authorization.

2. **Remaining integration requirement: recognize the whole #99 writer.**
   `validate_flash` currently permits only the legacy updater fingerprint.
   After installing #99, subsequent PPU updates will intentionally fail with
   `flash_writer_unknown`. Simply adding the new `/sbin/update_frm.sh` hash is
   insufficient: it is a wrapper around `/usr/sbin/pluto-fw-update`. Introduce
   an explicit reviewed writer identity covering that helper, its range helper,
   and the actual executable dependencies. Preserve legacy support and the
   physical 16 MiB default. Test missing/modified dependencies, unknown writer
   versions, changed observations between planning and invocation, and a
   successful second update after bootstrap. An extended-address qualification
   must remain a separate evidence-bound decision.

3. **Recovery progress is ahead of the committed narrative.**
   The private `.14` session's verified journal includes `flash_verified`,
   `awaiting_cold_boot`, and the operator's power-off/SD-removal event. Latest
   read-only status still reports `awaiting_cold_boot` (314 events). This is not
   completed recovery or proof of a persistent boot. Resume the same recovery
   session for return attestation; do not create another repair or repeat writes.
   The incident recipe is bound to one unit and exact rollback artifacts. It
   does not qualify the general upper-bank write path.

## Validation of this patch

- 632 tests passed across flash safety, IP firmware, bootstrap, DFU safety and
  SD recovery suites (one dependency deprecation warning).
- Five reader cases passed under the actual candidate ARM BusyBox via qemu-arm:
  binary round trip without base64, short read, reader error, encoder error,
  and wrong lock owner. Temporary file cleanup is checked.
- Ruff passed for changed Python files; mypy passed for flash_safety_io.py.
- These are software and emulated-shell checks, not physical flash qualification.

The ARM regression can be repeated with `PYTHONPATH=src`, the repository's dev
Python environment, and `PPU_TEST_BUSYBOX` set to an absolute qemu-arm command
prefix followed by `-L ROOT ROOT/bin/busybox`, running
`pytest tests/test_flash_safety.py -k reader_without_base64 -q`.

## Continuation sequence

1. Finish the existing recovery session's cold-boot acceptance and retain its
   sanitized receipt. Coordinate ownership before opening its UART.
2. Add the complete #99 writer identity and its rejection tests in PPU while
   keeping ordinary writes below physical 16 MiB.
3. Prepare a candidate that preserves the selected radio's intended FPGA and
   userspace role. The current #99 candidate uses v0.50 counter-RX components;
   the incident rollback is a GLRT image, so they are not feature-equivalent.
4. On the recovered, explicitly selected unit, capture protected-region hashes,
   RAM-test the exact candidate, install the below-boundary bootstrap, verify
   flash and protected regions, then record a real cold boot and radio checks.
5. Separately qualify boundary-crossing writes, bank reset, injected failures,
   and cold boot with recoverable hardware evidence before enabling any larger
   physical address limit. Neither recent PPU commit grants that permission.

No hardware was accessed or flashed by this review. Raw recovery images and
identity evidence remain outside the repository.

## Implemented integration, 2026-09-15

The integration branch now includes current main through `9a4dc78`, the BusyBox
backup fix, and a pinned conservative writer footprint in
`src/pluto_plus/flash_writer_issue99.json`. Its aggregate covers 36 file paths,
including the wrapper, implementation/range helpers, resolved external commands,
shell, dynamic loader and required libraries. Unknown helper bytes or changed
PATH resolution are refused. No extended qualification is added.

Live `.14` preflight exposed and corrected authentication diagnostics leaking
into SSH command results and quadratic prompt scanning during large backups.
The stdin handshake now separates authentication from command output, with a
bounded prompt-search window and a real-PTY binary-text capture regression.
The reviewed update transaction accepts CRC-valid opaque environment tail bytes
using U-Boot's double-NUL termination semantics; strict recovery parsing remains
the default. All original bytes are backed up and active settings remain protected.

Firmware packaging also needed a separate fix: the released BusyBox lacks `stat`,
so the common updater now uses `wc -c`. That change is Buildroot `857c1a817` and
produces candidate FIT SHA-256
`11248f8b028c5f1b09693c7c7ab9dddcbc63a2cb94ffdc4dab65ef8b5bea4562`.
It has the same kernel/FPGA as the RAM-tested candidate, with updated updater and
source provenance. Its persistent deployment is a new acceptance milestone.

Validation: 681 related PPU tests passed before the bounded-search change;
147 SSH/setup/bootstrap tests passed afterward, including the large-output PTY
regression. Ruff and type checks passed. The live protected-region and exact
rollback FIT backup then completed and matched the retained recovered baseline.

## Installed and exercised on .14

The immutable host release `issue99-a049f54` passed 682 installed-package tests
and comparison of all 122 package files. Local CLI launchers select that release;
previous targets remain recorded and existing daemon processes were not restarted.
Both Python 3.11/3.12/3.13 offline CI and browser CI passed on `a049f54`.

The dedicated `.14` radio passed conservative legacy-writer bootstrap, normal
candidate warm boot, a second update using the new writer, verified GLRT rollback,
and final candidate reinstall using the installed PPU package. Protected boot/NVM
and active environment settings were checked at each return. Receive-only capture
returned 1,024 samples and restored scan settings. Both PPU and the device refused
a valid FIT one byte beyond the permitted range, with identical full flash hashes
before and after. No extended production grant was added.

Cold-boot acceptance is waiting for operator power removal with UART capture
armed. Independent SD verification of the new persistent image, a single crossing
MTD request, installed bootloader extended paths and an actual crossing FIT remain
qualification work. Details are in firmware PR #100's deployment report.

## Candidate cold-return acceptance, 2026-09-15

The operator confirmed the requested power-off/SD-removed/QSPI boot procedure.
The original UART capture window had expired; attestation resumed from the
running console. The bound target reported power-on reset `0x00400000`, QSPI
selection `0x1` and a changed boot ID. Candidate FIT, complete writer footprint,
protected boot/NVM, active environment, IIOD and network IIO discovery passed.
The complete Linux flash hash matched the expected candidate image exactly.

The conservative candidate's cold-return milestone is complete. The private
receipt is in `~/pluto-qualification-99-radio14/deployment/cold-return.json`;
firmware PR #100 records its digest and the limits of this evidence. No new
independent SD capture or extended-range production grant is claimed.
