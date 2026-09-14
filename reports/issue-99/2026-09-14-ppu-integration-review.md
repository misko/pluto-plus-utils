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
