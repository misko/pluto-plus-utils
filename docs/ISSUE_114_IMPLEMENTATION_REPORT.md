# PPU #114 live incident recovery follow-up

The guided command now has a concrete `plutoplus-incident-114` backend. It is
restricted to the motivating radio, retained original flash digest, exact SD
bootstrap and rollback FIT. General hardware qualification remains pending.
Earlier release reports below describe superseded empty-registry installations.

Live validation on the bound FTDI UART established the flash UID, Z7010/512 MiB
identity, native four-byte read placement, bank-zero checks, executing U-Boot code
interval and SD asset hashes. A fresh complete 32 MiB capture matched the retained
original, and writing/reloading the SD backup matched the same digest. The
current `~/pluto-recovery-14` session is `plan_ready`: 73 changed sectors and an
expected full-image SHA-256 of
`70ab950899687290560e3bfe86044bd26fa462a5abc37f4277c1687648889afa`.
The plan matches the independently prepared incident repair image.

The RAM-only SHA-256 helper is reproducibly compiled and passed native vectors,
ARM emulation and live vector/full-flash checks. Its first development attempt
faulted and reset the CPU; disabling caches before upload and verifying every
uploaded byte corrected that fault. No persistent flash writes were performed.

The runtime recipe bypasses normal init and environment boot helpers during RAM
trial, verifies pinned kernel/rootfs files, boot registers, preserved partition
hashes, Ethernet/IIOD context and RF inactivity. It then requires return to SD and
an unchanged full-flash comparison. Cold acceptance separately records physical
operator actions and checks QSPI source plus power-on reset. These live RAM,
write/readback and cold-boot stages remain pending the SD card transfer and actual
execution. Simulated tests are not reported as their hardware acceptance.

See [the operator guide](SD_RECOVERY.md) for the exact card transfer and command.

## Current verification and local release

- Full Python 3.11 offline suite: **3,302 passed, 1 skipped, 10 deselected**.
- Recovery/flash-safety/DFU tests: **476 passed** on Python 3.12 and 3.13 and
  against the installed wheel on Python 3.11.
- Ruff passed; strict mypy passed for 101 source files.
- All 113 installed package files matched the wheel; workspace package files
  matched too. The wheel contains both profile contracts and the helper source,
  linker script and pinned binary.
- Installed CLI help, profile inventory and real `plan_ready` status passed.
  The installed guide reopened the real plan, acquired the bound UART and cleanly
  cancelled at the first boot prompt, before RAM boot or any flash writes.

Gauss release: `issue-114-live-9f618714c5cf` under
`~/.local/share/pluto-plus-utils/releases/`.
Wheel SHA-256:
`9f618714c5cf904865cc6521e48ce777dfcf7b77a6011a8409a12cc3686bedd5`.
The user-local `pluto` and `plutod` launchers select its installed runtime.
The release retains package digests, test logs, smoke results and prior launcher
targets in its deployment receipt. Existing daemon processes were not restarted.
The repository virtual environment also imports the corrected editable source.

## Earlier framework and guided releases (historical)

### Framework deployment

Implemented and deployed locally on 2026-09-13. This delivers diagnostic tools
and a tested SD recovery engine. **Live radio recovery is not yet enabled or
hardware-verified:** no production profile or board-specific identity/boot recipe
has completed the required qualification. Issue #114 must remain open until that
hardware acceptance and the motivating unit's actual repair are recorded.

The operator guide is [SD_RECOVERY.md](SD_RECOVERY.md); the architecture and
acceptance requirements are in [the implementation plan](ISSUE_114_SD_RECOVERY_PLAN.md).

## Guided command follow-up

The stages are connected in `pluto firmware recover guide --session DIR` and
installed on Gauss in release `issue-114-guide-26727df73e80`. The wheel SHA-256 is
`26727df73e8091bf89618a981e17c837778d4fa399cebee59beece50f70bd34c`.
The recovery/flash-safety/DFU suites passed **454 tests on each of Python 3.11,
3.12 and 3.13**, including 18 new guided-flow cases. All 454 also passed against
the installed wheel. Ruff passed and strict mypy checked 99 source files.
All 106 installed package files matched the wheel; workspace package files also
matched. Post-deployment help, empty-profile inventory and unsupported-recovery
refusal checks passed. Previous launcher targets remain recorded for rollback.

This follow-up performed no live UART operations or radio flash writes. The
successful `.14` diagnostic SD boot was observed earlier through the separate
UART helper. Production profiles and live recipes remain empty: the command
refuses live recovery before opening UART, and `.14`'s automatic repair is still
unfinished. Tests use explicitly injected synthetic hardware only.

## Delivered behavior

- `pluto firmware recover guide --session DIR` now connects these operations into
  one interactive, resumable invocation. It acquires UART before physical boot
  prompts, exports SD bundles, checks RAM acceptance, requires exact-plan flash
  confirmation and emits a receipt only after cold-boot acceptance. It preserves
  the empty production qualification registry and cannot yet repair `.14`.
- `pluto firmware recover` exposes discovery, private diagnostic sessions,
  unverified evidence import, status and sanitized export. Qualified workflow
  commands cover SD preparation/capture, planning, payload staging, RAM testing,
  execution, resume and persistent-return attestation.
- Strict contracts and a hash-linked, fsynced private journal preserve original
  backups and source artifacts. Imports cannot self-certify physical placement.
  Missing, changed, truncated or unsafe files block dependent operations.
- The planner validates the exact rollback FIT, selected configuration and
  component integrity/RAM bounds. Gzip requires an exact bounded expanded size.
  Boot provenance includes an actual historical receipt and an explicit repair
  interval; unexplained changes elsewhere in the boot partition are refused.
- Repair plans reconstruct the complete expected flash image and emit only
  differing full erase sectors. Unrelated bytes and partial-sector remainders are
  preserved. Environment serialization allows only planned `fit_size`/CRC changes
  in the supported single-copy format.
- Recovery and #113 ordinary deployment use the same physical interval validator.
  Production qualification registries remain empty. CLI flags cannot authorize
  an unknown board/writer or bypass normal boot protection.
- The SD U-Boot data adapter implements bounded SF/SD operations with separate
  staged-payload and readback RAM buffers. Qualified compiled recipes must supply
  actual board identity, executing-artifact observations and RAM/cold-boot behavior.
  PPU does not invent those recipes from a console banner.
- The serial parser handles fragmented replies, echoed commands, stale prompts,
  explicit errors and exact SF offsets/counts. Uncertain completion poisons the
  connection and stops subsequent commands. There is no automatic flash retry
  or reboot.
- Execution records intent before each erase/program, rechecks target/writer and
  erased bytes before programming, verifies complete sectors and compares the
  final full physical image. Resume reads current hardware and creates a linked
  successor plan from the immutable original; it never trusts a saved step count.
- `recovered` requires QSPI power-on/source evidence, separately recorded operator
  actions, identity/image continuity, expected network/IIO services, settings and
  RF inactivity. SD/RAM success or an old IP returning cannot satisfy that gate.
  Returned Linux firmware retains its conservative update restrictions.

The new code lives in `src/pluto_plus/recovery/`, with the shared interval helper
in `flash_ranges.py`. Existing #113 changes were integrated, not replaced. No
website, API recovery endpoint, JTAG automation or production qualification was
claimed as delivered.

## Verification

| Check | Result |
|---|---|
| Full Python 3.11 offline suite | 3,262 passed, 1 skipped, 10 deselected |
| Python 3.12 recovery/flash-safety suites | 436 passed |
| Python 3.13 recovery/flash-safety suites | 436 passed |
| Ruff, all source/tests | Passed |
| Strict mypy | Passed, 98 source files |
| Wheel and source distribution | Built; package bytes compared with workspace source |
| Clean wheel installation with base dependencies | Diagnostic CLI, redaction and unqualified-profile refusal passed |
| Tests importing the installed release package | 436 passed |
| Deployed fake-radio daemon | Health, index, JavaScript and CSS returned HTTP 200 |
| Deployed CLI-to-daemon check | Listed only the explicitly configured synthetic radio |

Tests reproduce the incident's exact wrap and previous FIT size using synthetic
bytes, verify full-image preservation for different boot erase sizes, compare
recovery and deployment boundary behavior, inject failure before/during/after each
FIT/environment/boot mutation, and exercise loss of durable completion evidence.
They include all split positions in representative SF replies, a real host PTY,
SD file verification on a separate interpreter, wrong target/writer/provenance,
hidden RAM writes, environment CRC semantics and false cold-boot acceptance.
The CLI-to-workflow integration test injects a test-only registry; production
commands still see no enabled profiles.

The skipped offline test requires an unavailable transmitter implementation. The
10 deselected tests are hardware/browser lanes. One existing Starlette/httpx
deprecation warning remains. No actual radio UART was opened, no flash was
written, no SD media was prepared and no real cold boot was attested in this task.

## Local deployment and retained evidence

The user-local commands now select the installed wheel rather than the editable
checkout:

```text
/home/mouse9911/.local/bin/pluto
/home/mouse9911/.local/bin/plutod
```

Release directory:

```text
/home/mouse9911/.local/share/pluto-plus-utils/releases/issue-114-12827d126436
```

Wheel SHA-256:

```text
12827d12643613f3d237e220c783cf7ea695e7b40e16841e9eae8197350358a1
```

The release retains the wheel/source distribution, source digests, test logs,
clean-install and deployed smoke results, and `deployment.json`. Its `runtime/`
contains the installed package. Launchers preserve the existing host dependency
environment at `/home/mouse9911/gits/pluto-plus-utils/.venv/bin/python`; keep that
environment available. `clean/` records an independent base-dependency install.

Previous launcher symlinks are preserved under `previous-launchers/`, and the
previous #113 release files remain unchanged. Restoring those saved links rolls
back command selection. The smoke daemon was stopped after verification; existing
radio services were not restarted. No GitHub publication or hardware deployment
was performed.

## Remaining live acceptance

To finish the hardware portion, provide the explicit recovery host/radio binding
and private bootstrap/backup/provenance locations. Firmware owners must supply
qualified board wiring, console-only bootstrap artifacts, physical reader/writer
evidence and compiled identity/RAM/cold-boot recipes matching the profile contract.
Then run controlled recovery/interruption tests on designated recoverable boards,
independent physical verification and repeated actual QSPI cold boots. Record the
motivating unit's result separately. Missing evidence is not replaced by a generic
model match, caller-supplied capability or simulated success.
