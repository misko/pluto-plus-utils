# Flash safety and recovery review, 2026-09-14

Reviewed PPU main through `0ae626c`, including the physical flash boundary in
`d201971`, its integration with the v0.50 profile updates, and the new incident
SD recovery backend. The workspace was clean and matched remote main at review
start.

## Finding and correction

The incident backend's cold-return check populated `ReturnEvidence.fit_sha256`
from the rollback profile without reading the persisted FIT after cold boot.
The earlier complete SD readback and the runtime's protected-region checks do
not detect a firmware-partition change between those stages. Matching kernel
version and selected userspace hashes also do not establish the complete FIT
digest. This could incorrectly record recovery despite a changed persisted FIT.

Cold acceptance now checks the live firmware partition's name, offset and size,
then hashes exactly the rollback FIT's byte length through raw MTD. Missing or
different geometry, changed bytes, truncated reads and malformed hash output
prevent the recovered receipt. The read is bounded by the conservative physical
16 MiB limit even though the incident chip has 32 MiB. RAM acceptance retains its
separate verified staging path.

Regression coverage exercises the actual cold-runtime adapter through
`Workflow.attest`: successful acceptance, a changed final FIT byte, short readback
and changed geometry. A separate test rejects an upper-bank range before console
I/O. These are synthetic tests, not hardware qualification.

## Current recovery and firmware status

The private `.14` session journal is newer than the original #114 commit report:
it reports `awaiting_cold_boot`, after RAM acceptance, sector repair and complete
flash verification. A recovery guide process was already running at review time;
this review did not acquire its UART, issue radio commands or change its state.
That process must be restarted from the retained session to load this corrected
acceptance code. A new CLI installation does not update an existing process.

Firmware #99 has a separate conservative kernel/updater recovery candidate and
source-graph regression work. Its implementation report still leaves hardware
qualification pending. Neither that candidate nor the incident recovery profile
authorizes extended Linux flash ranges. The next hardware milestone is the
incident radio's observed QSPI cold boot, followed by the companion's explicit
writer/bootloader qualification work.

## Verification and local deployment

- Full Python 3.11 suite: **3,941 passed, 11 skipped**; one existing dependency
  deprecation warning.
- Installed-wheel recovery, flash-safety and DFU suites: **488 passed**.
- Ruff, strict mypy (108 source files), whitespace checks and wheel/source build
  passed.
- Installed CLI entry points, saved-session status and every packaged file were
  verified. The local launchers now select release `cold-fit-c0b2aea8d1c9`.
  Its deployment receipt preserves prior launcher targets and verification logs.
  Existing processes were not restarted; no hardware acceptance was performed
  during this review.
