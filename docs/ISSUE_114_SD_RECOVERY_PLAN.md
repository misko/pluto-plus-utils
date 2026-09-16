PPU #114 — guided SD recovery implementation and test plan
=========================================================

Status: proposed, reviewed 2026-09-13 against PPU `4bc2ca6` and the evolving
working tree. This document adds a plan only. Existing #113 implementation and
documentation edits are separate work.

Implementation follow-up: see [the implementation/deployment report](ISSUE_114_IMPLEMENTATION_REPORT.md)
for delivered software, test results and pending live hardware qualification.

Implement recovery as a durable session around a pure repair planner and one
qualified SD U-Boot adapter. The planner produces the complete expected flash
contents; the executor applies only justified sector changes; an independent
return gate decides whether persistent recovery was proved. Share physical flash
policy with ordinary deployment, while giving recovery its own explicit operation
contract for narrowly justified boot restoration.

The requested outcome and incident evidence are in
[PPU #114](https://github.com/misko/pluto-plus-utils/issues/114).
[PPU #113](https://github.com/misko/pluto-plus-utils/issues/113) owns shared
prevention policy; [firmware #99](https://github.com/misko/plutosdr-fw/issues/99)
owns the writer/addressing fix and hardware qualification. At review time all
three issues were open with no comments. The incident repair remains prepared,
without a reported successful persistent restoration or cold boot; its fresh
flash UID is still pending. This plan does not change those acceptance statuses.

**1. Findings that shape the implementation**

| Inspected surface | Consequence for #114 |
|---|---|
| `flash_safety.py`, in-progress #113 work | `validate_flash` currently describes a Linux updater, serial/boot/kernel evidence, four MTD partitions, and one environment format. Extract common interval/qualification validation beneath this existing entry point; do not fabricate Linux observations for SD U-Boot or weaken ordinary boot protection. |
| `flash_safety_io.py`, in-progress #113 work | Its `FlashSession` supplies useful private-backup, final-observation and uncertain-dispatch patterns, but observes Linux and captures protected regions plus rollback FIT. Recovery needs a qualified full-chip reader and UART/SD transport. Agree on a shared backup/provenance contract so prevention evidence can seed recovery. |
| `firmware.py`: `_validate_fit`, `validate_dfu`, `validate_frm` | Existing validation checks container/header size, magic and wrapper checksums. It does not establish selected FIT configuration, component hashes or SoC compatibility. Recovery must add that validation; passing existing tiny FIT fixtures is insufficient. |
| `volatile_firmware.py`: `prepare_ram_boot_plan` | Requires an already running USB/IIO radio and a stable serial. Reuse artifact and return-check concepts, but add a qualified SD-to-RAM transition for a radio whose normal boot is dead. |
| `release_candidate.py`: canonical/private contracts | Reuse absent-only publication, strict parsing, file identity and fsync patterns. Extract a small shared storage utility if needed; keep existing contract bytes compatible. Do not import recovery into release-candidate lifecycle logic. |
| `ip_firmware.py`: `IpFirmwareExecutor` | Reuse the distinction between dispatch intent, confirmed completion and uncertain outcome. A process exit or prompt cannot replace command-specific evidence. |
| `radio_lock.py` | The existing lock is keyed by runtime serial. Add explicit physical-adapter/session locking and acquire the existing serial lock whenever that identity is established, including during RAM and return-service checks. |
| `cli.py`, `docs/FLASHING_AND_DOCTOR.md` | Add a separate `pluto firmware recover` group. Existing `pluto radio recover --data-plane` remains an IIOD recovery operation. Keep the new implementation outside the large CLI module. |

The adjacent firmware checkout's U-Boot `1ff0468e9b` was also inspected at
`u-boot-xlnx/include/configs/zynq-common.h` and `u-boot-xlnx/cmd/sf.c`.
Its SD preboot imports `uEnv.txt`; some normal ADI boot helpers call `saveenv`;
`sf update` can erase/program a complete sector for a partial payload. These are
source-review findings, not identification or qualification of a running radio.
They require a console-only bootstrap, a boot recipe without hidden persistence,
and explicit sector footprints instead of assuming command names imply safety.

**2. Scope, ownership and release dependencies**

Start with a Linux-host CLI and one explicitly qualified board/SoC/DDR/flash
combination. SD copying and backup transfer also work through a second computer
using a self-contained verification utility and documented filesystem operations.
Add further live-host platforms or board revisions only with acceptance evidence.
JTAG initially provides a documented handoff and evidence export.

PPU owns sessions, host evidence, artifact verification, planning, command
orchestration and return attestation. Firmware owns actual bootstrap binaries,
safe boot recipes, board wiring profiles, writer/reader qualification and rollback
artifact manifests. The operator supplies physical wiring, SD and power actions.
No dependency on normal SSH/IIO availability is allowed before SD bootstrap.

The first release must not wait for the Linux addressing fix: diagnostic tooling
and offline planning can ship independently. Persistent execution requires the
shared #113 final gate and a reviewed SD reader/writer qualification. Neither an
issue checkbox nor a local version string grants qualification.

Use two related, versioned contracts:

- `RecoveryProfile`: board revision, SoC/DDR constraints, UART electrical/wiring
  instructions, boot selection, SD filesystem/file set, bootstrap and safe-boot
  recipe digests, permitted RAM areas, environment/layout formats, expected
  services and supported identity evidence. Unknown wiring yields a diagnostic
  explanation, never an inferred voltage or jumper position.
- Shared `FlashQualification`: exact hardware/geometry and executing artifact
  identities, command implementation/recipe identity, permitted read ranges,
  erase/program ranges and boot-path evidence. Keep full-chip read qualification
  separate from write permission: a 32 MiB backup does not authorize a 32 MiB
  persistent update. Separate SD writer identity from the QSPI boot image being
  repaired; its corrupted digest cannot identify the executing writer.

Initially trust a shipped registry that pins reviewed manifest digests. Check
manifest and asset bytes before use, including offline imports; record source
revision and qualification evidence digests. Do not trust a manifest merely
because it accompanies an image. Registry changes/revocation invalidate plans.
Synthetic qualifications exist only through injected test registries. Ship no
production execution grant until bench evidence supports the exact combination.

**3. Small implementation boundaries**

Add `src/pluto_plus/recovery/` with these responsibilities:

| Module | Responsibility |
|---|---|
| `contracts.py` | Strict versioned session, observation, plan, command-result and receipt models. Distinguish observed, operator-reported, unsupported and missing evidence. |
| `profiles.py` | Trusted recovery profiles, manifest verification and compatibility selection; consume the shared qualification registry. |
| `store.py` | Private immutable artifacts, ordered durable events, session reconstruction and allowlisted public receipts. |
| `sd.py` | Diagnostic bundle creation, mounted-media verification, transfer manifests and exported-backup ingestion. |
| `uboot.py` | Bound serial connection, qualified commands, incremental parsing and typed reader/writer interface. No generic shell execution API. |
| `planner.py` | Pure reconstruction, provenance checks, environment changes and sector-preserving operation generation. |
| `workflow.py` | Evidence-gated transitions, final policy check, execution, resume and cold-boot attestation. |
| `cli.py` | Thin Typer commands and a guided presentation of the next permitted action. |

Promote shared FIT inspection and environment codecs into focused common modules
as their second caller arrives. Extract common flash-range logic in #113 rather
than duplicate it in `recovery/`. Keep the first delivery CLI-only; later API/UI
integration must use the same executor and existing privileged boundary.

Define a narrow injectable backend: observe target/bootstrap, read a physical
interval, load and verify an SD payload in RAM, erase/program an approved sector,
attempt the qualified RAM boot, and collect return evidence. The production
adapter never accepts user-provided U-Boot commands or an `allowed=true` claim.
Use a serial library behind this interface, loaded only for live recovery; unit
tests and offline planning must not require serial hardware or libiio.

**4. Session and operator experience**

Proposed commands, not commands available today:

```text
pluto firmware recover start          # explicit adapter and board profile
pluto firmware recover prepare-sd     # verified diagnostic bundle
pluto firmware recover capture        # observe, export, ingest and verify backup
pluto firmware recover plan           # exact artifacts and preservation report
pluto firmware recover ram-test       # exact FIT/configuration, no persistence
pluto firmware recover execute        # exact current plan and existing-style confirmation
pluto firmware recover resume        # re-identify and inspect; produce a new decision
pluto firmware recover attest        # guided QSPI cold-boot and service evidence
pluto firmware recover status         # evidence, blockers and next action
pluto firmware recover export         # sanitized receipt
```

All subsequent commands take a session path/ID. `status` explains what is known,
what is missing, and the next concrete action. The CLI can guide the sequence
without requiring operators to invent flash commands. Preserve JSON output for
automation. An execution confirmation binds the target and exact plan digest;
it cannot override a blocked check. Resume inspection never authorizes new writes.

Bind the serial endpoint to adapter identity and physical topology, not a tty
enumeration number. Adapter identity identifies the cable, not the radio: before
mutation also require observed unique target evidence under the profile's rules.
Prefer flash UID or another qualified SoC identifier. For the initial executor,
missing unique evidence blocks writes unless a separately reviewed profile
defines an equally discriminating target-binding method. An IP, generic MAC,
model, operator label or another radio's environment is insufficient. Diagnostic
capture remains available with uncertainty represented explicitly.

Hold exclusive serial/session ownership during commands. When a runtime serial
becomes available, hold its existing radio lock too, in a documented stable lock
order. Reopening a different port requires fresh binding; no fallback to the first
matching device. Keep the distinction between physical and runtime identities in
receipts instead of inventing a serial for a dead device.

Represent progress as evidence milestones plus current activity and outcome:

```text
discovered → bootstrap_ready → backup_verified → plan_ready
           → ram_boot_verified → flash_verified → awaiting_cold_boot → recovered
```

`ram_boot_verified` includes returning to the qualified SD console, reacquiring
identity and proving the pre-repair flash is unchanged. `plan_ready` is reviewable;
execution also needs RAM acceptance and a fresh execution binding. A RAM boot
necessarily changes the running boot epoch, so rebind explicitly to the new SD
epoch after checking invariant target, artifact, geometry and flash evidence.

Record `interrupted` whenever dispatch may have occurred without adequate result
evidence. Record a definite failure separately from whether flash contents are
known. A previous verified milestone remains history, not current authorization.
`recovered` requires all return checks; neither a changed boot ID nor network
reachability alone is sufficient.

**5. Diagnostic SD and immutable evidence**

Generate a deterministic bundle containing only profile-approved files and a
digest manifest. The boot path must stop at the console even with stale or corrupt
QSPI environment, absent `uEnv.txt`, or unexpected SD files. That property requires
firmware-owned bootstrap qualification; a host-generated override file alone
cannot guarantee it. The diagnostic bundle must not trigger updates or persist
environment settings when inserted.

Initially copy to an explicitly selected, already prepared mounted filesystem;
do not implement raw-disk formatting. Verify mount/media identity, free space and
the complete boot-relevant file set, refusing conflicting pre-existing startup or
update files. Copy atomically where supported, flush, reopen and hash every file.
Provide the same validation as a small portable offline utility for the second
computer, followed by safe-eject instructions. Its transfer receipt is evidence
of file verification, not proof of the radio's running bootstrap. Missing files,
read-only media, insufficient space or interrupted transfer leave preparation
incomplete. Bind later repair-file transfers to the session and plan digest.

Capture boot transcript, observed identity/JEDEC/SFDP/UID availability, geometry,
layout, protection state, writer build evidence, raw environment and provenance.
Read the full chip through the qualified physical reader using bounded RAM areas.
Perform the qualification's boundary/high-to-low read checks without writing test
patterns onto the damaged target. Compare overlapping/chunked reads and flag
inconsistency or suspicious bank duplication. Equal bank hashes can be legitimate;
such heuristics cannot establish or replace addressing qualification. If the read
path cannot be qualified, retain the bytes as unverified evidence and block repair.

Verify device export size/digest, reload the SD file and compare it with the
captured RAM bytes, then ingest on the host and reopen/hash the complete file.
Use CRC/comparison evidence where that exact U-Boot lacks SHA-256, alongside host
SHA-256; do not invent a target-side SHA result. Allocate nonoverlapping verified
RAM buffers or perform a qualified chunked comparison for limited-memory boards.

Store evidence outside the repository in a private `0700` session directory;
private documents and blobs use restrictive permissions. Publish the original
dump absent-only, fsync file and directory, and record its length/digest in an
immutable event before enabling repair. Never replace it with a resumed capture.
Content hashes and strict reopening detect later modification; read-only file
permissions alone are not a claim of tamper-proof storage.

Keep commands, environment values and raw UART output private. Public export is
an allowlist of result codes, artifact/qualification identities, interval digests
and attestation summaries; it omits raw dumps, environment values, credentials,
local paths and unreviewed log text. Record key-change names privately and disclose
only approved non-secret changes publicly. Device identity can use a session
pseudonym. Do not attach private evidence automatically to issues or telemetry.

**6. Repair planning and the shared mutation boundary**

The planner consumes verified original bytes, current observation, approved
artifacts and target-specific provenance. It has no transport I/O. Its output is
a canonical immutable document plus content-addressed sector payloads.

For each proposed restoration, require an independent reason to trust those
bytes. Boot reconstruction must match the target's historical boot-partition
digest, not merely a similar board's image. Validate rollback FIT manifest/hash,
selected configuration and all referenced kernel/FPGA/DTB/ramdisk payload hashes,
target compatibility, load/entry addresses and RAM footprint. Reject unsupported
FIT features instead of partially validating them. A hash establishes content
identity; a trusted manifest/profile supplies compatibility and provenance.

Build the expected full image from the original backup and explicit byte patches:

```text
expected = original backup
apply only provenance-approved boot, FIT and environment patches
enumerate erase sectors intersecting actual differences
sector payload = expected bytes for that entire sector
skip sectors already equal to expected
```

Every operation includes payload interval, full erase/program footprint, current
and expected digests, preserved-byte digests, provenance, writer qualification
and dependencies. Use end-exclusive byte intervals and actual sector geometry;
reject conflicting overlapping patches and unsupported sector layouts. If an
erase crosses a partition/protection boundary, require an explicitly qualified
cross-boundary preservation contract or refuse it. Do not infer geometry from
the incident's proposed 64 KiB boot payload.

For the incident-shaped fixture, the intended patches are the first `0x10000`
boot bytes, the captured environment with only `fit_size`/CRC changed, and the
prior FIT at `0x200000` with length `0xC56117`. The FIT ends at `0xE56117`.
Preserve its trailing sector bytes and every byte after it, including remnants of
the failed larger image. Clearing those remnants is an additional unjustified
write. Restore only sectors with differences; reconstruct and verify the entire
1 MiB historical boot partition even if only its first sector needs programming.
These values belong to regression fixtures, not production profile defaults.

Generate environment bytes from the captured raw target environment, preserving
serialization/padding where possible. Allow only explicitly planned changes;
validate CRC coverage, endian convention, size, duplicate keys and padding.
Initially enable the qualified single-copy format. Reject redundant environments
until their selection/flags/sequence/CRC behavior and interrupted-copy update
rules have their own codec and writer qualification. Preserve calibration,
identity and all unplanned settings. Never serialize the live diagnostic SD
environment or call unrestricted `saveenv` to produce the repair.

Generalize #113's pure interval validator to accept typed operation contracts:
ordinary firmware deployment still cannot alter boot regions; recovery may alter
only exact provenance-approved boot intervals, with sector restoration and a
verified external bootstrap. This is not a `recovery=true` exemption. Validate
all erase, program and any protection-register effects. Unsupported flash lock
state refuses execution rather than issuing an automatic global unlock.

Bind plan digest to target evidence, original and current flash digests, geometry,
environment codec, all artifact/sector payload digests, profile, read/write/boot
qualification contents, policy revision and RAM acceptance. After staging, the
executor independently reloads authoritative bytes, re-observes the target and
writer, reads current flash, and runs the shared policy immediately before the
first erase. Maintain exclusion and check expected intermediate state at later
mutation boundaries; planned changes do not count as unexplained drift.

**7. RAM test, execution and interruption recovery**

Load the exact rollback FIT and configuration through the qualified SD RAM recipe.
The recipe must bound RAM use, avoid persistent boot helpers and disable startup
updates/environment writes in the tested runtime. Establish RF inactivity before
booting the candidate and verify it alongside the expected network/IIO services.
Returning through SD and reading the complete flash proves that this trial did
not persist settings. RAM failure blocks persistent execution in the initial
release, with diagnostics and JTAG handoff available; no skip-test override.

For the initial incident repair, use this qualified ordering:

1. Stage and verify the complete sector payloads and durable execution intent.
2. Restore changed FIT sectors and verify them.
3. Restore the planned environment sector(s); verify bytes and semantics.
4. Restore the justified early-boot sector(s) last, once their dependencies pass.
5. Read the complete chip through the qualified path and compare with the full
   expected image; separately validate historical boot integrity and environment.
6. Record `flash_verified`, then request the physical QSPI cold-boot procedure.

Keep external SD bootstrap available throughout. Ordering reduces the chance of
making early boot usable before its dependencies are ready, but supplies no
multi-region atomicity. The profile must qualify the ordering; a different layout
or redundant environment may require a different dependency graph.

Prefer explicit full-sector erase/program/read operations for the first adapter
so each destructive boundary is visible and journaled. If a qualified writer uses
`sf update`, model its internal erase/program and preservation behavior explicitly.
Stage and hash a sector's complete intended bytes before erasing it. Use only
reviewed command templates with bounded numeric arguments and controlled names.

The serial parser must process fragmented bytes, command echo, CR progress lines,
stale prompts, asynchronous text and disconnects. Use a per-command correlation
marker supported by the qualified interpreter, require the command-specific
offset/count/result, and treat explicit failure as overriding an apparent success.
An echo of the marker is not a completion event. `sf update` written-plus-skipped
counts differ from `sf write`; each supported grammar needs fixtures. An unknown
output form is unverified. Never pipeline a later destructive command or reboot.

Durably publish intent before each erase/program dispatch and the evidence after
completion. A missing completion event, including loss of host storage after a
successful device write, means `interrupted`; stop sending mutations. Session
reconstruction tolerates an incomplete final event but rejects contradictory or
corrupt prior events. A truncated public/private receipt cannot authorize work.

On resume, reacquire binding and qualifications and capture current physical flash.
Compare against the original and expected images: completed sectors are proved
by bytes, remaining original sectors are eligible for replanning, and partially
programmed/erased sectors require rebuilding their complete expected payload from
the immutable original. Unexpected changes outside dispatched erase footprints
block the old plan. Do not incorporate them silently into a new baseline. Persist
a successor plan linked to the old attempt, rerun policy, and require deliberate
execution of that concrete plan; never continue from a saved step counter.

**8. Persistent-return attestation**

Guide full power-off, removing SD boot selection and restoring the profile's QSPI
boot mode. Record operator actions separately from machine observations. Collect
a continuous bound UART boot transcript and the profile's observable boot-source
and reset-cause evidence; a software reset or new Linux boot ID does not prove
cold power-on. Where machine evidence cannot establish the required distinction,
report the missing proof instead of promoting operator confirmation into a sensed
measurement. The firmware profile must define the acceptable evidence mechanism.

Require identity continuity, intended persistent boot/image evidence, expected
runtime layout, network and IIO service checks, preserved target settings and
RF inactivity. Correlate network observations with the physically bound target;
do not accept another radio that appears at the old address. A RAM/SD runtime,
wrong image, missing service or incomplete power/boot-source evidence cannot yield
`recovered`. Check any boot-time environment effects against the qualified allowed
changes; an unexpected rewrite invalidates acceptance.

The final private receipt links all observations, artifacts, before/after full
flash and sector digests, exact changes, command results, qualification IDs and
contents, operator actions and return evidence. Publish only the sanitized view
on request. Preserve the conservative #113 update restrictions after rollback:
SD writer qualification does not qualify the older Linux writer now running.

**9. Automated tests with independent oracles**

Build one reusable synthetic NOR model in `tests/support/` and parameterize it for
both #113 and recovery. Model physical bytes independently of logical addressing,
erase sectors, page programming/1-to-0 behavior, bank state and injected faults.
Keep an out-of-band physical reader solely as the test oracle. Pair it with a
scripted serial/SD backend and bounded real pseudo-terminal integration tests.
Use generated structured FITs with real configuration/component relationships,
valid synthetic environments and offset-dependent flash patterns. No real dumps.

| Test group | Decisive assertions |
|---|---|
| Incident reconstruction | Reproduce a `0xE0FD6F` candidate at `0x200000` wrapping `0xFD6F` bytes to zero. Recover the exact synthetic prior boot/FIT/environment, compare the entire expected chip and assert the unrelated-byte diff is empty. Exercise 64 KiB and larger erase sectors independently of patch length. |
| Shared policy | Parameterize ordinary deployment and recovery over below/at/above 16 MiB, nonstandard offsets, partition ends, erase rounding, variable/unknown geometry, malformed numbers and overlap. The same range violation blocks both; ordinary deployment cannot invoke recovery's boot-restoration authority. |
| Provenance and artifacts | Missing historical digest, donor environment/calibration, wrong target/SoC/DDR/FIT configuration, corrupt component/manifest, revoked qualification, changed running writer and unsafe RAM addresses all block before erase/program. An oversized image containing a kernel fix never qualifies the old writer. |
| Aliasing | A writer and logical reader deliberately agree on an incorrect upper-bank hash. Independent physical bytes show corruption, and missing/mismatched physical qualification blocks backup/final acceptance. Also test bank transitions and failure to restore bank state. |
| Environment | Valid CRC and exact `fit_size` change pass; diagnostic `bootcmd`/console/SD overrides, invalid CRC, duplicate keys, unexpected padding or unsupported redundancy fail. Add redundant-copy power-loss cases before enabling that format. |
| SD and evidence | Missing/conflicting files, wrong media binding, failed copy/reload, truncated/changed backup, wrong full-chip length, corrupt export, ENOSPC, fsync failure and symlink/replacement attempts never enable repair. Test second-computer verification and private/public separation. |
| Serial parser | Every split point in representative responses, command/marker echo, stale prompt, malformed/short counts, explicit `sf` errors, timeout, disconnect and progress text. Assert no next destructive command or reboot after uncertain completion. |
| Interruption and resume | Cut execution before dispatch, inside erase/program, after device completion but before receipt fsync, and around every verify/environment phase. Resume reads hardware, preserves the original backup, regenerates partial sectors and refuses swapped hardware or unexplained off-plan changes. |
| Target isolation | Two attached radios, reordered tty enumeration, a moved cable, missing/duplicate UID and an existing runtime lock. Assert all unrelated-device command logs stay empty, including service/RF checks after RAM boot. |
| Final outcome | RAM pass/QSPI fail, SD-only boot, warm reset presented as cold boot, wrong returned identity/image, missing services, settings drift or RF-safety failure never produce `recovered`. Positive acceptance requires the complete evidence conjunction. |
| Durability and contracts | Restart in a fresh process from each event boundary; reject edited plans, changed sector files, duplicate JSON keys and stale schema execution. Public receipt serialization excludes synthetic secret canaries in all failure paths and logs. |

Avoid a simulator that simply returns success for whatever command was sent:
faults must change the independently held physical state and output separately.
Assert exact command absence on refusals as well as error messages. Test the real
CLI-to-workflow path with the fake backend so safe unit functions cannot hide an
unguarded dispatch route.

Run focused tests during implementation, then the existing CI gates on Python
3.11–3.13: pytest, Ruff, strict mypy and build. Hardware tests must be explicitly
opted into with a dedicated target enrollment; a marker alone is insufficient
because normal CI runs `pytest -q`. Collection/default execution must never open
a serial port, contact a radio or format media. Extend existing firmware, helper,
CLI and lock regressions when extracting shared code.

**10. Reviewable delivery sequence and hardware acceptance**

| Change | Scope and exit gate |
|---|---|
| 1. Shared contracts and policy seam | Coordinate with #113 on typed writer/range contracts, provenance storage and qualification matching. Ordinary deployment retains all restrictions; test recovery-specific boot authority cannot escape its exact intervals. |
| 2. Diagnostic sessions and SD bundle | Add profiles, durable store, bound console observation, SD preparation and full-chip backup ingestion. Deliver useful diagnosis and `backup_verified` without enabling mutation. Pending reader qualification produces an explicit unverified capture. |
| 3. Pure repair planner | Add FIT/configuration validation, the initial environment codec and sector reconstruction. Incident, provenance, boundary and preservation tests pass; plans are deterministic and reviewable offline. |
| 4. RAM acceptance and narrow executor | Add qualified SD RAM recipe, final shared policy gate, command parsing and per-sector journal. Ship live execution only for reviewed qualification records; all simulated mutation/error cases pass. |
| 5. Resume and persistent return | Add fresh-observation reconciliation, complete integrity comparison, cold-boot evidence, services and sanitized receipts. End-to-end simulator covers success and every interruption/failure gate. |
| 6. Hardware qualification and operator documentation | Run the acceptance matrix, publish exact supported combinations/limitations, and update flashing guide, hardware/release checklists and an ADR explaining recovery's narrow boot-write authority. |

Changes 1–2 deliver the issue's diagnostic stage; 3–5 deliver planned, resumable
repair; 6 supplies the hardware evidence required for full completion. Keep the
production allowlist empty for combinations not yet qualified; simulator success
does not qualify a board. Land diagnostic/offline work while firmware prepares
the missing artifacts and evidence.

On designated recoverable boards with independent recovery access, firmware and
PPU acceptance must jointly cover:

- The incident's Z7010/512 MiB/Winbond combination and representative additional
  supported revisions/flash families, each with exact identities and artifact
  digests. Do not inherit support merely from a shared product name.
- Controlled early-boot corruption after an independently verified backup;
  complete recovery with protected-byte/physical-placement verification using a
  separately qualified reader. Exercise bank boundaries without risking deployed
  radios or using the damaged original as a destructive test fixture.
- Power interruption during FIT, environment and boot programming, including
  after erase and during a program operation, followed by SD recovery and exact
  preservation checks. Record cut points and current bytes, not just final success.
- Local and second-computer SD preparation/export, missing and corrupt media
  files, and clear media-selection instructions. The first version never formats
  a disk, so an unrelated disk must remain untouched by construction.
- At least three consecutive actual QSPI cold boots per accepted combination
  as an initial acceptance threshold, with identity/image/service/settings and
  RF-inactive evidence each time. Firmware owners may require a larger campaign;
  three boots are an acceptance check, not a reliability estimate.

Record the motivating unit's actual repair and cold-boot result as a separate
receipt. Completion requires a supported operator path through all gates, not
only prepared files, an SD console banner, RAM success or a matching logical hash.

The remaining external prerequisites are concrete: a trusted diagnostic bootstrap
and board wiring profile, full-chip read and narrow-write qualification, exact
rollback/boot provenance, and a qualified cold-boot evidence recipe. Missing items
block only the dependent live stages; do not substitute guessed identities,
geometry, electrical instructions or capability flags.

**11. Validation performed for this plan**

Reviewed the three issue bodies, the listed PPU integration points, the local
#113 plan/implementation under development, current CI configuration, and the
referenced U-Boot boot/flash-command source. Ran this offline reuse baseline:

```sh
.venv/bin/python -m pytest -q -m 'not hardware and not firmware and not browser' \
  tests/test_firmware.py tests/test_volatile_firmware.py \
  tests/test_radio_lock.py tests/test_release_candidate_rx_only.py
```

Result: **94 passed**. This verifies the inspected reuse surfaces' current tests,
not the proposed recovery workflow. No radio access, persistent writes, SD-media
operations or hardware qualification were performed for this planning task.
