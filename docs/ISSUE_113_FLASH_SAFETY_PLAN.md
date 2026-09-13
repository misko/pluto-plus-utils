PPU #113 — physical flash safety implementation and test plan
============================================================

Status: proposed; reviewed 2026-09-13 against PPU `4bc2ca6` and the current
working tree. Existing uncommitted profile changes were left untouched.

The recommended design is one pure physical-write policy, enforced by every
persistent execution boundary, with a separate integrity gate before reboot.
Release-profile approval remains necessary where already required, but cannot
grant physical addressing permission. Deliver the conservative guard before
waiting for a repaired kernel or larger-image qualification.

The incident and acceptance requirements are documented in
[PPU #113](https://github.com/misko/pluto-plus-utils/issues/113). Kernel repair,
device-updater changes and destructive hardware qualification belong to
[firmware #99](https://github.com/misko/plutosdr-fw/issues/99). Neither issue had
comments at review time. Physical wraparound is the reported finding; the second
board's identical failure mechanism has not been independently established.

**1. What the code review established**

| Surface | Current behavior and implementation consequence |
|---|---|
| `bootstrap_firmware.py`: `prepare_lan_flash_plan`, `prepare_usb_flash_plan` | Validate image/profile and IIO identity/topology. Plans lack physical geometry and writer qualification. Planning needs an authenticated read-only flash observation, not another model-name check. |
| `execute_lan_flash_plan`, `execute_usb_flash_plan_ssh` | Invoke the fixed updater, hash the FIT through `/dev/mtdblock3`, then reboot. Add the shared final write gate and protected-region verification here. LAN source/return reports hash the full logical firmware partition; those hashes are not physical-addressing evidence. |
| `firmware.py`: `FirmwareManager`, `MassStorageQspiUpdater`, `SystemFirmwareExecutor` | Manager and executor validate images and identities, but do not establish physical write ranges. Guard both planning and the actual updater boundary, including direct executor callers. |
| `ip_firmware.py`: `IpFirmwareExecutor` | Already journals mutation dispatch and uncertain results, and checks the FIT through `/dev/mtd3`. Extend its attestation and evidence instead of creating a second receipt framework. |
| `firmware_helper.py`: `UnixFirmwareHelperServer._dispatch` | Already copies and verifies an image privately, then rechecks identity. Recompute physical safety from that private copy and independently observed target state at this trust boundary. |
| CLI/API/service and setup/recovery wrappers | Carry the same decision and failure details; no transport-specific override. Audit standalone entry points as well as daemon calls. |
| Volatile DFU and resume/lifecycle helpers | Audit actual RAM-mode evidence. The alternate name `firmware.dfu` alone is insufficient to establish RAM-only behavior. |

Supporting source was inspected in the adjacent firmware checkout
`/home/mouse9911/gits/plutosdr-fw-starlink-glrt-only`: firmware `6e49144af`,
Buildroot `35d87ae5b`, U-Boot `1ff0468e9b`. These are implementation references,
not attestations of the software currently running on any radio:

- `buildroot/board/pluto/update_frm.sh` strips the 33-byte FRM trailer, writes
  through `mtdblock3`, and sets `fit_size` in hexadecimal. `dd bs=64k` is an I/O
  block size, not evidence of erase geometry. The MTD block implementation can
  erase and rewrite complete cache/erase blocks.
- `buildroot/board/pluto/update.sh` handles eject-triggered updates and reboots
  internally. It can also process an existing release ZIP, `boot.frm`, and changed
  `config.txt`. Writing only `pluto.frm` does not constrain all effects of eject.
- `u-boot-xlnx/include/configs/zynq-common.h` defines `firmware.dfu` for both raw
  SPI-flash and RAM modes. PPU's DFU download vectors select that same name.

**2. Shared policy and evidence model**

Add `src/pluto_plus/flash_safety.py` with small immutable records and a pure
validator. Keep transport I/O in adapters. Reuse existing target identities,
image validation, plans, receipts and authorization machinery.

The policy inputs should describe:

- **Observed target:** existing serial/USB path/pinned SSH binding, boot ID,
  board/SoC and available actual flash identity (JEDEC/part/SFDP evidence).
  A serial prefix is never a flash-capability grant. Blank-serial recovery may
  proceed only if the supported physical binding independently removes ambiguity;
  otherwise it must stop.
- **Physical layout:** flash capacity; partition names, physical offsets and
  lengths; erase geometry; firmware destination; immutable protected regions;
  and the precise updater-managed environment area. Cross-check MTD observations
  with the active partition map. `/proc/mtd` sizes alone do not prove offsets;
  do not infer offsets by adding listed sizes without a verified layout contract.
- **Writer identity and behavior:** running kernel/build evidence, updater hash,
  relevant utilities/configuration and bootloader evidence. A reviewed writer
  contract describes destinations, program/erase footprint, environment effects
  and reboot behavior. Knowing the legacy footprint is distinct from qualifying
  it for extended addressing. Unknown writer behavior blocks persistence.
- **Authoritative image:** validated FIT bytes, FIT/FRM digests and sizes. Parse
  with existing `validate_frm`/`validate_dfu`; never trust only profile metadata,
  caller-provided sizes, or the candidate's claimed kernel version.
- **Policy:** policy revision and, eventually, a matching qualification record.
  Initially ship no extended-range grants.

Return a structured decision containing allowed/blocked status, stable reason
code, observed inputs, FIT interval, all erase/program intervals, expected
environment changes, effective address limit and qualification ID/digest.

Use byte counts and end-exclusive intervals. For an identified legacy-compatible
layout without extended-address qualification:

```text
address_limit = min(observed_flash_capacity, 0x01000000)
payload = [firmware_start, firmware_start + actual_FIT_length)
```

Check payload and the complete writer footprint against the intended partitions,
the allowed physical range and protected-region exclusions. For uniform geometry,
round touched addresses to erase-block boundaries using the verified erase origin;
for variable geometry, enumerate the touched sectors. Reject unsupported geometry
rather than approximate it. An updater that erases a whole partition must qualify
that entire footprint even if the FIT is small.

Treat the `fit_size` environment write as a separate, explicitly allowed operation
with its own partition and erase span. Firmware writes cannot overlap it. Include
all effects of the writer and its configuration, not just the `dd` destination.

Missing or contradictory layout/identity evidence blocks persistence. Missing
extended qualification never increases the conservative range. Keep existing
exact-image, source/return IIO-layout, RF-idle and authorization constraints.
The existing blank-serial `force-flash` operation must still obey this policy;
there is no general force escape.

**3. Bind planning to the final mutation**

Add the decision and an evidence fingerprint to the existing plans. Bind target,
boot ID, running writer/kernel/updater, bootloader evidence where required,
layout, actual image, policy and qualification content. Qualification IDs alone
are not enough if their records can change.

Inject a read-only observer into planners. The CLI currently constructs the USB
SSH transport only after planning; move that construction sufficiently early to
obtain authenticated observations. A credential-free image inspection may remain
available, but must not produce an executable flash plan without target evidence.
Extend manager/helper interfaces deliberately and reject old executable plans or
helper requests that lack required safety binding. Preserve historical receipt
readability without treating missing evidence as a successful check.

Re-attest after staging and image verification, immediately before dispatch. Use
the same pure policy again and reject changed bindings. At the helper boundary,
derive bytes from the private verified copy and facts from the privileged observer;
the caller cannot supply an authoritative `allowed=true` or capability flag.

Hold the existing per-radio operation exclusion across observation and execution;
provide equivalent exclusion for standalone operations. Use a fixed remote wrapper
to compare the expected state and staged-file identity immediately before invoking
the known updater, under the available target-side lock. Keep range arithmetic in
the shared policy; the wrapper checks the bound facts. Abort if the required
exclusion or final evidence cannot be established. This covers cooperating PPU
operations; it is not a guarantee against an unrelated root process changing flash.

**4. Route policy: safe support includes explicit refusal**

| Route | Required behavior |
|---|---|
| Standalone LAN and USB-bound SSH | Shared plan/final guard; known synchronous updater; protected checks before the existing reboot command. |
| Daemon/API over SSH | Same policy through `FirmwareManager` and `IpFirmwareExecutor`; propagate structured evidence and preserve admin/controller boundaries. |
| Privileged helper and direct USB executor | Independently enforce policy before calling the updater. An unguarded injected updater cannot be a production fallback. |
| Mass-storage/eject | Block the legacy auto-reboot route unless a reviewed device-side contract supplies pre-write enforcement and pre-reboot integrity evidence, or a proven mechanism pauses before reboot. Recommend explicit USB-bound SSH when available. Do not silently switch transports. |
| Persistent DFU | No new raw-flash feature in this change. Any existing or future persistent DFU dispatch requires U-Boot-specific writer and boot qualification; Linux qualification cannot authorize it. Unsupported paths refuse. |
| True RAM/SD bootstrap | No QSPI-size restriction on a proven RAM-only operation. Re-attest the new running writer before a separate persistent plan. A patched oversized incoming image does not repair the old writer performing its installation. |

For any future enabled mass-storage route, validate the complete eject-trigger
input set before placing an actionable image and again before eject: reject
pending boot images/archives and unplanned configuration changes. If a late check
fails, remove only the image staged by this attempt when safe, verify that cleanup,
and do not eject. Never delete pre-existing user files automatically. A host check
after the radio returns cannot satisfy the pre-reboot integrity requirement.

For DFU, establish the actual RAM/SF mode from a supported attested transition and
bootloader contract, including resume paths. VID/PID, alternate name and a previous
receipt alone are insufficient. If the available interface cannot distinguish
the modes reliably, refuse the ambiguous download. Classify all current DFU call
sites, including comparator and release-candidate lifecycle helpers.

**5. Recovery evidence and the reboot gate**

Before the first flash mutation, durably save target/layout/writer evidence,
boot and other immutable-region backups and digests, the original raw environment
and parsed values, and the provenance of a verified rollback artifact. Reuse an
existing backup only after matching its target, ranges, length and digest. Keep
raw data in private local evidence storage; public receipts and tests contain
references/digests or synthetic data. If required evidence cannot be saved, stop
before mutation.

After a synchronous updater returns, flush writes and perform fresh length-checked
reads of the FIT and protected regions before permitting reboot. Avoid relying on
cached block-device data. The read adapter must have a reviewed low-address/bank
selection contract; switching from `mtdblock` to character MTD alone does not prove
correct physical mapping. Remove unnecessary whole-partition reads above the
conservative range from legacy preflight/reconciliation, or refuse them unless
their read behavior is qualified.

Immutable regions must match exactly. For the environment, require valid CRC and
the exact planned semantic change: `fit_size` must equal the actual FIT length in
the writer's documented representation, and all other variables must be unchanged.
Validate permitted serialization/padding and redundant-copy state according to
the known environment format; do not simply ignore the environment partition or
allow arbitrary changes wherever a CRC happens to be stored.

The successful sequence is:

```text
observe → validate → preserve evidence → stage → re-attest and guard
→ update → flush → verify FIT and protected regions → reboot → attest return
```

Record distinct failures such as `flash_range_unqualified`,
`flash_observation_changed`, `protected_region_changed`, and
`protected_verification_unavailable`. Preserve existing receipt outcomes:

- A rejection proven to precede flash dispatch is `failed`, with no flash write.
- After dispatch, deployment remains `unknown` unless complete success is attested.
  Record a definite integrity-check failure separately from that deployment status.
- Unexpected protected changes or unavailable post-write verification prohibit
  automatic reboot, reflash, retry and destructive rollback. Preserve the running
  device and evidence for recovery; an integrity failure requires explicit recovery
  resolution and cannot be cleared by a later matching logical FIT hash.
- Retain return identity, image, services, IIO layout and RF-safety attestation.
  Failed return attestation stays `unknown`. Power-cycle evidence remains separate.

**6. Tests that demonstrate the safety boundary**

Add `tests/test_flash_safety.py` for policy cases and a reusable synthetic NOR
model for integration tests. Extend the existing firmware, helper, CLI/API and
transport suites. Use generated FIT/FRM bytes; never commit device dumps.

| Test group | Required assertions |
|---|---|
| Exact incident | Start `0x200000`, FIT `14,744,943`, exclusive end `0x100FD6F`: reject before updater, erase/program, environment mutation, eject or reboot. Previous FIT size `12,935,447` passes the range gate under otherwise valid evidence. |
| Boundary arithmetic | `14,680,063`, `14,680,064`, `14,680,065` FIT bytes; changed offsets; smaller capacity; partition overflow; payload fitting while erase span crosses; nonaligned/variable geometry; protected overlap. At the normal aligned layout, the first two fit and the third fails. |
| Parsing and bytes | Negative/zero lengths, booleans/floats where integers are required, oversized values, duplicate/missing/inconsistent observations, truncated reads, corrupt FIT/FRM. FRM's 33-byte trailer does not count as FIT. Claimed small metadata cannot disguise larger authoritative bytes. |
| Qualification | Unqualified Winbond and non-Winbond share the conservative limit. Serial/model inference and generic `hardware_qualified` profiles cannot widen it. A complete matching test qualification permits a valid extended case; each mismatched field, revoked record and policy revision fails. |
| Stale plans | Change device, boot ID, kernel/updater/utilities, layout, image, bootloader evidence or qualification between planning, staging and dispatch. Include changes during helper private-copy work and a second concurrent attempt. All must stop before flash mutation. |
| False-positive readback | Model a 32 MiB NOR with upper-bank accesses aliasing address zero. Write the synthetic incident FIT: boot bytes change while same-path logical FIT SHA-256 still matches. The protected check must fail and prevent reboot/retry. |
| Integrity and failures | Legitimate `fit_size`/CRC update succeeds; wrong value, other variable changes, invalid CRC, boot/spare corruption and short reads fail. Inject updater, flush, evidence-storage, connection and verification faults. No post-dispatch fault causes automatic destructive retry. |
| Route parity | Parameterize dispatch counters and outcomes across standalone SSH, manager/IP executor, direct USB updater, helper socket, API/CLI wrappers and mass-storage refusal. Test legacy `force-flash` against the same limit. Assert unsupported routes never leave a newly staged actionable FRM or eject. |
| RAM distinction | A proven RAM operation accepts a larger valid image within its separate RAM limits. SF mode with the same alternate name is refused. Resume/transition ambiguity cannot bypass persistent policy. RAM/SD bootstrap requires a new observation and persistent plan. |
| Compatibility | Existing image/profile, RF-idle, host-key, token, controller and return-layout checks remain effective. Old receipts remain readable but missing integrity evidence is not upgraded to verified success. |

Keep the aliasing regression independent of admission: exercise the verifier
directly against the damaged model, and use only injected test qualification when
testing the whole execution sequence. The production conservative guard must
continue rejecting that image before any write. This proves both defenses without
introducing a production bypass. Use command spies or an isolated fake device
filesystem to test emitted remote scripts, not only canned hash-return mocks.

For release validation, run the focused suites first, then the repository CI
matrix (Python 3.11/3.12/3.13), Ruff, mypy and package build. Update browser coverage
if plan/error presentation changes. Exercise the public helper/API boundaries as
well as direct policy calls.

**7. Three independently reviewable deliveries**

1. **Conservative prevention.** Add policy/observation records, known legacy writer
   footprints, plan binding and final gates across all persistent routes. Disable
   routes whose safety cannot be established, including legacy auto-reboot eject
   and ambiguous DFU. Add incident/boundary/bypass regressions and actionable errors
   showing actual size/end, allowed size/end and a supported next path. Exit:
   existing unpatched firmware cannot receive an unsafe PPU write; no extended
   addressing grants ship. This does not wait for firmware #99.
2. **Protected integrity and recovery evidence.** Add backups, fresh FIT/protected
   checks, environment comparison and receipt/schema/reconciliation updates. Land
   aliasing and fault-injection tests. Exit: a successful logical hash cannot
   authorize reboot after protected corruption or an incomplete integrity check.
3. **Explicit qualification.** Consume reviewed, versioned records matching
   board/flash/layout, exact running writer artifacts and relevant bootloader.
   Separate write-path and persistent-boot proof; both are required to widen
   persistence. Records come from a trusted shipped or administrator-controlled
   registry, never from the candidate image or an API capability flag. Exit:
   extended ranges are enabled only for recorded combinations, with revocation
   invalidating plans. Coordinate schema and evidence with firmware #99 early,
   while keeping its hardware work off the prevention delivery's critical path.

Update `docs/FLASHING_AND_DOCTOR.md`, `docs/HARDWARE_ACCEPTANCE.md`,
`docs/RELEASE_CHECKLIST.md`, and ADRs 0003/0004/0008 to distinguish image approval,
physical addressing, pre-reboot integrity and cold-boot qualification. State the
intentional compatibility restriction on unsupported mass-storage and recovery
routes. Do not describe all products marketed as Pluto+ as qualified.

Hardware acceptance belongs on dedicated recoverable boards under firmware #99:
record exact board/flash revisions and software digests; test both sides of 16 MiB,
erase and high-to-low transitions; use an independently qualified physical reader;
verify protected regions, warm and cold boot, identity/services and rollback.
Include Winbond and each other flash family actually granted support. A successful
Linux readback or a different fleet canary is insufficient promotion evidence.

**8. Validation performed for this review**

The following offline baseline passed in the current Python 3.11 environment:

```sh
.venv/bin/python -m pytest -q -m 'not hardware and not firmware and not browser' \
  tests/test_bootstrap_firmware.py tests/test_firmware.py \
  tests/test_ip_firmware.py tests/test_firmware_helper.py \
  tests/test_firmware_integration.py tests/test_ip_firmware_integration.py \
  tests/test_volatile_firmware.py tests/test_setup_integration.py
```

Result: **260 passed**, one existing Starlette/httpx deprecation warning. These
tests establish the current baseline; they do not validate the proposed fix or
any hardware combination. No radio operations, persistent writes or hardware
qualification were performed. Implementation still needs supported legacy
observation fixtures, writer/environment contracts and bench evidence; unknown
combinations remain blocked rather than being filled in with assumptions.
