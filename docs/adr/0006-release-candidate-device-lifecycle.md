# ADR 0006: Pluto+ owns release-candidate device lifecycle

## Status

Accepted on 2026-08-26. This architecture decision and its offline-tested
RAM-only implementation do not by themselves authorize hardware access,
candidate deployment, or persistent flashing.

## Context

`pluto-plus-utils` already owns local USB discovery, guarded RAM boot,
persistent firmware updates, canonical setup, controller exclusivity, and
hardware receipts. The tandem-AGC release workflow in `plutosdr-fw` grew a
second live-device implementation to cover requirements that the utility does
not yet provide:

- four local Pluto+ radios expose the same gadget address and require an exact,
  temporary host route to select one interface;
- RAM Dropbear generates a new host key on every boot, so a pre-boot host-key
  pin is not a stable post-boot identity;
- release deployment must prove the selected image was loaded only into RAM,
  the same serial and USB topology returned, the persistent `qspi-linux`
  partition did not change, and the final RF/tandem state is safe;
- the release candidate is defined outside this repository and changes more
  frequently than the utility's built-in recovery and promotion profiles; and
- a release deployment receipt must be reusable by the lifecycle, quality,
  transient, modulated, soak, and release-evidence consumers.

Keeping two independent implementations of discovery, route selection, SSH,
DFU transition, cleanup, and receipt construction makes their behavior drift.
Adding a hard-coded utility profile for every release candidate would preserve
that duplication and make each firmware-only revision require a utility source
change.

This is an owner-operated workflow. Host keys, GitHub attestations, and remote
signatures are not authorization requirements. Content hashes, serials,
topology, QSPI equality, and safe-state readbacks remain valuable as operational
guards against selecting the wrong radio, wrong image, or persistent target.

## Decision

`pluto-plus-utils` will become the sole implementation of live Pluto device
operations for release-candidate deployment and later persistent promotion.
`plutosdr-fw` will continue to own firmware source, trusted builds, candidate
and final release policy, hardware-test definitions, campaign aggregation, and
publication.

The first implementation milestone is RAM-only candidate deployment. Setup and
persistent promotion will reuse the same identity, route, credential, and
receipt primitives after the RAM path passes offline and one-radio acceptance.

The legacy static-profile `firmware ram-boot` and its v1 receipts remain valid
for their existing profiles. Release-candidate deployment is a separate command
and schema; it must not reinterpret a legacy receipt as release evidence.

## Ownership boundary

### `plutosdr-fw`

- builds and packages the candidate;
- emits a local release-candidate plan from its verified artifact index;
- defines the required firmware version, hardware model, ABI/capabilities, and
  DFU/FIT hashes;
- validates the returned utility receipt semantically;
- runs the muted lifecycle, steady, transient, modulated, soak, and comparative
  gain-control campaigns; and
- decides whether a qualified image may be promoted to persistent firmware.

### `pluto-plus-utils`

- inventories and selects one exact serial and direct USB topology;
- owns daemon/controller exclusion and per-radio/per-endpoint locks;
- acquires, verifies, refreshes, and removes the exact temporary host route;
- runs the fixed password-SSH RAM transition command;
- seals and downloads the exact candidate DFU to the `firmware.dfu` alternate;
- resolves a serial-less DFU enumeration only at the pre-attested topology;
- re-attests the returned runtime, boot epoch, QSPI bytes, and final safe state;
- performs bounded cleanup or emits an unresolved receipt after uncertainty;
  and
- writes the durable device-operation receipt.

Neither repository translates an older receipt into the new schema. The
original receipt bytes are retained and hashed by release evidence.

## Candidate plan

`plutosdr-fw` will generate a mode-private canonical JSON document with schema
`pluto-plus-utils.release-candidate-plan.v1`. It contains only device-operation
facts, not the complete release archive or its policy machinery:

- plan identifier and creation time;
- source repository and exact source commit;
- required `pluto-plus-utils` repository, version, and exact source commit;
- artifact-index path and SHA-256 as lineage references;
- DFU absolute path, byte count, SHA-256, FIT byte count, and FIT SHA-256;
- expected firmware version and exact hardware model;
- expected metadata ABI and required capability names;
- allowed operation `ram-only`;
- expected DFU vendor/runtime/DFU product pair and alternate name; and
- the exact confirmation phrase template.

The document needs no signature or remote attestation. The utility re-reads the
candidate file and image immediately before mutation and rejects changed bytes,
an unexpected operation, an unsupported model, or a persistent target.

An eventual persistent-promotion plan is a different schema or operation value
emitted only after the release campaign is qualified. A RAM-only candidate plan
can never authorize QSPI writing.

## Per-radio operation plan

The candidate document is radio-independent. Before execution, the utility
creates a separate mode-private per-radio plan without mutating hardware. That
plan binds:

- candidate-document path and SHA-256;
- strict USB-inventory path and SHA-256;
- exact serial and direct USB sysfs topology;
- current bus/device address and one selected network interface;
- the operator's expected current firmware for the selected radio;
- selected SSH endpoint and local source address;
- the intended receipt path; and
- a serial-specific confirmation phrase.

Creating this plan reads local files only. It does not open IIO, SSH, USB, or a
radio. Execution consumes the saved plan, re-runs live discovery, opens the
serial-bound USB IIO context, and performs every firmware/model/capability and
safe-state observation. A changed bus/device address alone may be refreshed
only by creating a new plan; it is never silently substituted. The password
file is supplied at execution time and is not embedded in the plan.

The command names and whether the plan/execute surface is one dry-run-default
command or two explicit subcommands remain an interface decision. The domain
model and state transition must be shared by standalone CLI and any later
daemon/API integration so they cannot become separate flashing engines.

## USB-bound SSH policy

The selected runtime must first be proven by exact USB serial, direct sysfs
topology, one network interface, USB-bound IIO serial, and hardware model. SSH
then uses the owner password only to invoke fixed remote programs. It does not
use a retained host-key pin:

- password input is a private regular file and is never copied into a receipt;
- `StrictHostKeyChecking=no`;
- user and global known-hosts files are `/dev/null`;
- public-key and keyboard-interactive authentication are disabled;
- exactly one password prompt is permitted; and
- every SSH call revalidates the selected interface and owned route.

This policy is limited to a serial- and topology-attested local USB action.
Network-only administration may retain the existing enrolled-host-key policy.

## Route lease

The candidate operation owns a global lock for the destination and a lock for
the selected serial for the whole transaction. For the normal gadget endpoint
it:

1. refuses a pre-existing host route for the destination;
2. adds exactly `HOST/32 dev INTERFACE src SOURCE scope link proto static`;
3. verifies the route record and `ip route get` selection before every SSH call;
4. re-adds only the same tuple if USB re-enumeration temporarily removes it;
5. deletes only its own tuple in `finally`; and
6. proves the host route is absent before publishing a successful receipt.

The broader host-isolation helper, which downs peer interfaces and removes
their routes, is not used for routine candidate deployment.

## RAM transition

The reviewed operation has the following state sequence:

1. Validate the candidate plan, exact clean utility repository/version/commit,
   DFU/FIT bytes, live serial/topology/interface, current firmware, model, boot
   ID, QSPI partition, and initial safe state.
2. Acquire the locks and exact route lease.
3. Revalidate password-file identity and request only
   `/usr/sbin/device_reboot ram` over USB-bound SSH.
4. Wait for one exact-topology `0456:b674` device. Its serial may be absent or
   empty; a present mismatching serial is rejected.
5. Copy the already-validated DFU bytes into a sealed anonymous descriptor.
6. Run only
   `dfu-util -d 0456:b673,0456:b674 -p PORT -a firmware.dfu -D /proc/self/fd/N`.
7. Run only
   `dfu-util -d 0456:b673,0456:b674 -p PORT -a firmware.dfu -e`.
8. Wait for one exact serial and topology to return as `0456:b673`.
9. Re-attest the expected firmware/model/capabilities, a changed boot ID, exact
   QSPI byte-count and SHA-256 equality, and the final safe state.
10. Remove and verify the route lease before atomically publishing success.

`-R`, `-S`, bootloader alternates, arbitrary remote commands, arbitrary MTD
paths, and persistent firmware operations are not accepted by this plan.

## Safe-state record

Both preflight and final cleanup record and check:

- TX1 and TX2 hardware gain at the mute limit;
- every DDS raw value and scale disabled;
- all DAC selectors set to the safe zero source;
- tandem state `IDLE`;
- tandem FIFO level zero; and
- tandem fault flags zero.

An action failure does not excuse cleanup. If the exact runtime returned, the
utility makes a bounded safe-state attempt and records its readback. If the
device remains in DFU, recovery is limited to the exact topology and detach
operation. An unproven state is `unknown`, never success, and must be reconciled
before another automatic deployment.

## Receipt

The utility emits canonical mode-private JSON with schema
`pluto-plus-utils.release-candidate-ram-receipt.v1`. The release validator checks
semantic facts rather than exact command argument ordering. Required sections
include:

- result, timestamps, exact tool repository/version/source commit, and plan SHA-256;
- exact target serial, model, topology, interface, and runtime/DFU USB IDs;
- candidate image/FIT identity and expected/observed firmware;
- pre/post boot IDs;
- pre/post `qspi-linux` path, name, byte count, and matching SHA-256;
- route tuple plus successful release verification;
- transition method and fixed operation inventory;
- final safe-state values; and
- failure phase, cleanup result, and reconciliation guidance when not successful.

Password contents, password hashes, password-file contents, and host keys are
not receipt fields.

## Release qualification

Successful RAM deployment is necessary but not sufficient for release. The
existing `plutosdr-fw` campaign remains authoritative and must run on all four
exact local radios. Its quality cells use identical RF stimulus and include:

- fixed manual gain;
- native AD9361 `slow_attack`;
- native AD9361 `fast_attack`; and
- tandem AUTO.

Every adaptive mode must pass the absolute signal-quality envelope and prove
bidirectional gain response. Tandem must additionally prove paired indices,
stable ownership, and both increase and decrease directions. Reports include
tandem-minus-manual and tandem-minus-native measurements, but release does not
invent a winner when controllers meet different valid objectives.

The comparative matrix is required in steady, transient, and modulated release
evidence at all three supported bands, alongside the muted metadata lifecycle
and soak gates.

## Migration

1. Freeze this contract and add schema/oracle tests in `pluto-plus-utils`.
2. Implement the new command with fake backends and full planted failure tests.
3. Add a `plutosdr-fw` candidate-plan producer and utility-receipt validator.
4. Remove the duplicate live-device transaction from the next candidate's
   authorizing path.
5. Build a new candidate because the release harness and receipt contract have
   changed; RC13 remains immutable historical build evidence.
6. Run dry plans for all four radios, then a one-radio RAM canary.
7. Deploy RAM-only on all four radios and run the complete release campaign.
8. Add persistent promotion to the utility only after the candidate-qualified
   campaign passes.

## Acceptance criteria

Before the first live candidate operation:

- both repositories pass their full offline suites;
- every route, credential, DFU, cleanup, and receipt failure branch has a
  planted test;
- the utility dry plan names one exact serial/topology and performs no hardware
  access;
- the release validator accepts one real utility success fixture and rejects
  every missing/mismatched semantic field;
- no legacy RAM receipt can satisfy release evidence; and
- no code path can convert a RAM-only plan into a persistent write.

Release completion still requires successful deployment and all mandatory
hardware tests on every local USB radio, including the manual, native slow
attack, native fast attack, and tandem comparison matrices.

## Consequences

- Device mutation has one implementation and one durable physical receipt.
- Candidate revisions no longer require hard-coded utility profiles.
- Ephemeral RAM host keys stop blocking a correctly USB-bound owner operation.
- The next hardware-authorizing candidate is rebuilt after the contract lands.
- Legacy profiles and network-only pinned-key administration remain available
  without being confused with release-candidate evidence.

## Resolved implementation choices

1. The native lifecycle is used; there is no delegation back to the firmware
   repository's duplicate deployer.
2. The first implementation is a daemon-off standalone maintenance command
   with daemon, endpoint, and exact-radio exclusion locks.
3. The first milestone stops at inventory, RAM deployment, reconciliation, and
   receipt validation. Canonical setup is the next utility-owned milestone;
   persistent promotion remains unavailable until the four-radio RAM campaign
   qualifies the candidate.
