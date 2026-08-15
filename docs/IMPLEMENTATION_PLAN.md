# Pluto+ standalone implementation plan

This file is the durable implementation checklist. A phase is complete only
when its behavior and exit tests are both present. Hardware-mutating tests are
never part of the default offline lane.

| Phase | Implementation | Exit evidence | Status |
|---:|---|---|---|
| 0 | Package, contracts, state model, artifact and firmware safety boundaries | Contract tests run without hardware | Complete |
| 1 | Fake dual-RX radio, exclusive controller, settings, captures, SigMF, baseline analyzers | Unit and fake vertical-slice tests | Complete |
| 2 | REST/WebSocket daemon; CLI uses only the daemon | API and CLI contract tests | Complete |
| 3 | Embedded UI for status, tuning, capture, scan, waterfall, analysis and guarded firmware | Static safety/API tests and browser E2E | Complete; Chromium E2E runs in dedicated CI lane |
| 4 | Serial-bound IIO discovery and real receive adapter | Mock adapter tests, then one/two-radio marked tests | Mock-tested; hardware pending |
| 5 | Exclusive frequency-scan jobs with automatic settings restoration | Fake scan/API/CLI tests and hardware scan acceptance | Offline complete; hardware pending |
| 6 | Firmware inspect, upload, plan, RAM load, post-boot verify, persistent QSPI and receipts | Failure matrix, RAM qualification, persistent canary | Offline/API/UI/helper complete; hardware pending |
| 7 | Direct USB/IP optimized transports | Protocol fixtures, recovery and rate ladder | IP loopback and USB fake-backend I/O complete; attached-hardware ladder pending |
| 8 | Additional provenance-safe signal analyzers from audited requirements | Synthetic truth and provenance record | Complete: quality and dual-receiver |
| 9 | Failure, storage-pressure, interruption and soak qualification | One/two-radio fault matrix and 8–24 hour soak | Offline fault/storage/bounded-soak complete; attached 8–24 hour soak pending |
| 10 | Standalone release artifacts and clean-host deployment | Full CI, packaging smoke, SBOM, upgrade/rollback | Build/clean-install smoke and CI definition complete; hosted run/license/SBOM pending |

## Product invariants

1. `plutod` is the sole process that opens a radio. CLI and browser clients use
   the versioned API.
2. Every physical radio is selected and re-attested by stable serial. Transient
   USB addresses are not identity.
3. RX0/RX1 share one hardware refill. Separate processes never open the two
   receivers independently.
4. Settings are optimistic transactions: apply, read back, verify, then advance
   the revision. A mismatch fails closed.
5. Browser backpressure cannot stall acquisition. Spectrum subscriptions are
   bounded and discard stale presentation frames.
6. Complete captures are immutable atomic SigMF CI16 pairs. Failed captures are
   retained separately and never indexed as complete.
7. Analysis consumes artifacts, not radio handles, and records analyzer version
   and source identity.
8. Scans own the radio exclusively and restore the prior settings on success,
   cancellation, and recoverable failure.
9. Firmware mutation requires an immutable serial/path/image-bound plan,
   immediate identity and digest rechecks, an expiring one-time confirmation,
   and a durable receipt.
10. Persistent Pluto+ updates may stage only `pluto.frm` for the Linux FIT/QSPI
    firmware partition. Full update archives and `boot.frm` are refused.

## Test lanes

| Lane | Runs by default | Purpose |
|---|---:|---|
| Unit/contract | Yes | Models, protocols, analyzers, state transitions and safety validation |
| Fake integration | Yes | CLI → API → controller → capture/scan → analysis vertical slices |
| Browser | Yes when browser tooling is installed | Operator workflow, accessibility and live rendering |
| Hardware read-only | No; `hardware` marker | Discovery, identity, versions, settings and capabilities |
| Hardware capture | No; `hardware` marker | Dual-RX integrity, rate ladder, tuning and interruption |
| Firmware RAM | No; `hardware` + `firmware` markers | Volatile candidate lifecycle and rollback |
| Firmware persistent | Never implicit | Qualified single-radio canary followed by explicit fleet promotion |
