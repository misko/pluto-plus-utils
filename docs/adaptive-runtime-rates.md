# Adaptive scan runtime rate requests

Runtime rate negotiation extends the v0.54 adaptive and counter-UTC companion.
It does not add entries to the legacy rate mask or change existing v1 records.

`SCANCAPS2 96` returns an `SPCP` record with wire version 2. The legacy fields
retain their meaning. Three little-endian uint32 fields occupy offsets 80, 84,
and 88: rate mode 1 (setup validated), minimum requested rate 520833 S/s, and
maximum requested rate 61440000 S/s. These bounds admit integer requests; they
do not guarantee that a particular clock rate, RX topology, dwell, or transport
pace is realizable. Unsupported commands fall back to a fresh `SCANCAPS`
connection; malformed capability replies and other errors fail closed.

The campaign builder selects setup version 2 for rates outside the legacy
2.5/10/15/20/30 MS/s set. Explicit `ScanSetup(protocol_version=2, ...)` also
selects runtime negotiation for a legacy rate. Before changing radio settings,
the campaign requires runtime capabilities and the selected RX topology.
Source and capture clock readbacks must match the requested integer exactly;
a rejection or mismatch restores the saved settings before profile compilation.
Firmware must independently admit the exact setup; no rate is silently coerced.

Version 2 setup and visit records retain the v1 sizes and field offsets. A
session requires matching setup/visit versions. Feedback, acknowledgements,
terminal records, and counter-UTC observation wire formats remain v1. Existing
v1 setup golden bytes and legacy discovery are unchanged. Counter-UTC evidence
accepts exact runtime integer rates while retaining all interval and identity
checks; it does not claim independent absolute UTC accuracy.

For a dwell of `ms`, the retained sample count uses `rate * ms // 1000`.
For example, 120 ms at 7.5 MS/s is 900000 sample periods, or 7200000 bytes
for two CI16 receivers. Arbitrary integer rates may produce fractional sample
durations, so source-counter accounting remains authoritative.

## Bounded issue-111 qualification

`scripts/issue111_adaptive_qualification.py` runs one explicitly selected cell
and never retries. `--cell caps` performs capability discovery only. Capture
cells are `baseline-dual2p5` and `baseline-single15` (15 seconds each),
`dual5`, `dual7p5`, `dual8` (120 seconds each), and `unusual` (5 seconds at
12345679 S/s; either exact admission or explicit restored rejection is useful).
All use four lower-edge targets and 120 ms dwells. `--utc` additionally collects
counter-clock evidence without asserting absolute UTC accuracy.

The default serial is the issue's radio at 192.168.1.21. `--serial
1040007c4a94000211000b009186843ef2` selects the local RAM-test radio over its
physical LAN address 192.168.1.18. Always use the same `--ledger` file across
both radios, cells, and attempts. The exclusive ledger charges duration plus
60 seconds per attempt, including failed/interrupted attempts, and refuses
reservations exceeding 1200 seconds cumulatively. A wall-clock alarm cancels
an overlong attempt through the ordinary cleanup path. Cleanup must complete
before another cell; the ledger never automatically refunds time or retries.
This conservative reservation includes setup overhead, so two complete suites
do not fit: choose the planned acceptance cells and subsequent deployment checks
within the aggregate budget.

Each unique `--output` JSON contains metadata-only visit records, exact IQ-byte
and terminal accounting, a source interval partition including skips and the
terminal tail, gap samples in milliseconds, and independent ordinary-libiio
readback/restoration checks. A failed cell returns nonzero and retains failure
details. Do not treat an unusual-rate rejection as successful rate qualification.
