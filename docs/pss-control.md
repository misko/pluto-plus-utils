# Bounded PSS control and fine-start evidence

`PssIioClient.read_current_index(observation)` and
`read_tracker_control(observation)` expose bounded public reads for the paired
recorder. `open_fine_receipted(manifest)` opens a finite fine-result stream in raw
batch mode and retains the control operations which led to that opening. These
are reusable PPU prerequisites, not a paired recorder, a radio lease, or a
qualification of the eventual 300 s hopping workflow. Nothing discovers radios,
retunes an RF frontend, enables TX, seeds GLRT or chooses IQ using detector output.

All three methods currently require the explicit paired 15 MS/s/shared-XFFT
`ObservationIdentity` and an appropriately admitted `PssIioClient`. The 30/60 MS/s
profiles remain separate future qualification work. Existing `open_fine` behavior
and raw batch receipts are unchanged; the legacy and receipted methods share the
same owned buffer-opening body.

## Public methods

```python
index_receipt = client.read_current_index(observation, timeout_ms=1000, budget_ms=5000)
controls = client.read_tracker_control(observation, timeout_ms=1000, budget_ms=5000)
start = client.open_fine_receipted(
    manifest, queue_target=7, refill_results=16, timeout_ms=1000, budget_ms=10000,
)
```

The caller supplies a validated `FineScheduleManifest`, including its actual first
center. No center is automatically moved to make an otherwise rejected schedule
work. The actual refill size is `min(refill_results, manifest.count)`; the finite
count must fill whole native refills. Refills remain limited to 4096 fine scans.
The resulting stream is consumed through `read_fine_batch()` and checked against
the manifest with `validate_fine_batch()`. A startup receipt does not stand in for
any of those result batches.

Each method takes one exclusive lifecycle admission on its context. No public
read, open or close may interleave on that same client. Another context is not
locked or leased by this API: radio ownership, joining worker threads and binding
separate pilot/map/control contexts remain the recorder's responsibility. An
already-owned fine buffer is rejected before this method starts a new attempt.

Each operation receives a finite libiio timeout bounded by the remaining overall
budget. Both timeout and budget must be integers in 1..60000 ms. Work and the
journal are bounded: at most 128 operation records, with numeric attribute text
retained up to 128 characters and the original observed character count. These
are cooperative bounds on the supported binding; a broken native function which
ignores its timeout cannot be forcibly killed by this code. Context construction
and the earlier `PssIioClient.connect()` admission happen outside this transaction.

Exact cached context serial aliases must match the supplied identity. Present
cached `boot_id` metadata must also match. An absent boot attribute stays `None`;
the caller-supplied boot ID is not substituted or newly attested. Frequency,
processing fingerprint, coefficient content and radio/boot/visit ownership remain
externally established. Cached context metadata is not a fresh network identity
query, and no lease is created here.

## What the counter and control reads mean

The driver implements one `current_index` read as LOW then HIGH. The tracker RTL
latches the entire counter when LOW is read, so this one u64 value is coherent.
Zero is a valid observed index, not missing evidence. The value is a historical
original-source coordinate, not host arrival time, a measured ADC sample rate,
RF settling evidence, or a guarantee that a later command still has enough lead.

The full control receipt preserves separately sampled identity/rate/geometry,
status, active generation, schedule parameters, scheduling/submission counters,
delivery/failure counters, fault flags and finally current index. It is **not an
atomic snapshot** of those fields. A structurally complete read may report a zero
coefficient generation or nonzero fault counters: `complete` means the requested
reads were retained and validated, not that those values are healthy. Unknown or
failed numeric reads remain `None` with raw/error evidence, never invented zeros.

`schedule_submitted` resets when a new schedule is enabled. The driver's
`packets_delivered` counts successful pushes into the kernel IIO buffer, not host
refills or durable storage, and is not reset with each schedule. These counters
are u32 observations; no cross-epoch subtraction or continuous coverage is
inferred from them.

## Requested, acknowledged and subsequently observed

The immutable `PssFineStartReceipt` keeps the manifest, actual refill size, host
stream ID, before/after control receipts, every journaled operation and errors.
`PssControlStep` distinguishes:

- The exact requested attribute text and whether native I/O was entered.
- A known normal binding return from an exception or interrupted/unknown outcome.
- Exact returned read text, any bounded-prefix truncation, decoded integer and
  read/parse errors. Native attribute-write byte counts are unavailable in the
  installed Python binding and are not fabricated.

The five schedule staging writes, buffer allocation, native geometry check and
enable write have separate outcomes. Startup `enable_acceptance` is:

- `NOT_ATTEMPTED`: the enable operation never entered native I/O.
- `ACKNOWLEDGED`: the enable write returned normally through the binding.
- `UNKNOWN`: it was attempted but its successful return was not recorded.

An error such as a lost response may occur after the radio applied a write. It
does not prove rejection. An interrupted acknowledgment journal remains unknown.
If a known acknowledgment was recorded and a later read fails, the historical
acknowledgment stays recorded even though the overall startup receipt fails.

The Linux enable-write handler checks streaming, fault state, coefficient validity
and live minimum lead time before scheduling work. At 15 MS/s that minimum is
65,536 source samples. The earlier host preflight checks only its own observed
index; the driver checks again at the actual enable operation. Neither the
manifest nor an earlier read guarantees later acceptance.

`schedule_enable` reads the worker's live scheduling flag. The worker can clear
it after finite submission or on a fault, so zero is **not** a substitute for an
enable-write acknowledgment. A later zero with the full observed submitted count
can be consistent with a successful finite start. A stopped worker with an
incomplete submitted count fails startup verification. Acknowledged enable does
not prove that commands have all been submitted, that results have arrived, or
that the hardware detected anything.

The successful start also requires matching later schedule parameters, active
generation, fault-free observed fine-path counters and no observed source-index
regression. Before and after receipts are bound back to the retained operation
journal; copied raw/decoded inconsistencies do not qualify as complete. These
checks still do not replace the separate whole-path acquisition-health receipt,
PIL1 health, source-support joins or independent negative-retaining GLRT.

## Failure and cleanup

Ordinary failures raise `PssTrackerControlError` or `PssFineStartError`, carrying
their immutable `.receipt`. Process-control exceptions such as `KeyboardInterrupt`
remain process-control exceptions, with `pss_control_receipt` or
`pss_fine_start_receipt` attached when construction succeeds. If rich receipt
construction itself repeatedly fails, the original exception retains immutable
`pss_control_steps`, `pss_control_identity`, and for startup `pss_fine_manifest`.
The caller must persist those fallbacks as incomplete evidence, not infer a
successful start or retry the command invisibly.

Rejected starts attempt cleanup of their schedule/buffer before reconstructing a
rich receipt, so receipt-construction failure cannot bypass cleanup. Cleanup has
a separate finite reserve of up to twice the I/O timeout,
capped at 60 s. Disable and destruction outcomes remain in the same journal.
No native cancel is used. A timeout before entering an operation is recorded as
unattempted, including during cleanup.

A failed disable/destruction, an unavailable native handle after an uncertain
allocation, or failure to establish the cleanup budget quarantines the client.
Further reads/opens and legacy cleanup paths are refused. The owner must join all
readers and use explicit graceful context teardown; a possibly destroyed handle
is never retried. If no destruction was attempted and an owned handle remains,
joined teardown can still close that known owned buffer. Cleanup uncertainty is
retained, not converted into success after a later context close.

`cleanup_verified=True` means only that this attempt's known disable/destruction
calls returned. It does not prove command/result queues are empty, restore RF
settings, establish reusable acquisition epochs, or provide stop-at-map-boundary
semantics. Tracker schedule disable stops scheduling work; buffer disable cancels
that work and IRQ handling. Neither is a new FPGA flush or drain protocol.

## Tests and remaining qualification

`tests/test_pss_control.py` uses fake IIO only. It checks exact request text,
source-counter endpoints, early and late faults, finite deadlines, interrupted
writes and receipt finalization, missing/changed identity, each buffer/start stage,
copied contradictory receipts, exclusive admission, and sticky uncertain cleanup.
Existing PSS raw-batch and legacy tests also remain applicable.

This API has not acquired a live paired record. Deployment, independent pilot/map
and fine evidence on the same source interval, at least one second of timing
evidence, whole-path/terminal health and blind GLRT comparison remain required
before qualifying hopping or reporting a locked timing bound.
