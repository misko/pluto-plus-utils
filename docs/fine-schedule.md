# Finite fine-schedule evidence ledger

`pluto_plus.hardware.fine_schedule` is a pure prerequisite for a future paired
recorder. It makes no IIO calls, starts no schedule, changes no radio and performs
no detection. It does not implement the paired recorder or the eventual 300 s
hopping acquisition. The current supported profile is explicitly
`ProcessingProfile.PAIRED_15_SHARED_XFFT_512_447_V1`, at 15,000,000 source samples/s.
30/60 MS/s require separately qualified processing contracts in a later stage;
their geometry is not inferred here.

## Exact scheduling arithmetic

`FineScheduleManifest` binds a caller-owned `ObservationIdentity`, bounded
`schedule_id`, first center, unsigned Q32.32 period, nonzero request-ID base,
nonzero finite count, and nonzero coefficient generation. Construction and
indexing use constant-size arithmetic, even with a large finite count.

The current Linux `adi_starlink_pss_tracker.c` initializes `next_fraction = 0`
when enabling a schedule. `pss_advance_schedule()` adds the integer period,
adds the low 32 fractional bits with unsigned carry, and increments the center
on carry. For zero-based result ordinal `n`:

```text
center_at(n)  = first_center + ((n * period_q32_32) >> 32)
request_at(n) = request_base + n
```

This is not rounding each period independently or starting with a half-sample
fraction. The period's integer part must be nonzero, matching the driver.
Request IDs may end at `0xffffffff`, but never wrap through zero. Source centers
must not overflow u64. The kernel also advances after its final submission, so
the manifest conservatively rejects overflow of that unused post-last center.
Full capture supports must fit the unsigned source domain as well; no negative
history is clamped away. The exclusive interval end may equal `2**64`.

For the admitted 15 MS/s profile, `capture_at(n)` is the full fine-search input
interval `[center - 32, center + 98)`. Actual decoded winners separately retain
their 66-sample input interval `[winner, winner + 66)`. Neither is interchangeable
with the scheduled center or with a pilot-output index.

These checks do **not** prove that the first center is in the future, that the
driver's minimum lead time is satisfied, that coefficients were installed, or
that the driver accepted/submitted anything. There is no current-index read.
In particular, the fine tracker ABI `0x00010002` does not distinguish the legacy
and shared 15 MS/s map paths. The external identity/processing manifest must
attest the shared path, coefficient content, firmware, serial, boot, visit and
frequency plan; the packet contains no substitute for that binding.

## One native batch, one immutable successor

Create a `FineScheduleLedger(manifest)` and pass one retained fine
`PssBatchReceipt` to `validate_fine_batch`, with the independently established
`observation`. A `PssBatchError.receipt` is also useful input: it preserves a
failed attempt instead of dropping it. Map receipts are not fine observations.

The returned `FineScheduleBatchResult` contains the original receipt by reference
(including exact raw bytes, native refill boundary and detailed native errors),
the prior and successor ledgers, per-slot diagnostics, actual decoded packets,
source records, and bounded validation summaries. It checks:

- Fine rate/ABI, native scan stride/buffer length, refill completion and exact
  retained byte/scan coverage. A native refill byte count of `None` remains
  explicitly unavailable; a known count must match. Read bytes are not RF truth.
- Both before/after driver fault and coefficient-generation attributes, including
  their raw numeric values. Missing evidence, read errors and late faults fail.
  These are separate attribute reads, not atomic whole-path health receipts.
- The bound stream identity, consecutive native batch ordinal, and native
  expected-request/remaining-count agreement with the finite ledger.
- Re-decoding each raw 128-byte scan (104-byte payload plus zero IIO padding),
  matching the supplied decoded diagnostics, and exact scheduled request ID,
  Q32 center and coefficient generation at every ordinal.

Only a completely valid native batch advances the accepted prefix. Any failure
returns a `FAILED` successor with the prior accepted count, batch ordinal and
stream binding unchanged. All source records from that failed batch are
`INCOMPLETE`, including otherwise valid diagnostic packets. Their actual support
may still be retained; an expected center never substitutes for an observed one.
Missing requested slots and truncated tails remain explicit. A badly shaped or
oversized envelope yields one unexpanded incomplete observation instead of
traversing an unbounded collection; its original receipt is still retained.

At most 4096 fine slots / 512 KiB of retained raw bytes are traversed per call.
The ledger holds no batch history. A caller can already own a malformed receipt
larger than that cap; returning its reference neither copies nor validates those
oversized contents. Global original error collections are not expanded into each
row. The owner remains responsible for bounded persistence and history retention.

`ACTIVE` accepts another batch; `FAILED` and `COMPLETE` refuse further admission.
The durable owner must journal each result and adopt `result.after`, including
failed successors. Historical immutable states can deliberately be forked; this
module cannot revoke old values, enforce exclusive ownership, or prove that a
record was persisted. Do not resume from `result.before` after a failure.
If pure validation is interrupted or a programming precondition raises, no state
has been mutated and no successful successor exists; the owner must retain the
input and treat that attempt as uncommitted, not infer acceptance.

## Independent negatives and source-support joins

Optional per-requested-slot labels use the existing `DetectionState` enum. The
default is `NOT_EVALUATED`; `NO_TRIGGER` is preserved, not omitted. Labels never
filter records, choose the comparison interval, alter source geometry, or seed
GLRT. An unavailable slot without a supplied label is not fabricated as negative.
Even supplied negative labels on malformed slots remain only labeled incomplete
observations, not validated detector outcomes.

Pass `result.source_records` to `source_support.join_source_interval()` with
caller-chosen, trigger-independent `comparison` and `available_inputs` bounds.
Fine joins require the actual winning first-tap coordinate inside `comparison`
and the **full search capture** inside `available_inputs`. A boundary without
enough input history is `UNOBSERVABLE`; it is not cropped or silently accepted.
Failed-batch records remain `INCOMPLETE`. Shared observation identity is required.
No host-arrival time participates in these joins.

The ledger exposes `validated_anchor_separation`: last accepted scheduled center
minus first, or `None` without accepted results. One result has zero separation.
For a 20,000-source-sample integer period, 750 results span 14,980,000 samples;
751 results span 15,000,000 samples between their anchors. This is neither
`count * period` nor continuous measured raw coverage: the 130-sample captures
are sparse and leave gaps. `COMPLETE` means only that the requested finite result
sequence was validated. It does not establish one second of timing lock, paired
map/pilot support, independent GLRT agreement, whole-path/RF health, or graceful
stop-at-map-boundary behavior. Those remain recorder/firmware qualification work.

## Offline tests

`tests/test_fine_schedule.py` covers the explicit kernel u32 carry recurrence,
fractional periods across native boundaries, finite/u64/request-ID endpoints,
post-last overflow, maximum count without schedule allocation, wrong center with
a valid ID, raw/decoded contradictions, generation and identity changes, malformed
middle/tail packets, late/missing health, negative retention, incomplete and
unobservable joins, bounded expansion, and failed/completed successor refusal.
These are pure synthetic evidence tests; none access a radio or certify RF lock.
