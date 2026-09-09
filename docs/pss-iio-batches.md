# Bounded raw PSS refill receipts

The experimental `PssIioClient` supports additive `batch_mode=True` admission
and `read_map_batch()` / `read_fine_batch()` methods. They retain each native
IIO refill's actual bytes before parsing, including padding and malformed
tails. They do not implement the paired recorder, durable storage, hopping,
independent GLRT, or a stop-at-map-boundary protocol.

On an already attested, caller-owned context, the intended API is:

```python
# No discovery, configuration, connection or ownership acquisition is shown.
client.open_maps(refill_chunks=200, batch_mode=True, timeout_ms=1000)
receipt = client.read_map_batch(timeout_ms=1000)
# Persist receipt.raw AND the receipt metadata before giving decoded chunks
# to the recorder's stateful PssMapReassembler.
```

`open_fine(..., batch_mode=True)` similarly selects `read_fine_batch()`. The
default 16-result fine refill is supported. Finite fine counts must be divisible
by the actual refill length (`min(refill_results, count)`); otherwise admission
fails before configuring or allocating a buffer. Count zero still denotes an
unbounded producer; individual reads are bounded, but this is not a finite
capture or a valid complete fine-schedule receipt.

Legacy `open_*` defaults, decoded-only reads and default cleanup behavior are
unchanged. Batch reads require explicit batch admission; decoded-only and batch
reads cannot mix within a stream. A failed batch poisons that stream until
cleanup and a newly admitted stream/context. Coarse acquisition remains one
continuous session per FPGA reset epoch; cleanup never makes it restartable.

## Bounded admission and execution

Batch admission checks a maximum of 4096 scans **and** one MiB before native
buffer allocation. Map scans are 256 bytes, so 4096 scans equal one MiB; fine
scans are 128 bytes, so their maximum batch is 512 KiB. A 200-chunk map refill
is 51,200 bytes; the legacy default 400-chunk refill is 102,400 bytes. Actual
scan stride, native buffer length/step and any exposed sample count must agree.
A finite context timeout is set before batch-mode opening performs its first
IIO attribute/configuration operation, and again before each batch read.

The `PssIioClient` constructor/connection still performs its existing discovery
and ABI attribute reads using the binding's connection/context defaults; the
new batch timeout does not retroactively bound them. `timeout_ms` on `open_*`
is used only with `batch_mode=True`. Timeouts bound individual supported IIO
calls, not total recording duration or arbitrary third-party Python code.

New batch opening/reading requires exclusive public-operation access to its
context. Another in-flight operation prevents changing its timeout; new public
operations and cleanup are rejected while the batch operation is in flight.
After taking that guard, the reader resolves the current buffer/stream and
rechecks closed/open state. A legacy close or competing open that finished
before admission cannot leave a cached destroyed buffer or overwrite an owner.
Use separate bounded pilot/map/fine contexts under one externally attested owner
in the future paired recorder. Private context/buffer access is not guarded.

No queues, history accumulators, persistence callbacks or reassembler are owned
by this API. Each call returns one bounded receipt or raises one receipt-bearing
error. A recorder must use its own bounded queue and storage budget and must
retain failed as well as successful observations. Retaining an unlimited number
of receipts is not bounded by these per-call limits. Decoded objects, raw/native
buffer copies, and caller-owned queues use additional memory.

## What one receipt proves—and does not

`PssBatchReceipt` is immutable. It records host-generated stream ID and attempt
index, admitted ABI/rate, requested scans, native geometry, refill start/return
state, observed byte count, retained `raw`, before/after attributes and indexed
`PssBatchScan` observations. Stream ID is not a serial, boot, visit or RF identity;
the caller must bind all those to its manifest. Batch indexes count attempts,
not RF samples, and never replace FPGA source coordinates.

`raw` is `None` when no readable payload was obtained; this is distinct from
`b""`, an actually returned empty payload. `refill_completed` means the native
refill call returned without a reported error. Standard pylibiio 0.25 discards
the C refill return count, so `native_refill_bytes` is `None`, not an invented
zero or `len(raw)`. A binding that supplies an integer count is checked against
the actual `read()` result; a negative return is a failed refill and is never
followed by reading stale buffer memory. Native buffer capacity is not treated
as its valid byte count.

Supported returned payloads are `bytes` or `bytearray`. A broken binding can
already have allocated an oversized object before returning it. The reader
retains at most its bounded per-stream prefix and labels retention truncation
explicitly; `observed_bytes` retains the original length and
`raw_retention_complete` is false. It never silently describes that prefix as a
lossless full batch. No concatenation, padding repair or scan-fragment carry
between refills occurs. Whole-but-short, empty, oversized and partial-tail
refills are all retained but rejected as complete batches.

Each scan observation names its exact byte offset and length within retained
raw bytes, decoded object if available, and diagnostic errors. Complete scans
are decoded independently: a malformed middle scan does not erase valid later
diagnostics. A trailing fragment remains an explicit undecoded observation.
Context-ABI, coefficient and request-sequence mismatches retain any parsed
object **as diagnostic data only**. All-zero maps and other negative observations
are retained exactly; there is no detection-based filtering or GLRT seeding.

Fine request accounting changes only after the entire batch passes, including
the separately sampled active coefficient generation and driver fault flags
before/after the refill. A malformed packet cannot partially consume the host's
request ledger. This checks IDs and existing packet self-consistency, not the
future recorder's exact Q32 scheduled-center ledger or coefficient provenance.
Unknown attribute values are `None`, not assumed healthy zeros; raw numeric text
is retained up to 128 characters with explicit truncation/error reporting.
These attribute reads are not mutually atomic, terminal health snapshots or
complete upstream/DDC coverage; use separate fresh acquisition-health evidence.

`complete` means only the requested raw batch size, scan decoding and these
narrow contextual checks passed. It requires every requested scan to have its
exact index, byte offset and full stride, a decoded object, and no scan errors.
Raw-only or partly decoded fallback receipts are never complete, even when all
requested bytes were received. It does not establish complete map reassembly,
map generation continuity, source-support containment, durable storage, DMA/RF
truth, settling, signal presence, GLRT agreement or timing lock. A whole map
still requires the caller's strict reassembler. A failed reassembly must retain
the original receipt/raw before the reassembler resets its partial state.

## Errors and joined cleanup

`PssBatchError.receipt` retains the same raw bytes, decoded diagnostics, unknown
attributes and error descriptions. Further reads in that selected stream are
refused; do not guess a new request index or forgive a missing map. A refill
exception is not followed by reading a possibly stale old buffer. Decoding
and receipt-finalization interruptions re-raise the process-control exception,
attaching `.pss_batch_receipt` and, when needed, `.pss_batch_scans` diagnostics.
If even initial raw-receipt construction fails, `.pss_batch_raw` preserves the
bytes without pretending a complete structured receipt exists. Interruption
during final completeness traversal or host-ledger updates also retains the
decoded receipt and fails the stream. A partial ledger update is not claimed
to have rolled back: the receipt keeps its pre-update values, and failed-state
admission prevents resuming that ledger. The exception remains authoritative.
The operation guard is released on all these failure paths.

Retain the capture worker's return/exception outside any queue, stop and join
all bounded readers, then use `close_gracefully(readers_joined=True)`. This
tears down failed streams without native cancellation and retains the failed
batch/incomplete fine schedule in its cleanup errors. It does not abandon
cleanup just because evidence is incomplete. Batch-mode opening failures with
an owned buffer also disable/destroy it without native cancellation, preserving
any cleanup errors on the original exception. Stream identity is prepared before
native allocation; allocation and registration are both inside owned-buffer
cleanup protection. Existing legacy close/context
manager defaults retain their native-cancel policy; choose graceful cleanup
explicitly for paired recording.

If failed-open producer disable or native destruction itself fails, a sticky
cleanup-uncertainty quarantine blocks every later public I/O/admission path,
including legacy readers/openers and default close methods. Only explicit
joined `close_gracefully` remains available; it closes the context and retains
the original uncertainty in its failed receipt. A cleared ownership pointer
does not prove destruction succeeded, and the possibly destroyed buffer is
never destroyed a second time. Repeating joined cleanup reuses its receipt.
The context cannot be reused; this does not claim the radio recovered or that
a new deployment/connection is automatically safe. Preserve the original open
exception and its cleanup notes alongside the joined-teardown receipt.

There is still no implemented map-boundary stop receipt in this host API.
Ordinary coarse disable can abort a partially filled map and leave a real fatal
hardware counter. No raw-batch success or cleanup policy forgives that fault.
The future paired recorder must independently finish/drain admitted map and
fine work, retain every receipt and compare only proven common source support.
Offline tests exercise fake buffer/control lifecycles, not radios or Ethernet.
