# Bounded finite pilot progress

`PilotIioClient.capture()` optionally accepts `progress_queue` and `cancel_event`.
These are additive hooks for a future fixed-frequency paired recorder. They do
not implement that recorder, blind GLRT, FPGA lock qualification, hopping, or
the eventual bounded 300-second scan. The existing default remains 120 ms;
the optional finite limit remains two seconds (5 million complex samples).

```python
import queue
import threading

from pluto_plus.hardware.pilot_iio import PilotCaptureEvent

events: queue.Queue[PilotCaptureEvent] = queue.Queue(maxsize=32)
cancelled = threading.Event()
# In a caller-owned worker, using an already attested, exclusively owned client:
# capture = pilot.capture(visit_id=17, samples=5_000_000,
#                         progress_queue=events, cancel_event=cancelled)
# A separate consumer drains events and persists IQ while capture is running.
```

The queue must be a standard FIFO `queue.Queue`, with integer capacity 1–4096.
Unbounded queues, subclasses, `SimpleQueue`, priority/LIFO queues and arbitrary
callbacks are rejected. The producer calls `put_nowait`: it never waits for
consumer capacity and never silently drops an event. This is not a hard-real-time
guarantee about Python scheduling or the queue's internal mutex. Do not mutate
queue methods, capacity or internals during capture. There must be one producer.
Use a new empty queue for each capture, or drain and identity-check all old
events before reuse. The event-count cap does not bound caller-owned preexisting
payloads. This capture enqueues at most 20 MB of IQ, plus event/snapshot overhead;
the final in-memory IQ, native buffer and temporary copies use additional memory.
Use distinct visit IDs within a client session; the host session UUID is not a
boot identity and does not change between that client's finite captures.

## Ordered immutable observations

Every event has an immutable `PilotEventIdentity`: expected serial, host session,
observed optional boot ID, visit, source rate, requested/refill sample counts and
2.5 MS/s output rate. These are ownership bindings, not new RF or firmware proof.
The event variants are frozen dataclasses, and IQ chunks contain immutable bytes.

| Event | Meaning |
| --- | --- |
| `PilotArmedEvent` | DMA buffer construction completed and a healthy fresh snapshot matches the requested visit/rate. No host IQ is claimed. The snapshot can have an empty or nonempty AXIS prefix. |
| `PilotOriginEvent` | The first complete host refill has actually been received. The validated prefix snapshot anchors output index zero; `received_samples` comes from the reader. `first_source_center` is a source-sample coordinate, not wall time. |
| `PilotIqChunkEvent` | An exact complete CI16 refill: `iq`, zero-based complex-output `output_offset`, and `sample_count`. Concatenation in offset order reconstructs successfully published bytes. |
| `PilotTerminalEvent` | Best-effort summary after ordinary cleanup, containing actual received/published byte counts, IQ hash, snapshots and errors. `complete` means only the finite transport gate. |

The normal order is ARM, origin, chunk zero, remaining chunks, terminal. An ARM
snapshot with an AXIS-delivered prefix can supply the origin without another
snapshot. Its count can be less than the first received refill: that earlier
count is **not** relabeled as the reader's later count. An empty ARM prefix
requires one fresh snapshot after the first full refill; that new snapshot
must account for at least the received refill. No origin is published before
actual complete IQ has arrived. No additional network snapshot is taken for
ordinary chunk progress. With no progress queue there are no additional
snapshot requests and the original IQ/count behavior is unchanged.

Origin observations check serial/available boot, visit, actual and declared
source rate, health, supported source index, and fresh snapshot generation.
The matched driver's buffer preenable CLEAR invalidates the old snapshots and
resets generation to zero. ARM establishes a **new** snapshot epoch; its
generation is not compared against the pre-buffer snapshot. From ARM onward,
generation must strictly increase through final cleanup; u32 wrap/reset within
that epoch is intentionally fail-closed, not inferred as continuity. An
established first index must remain unchanged. The final capture retains
`snapshot_origin` when progress was requested; failed captures retain every successfully parsed
snapshot. A malformed snapshot cannot become an origin. Missing, insufficient,
underflowing or changing source support fails the capture; nothing is clamped.
The context's cached identity attributes are not continuous authenticated boot
attestation; the external owner still supplies deployment evidence.

Early data is provisional. Later clipping, DMA/health faults, changed source
origin, failed cleanup or unavailable terminal evidence invalidates the result
even if all earlier events looked healthy. These hooks neither qualify all
upstream PSS health nor join pilot/PSS/filter support. Use the separate explicit
source-support contract for geometry; do not infer filter coverage from arrival
times, event counts or nominal dwell duration. Do not seed independent host GLRT
from these events or from FPGA detections.

## Failure, cancellation and persistence

Queue full or another enqueue failure stops the capture and invalidates it.
`PilotCaptureError` retains bounded partial IQ, available snapshots, cleanup
errors and `progress_errors`. A first-refill validation/cancellation failure
can leave received bytes only in that error, without a chunk event. A malformed
short/oversized refill is not published as a complete chunk; its bounded bytes
remain in the error. The consumer must reconcile offsets against the final
receipt/error, not assume the last received event describes all acquired bytes.

A terminal event is attempted after cleanup, including on failure, but cannot
be guaranteed when the queue is full or broken. Even terminal-only overflow
invalidates an otherwise successful capture; there is no successful return in
that case. A failed terminal enqueue may add an error unavailable to the queue.
The capture return value or exception is therefore always authoritative. Join
the producer and retain that outcome independently of queue delivery; do not
wait forever for a terminal event. `published_iq_bytes` means successfully
enqueued, **not** consumed, fsynced, persisted or RF-validated bytes. Hashes do
not establish disk durability. Consumer storage failure must set cancellation
and be retained in the recorder's own failed receipt.

`cancel_event` must be a standard `threading.Event`. It is checked before the
first capture I/O, at each I/O budget boundary and before terminal outcome;
the client never clears it. This avoids losing a cancellation racing with
worker startup. A pre-set token performs no capture timeout/identity calls,
configuration changes or ARM; creating the client beforehand still performs
its normal connection/attestation. The legacy `client.cancel()` remains a
per-capture cooperative token, reset when capture starts. Use the external
token when cancellation must survive that startup boundary.

Neither path calls native buffer cancellation or concurrently destroys an
outstanding refill. An in-flight IIO operation must return or time out first;
already returned bytes are retained. Recovery has its own bounded per-operation
I/O timeout, stops/drains/destroys normally, reads terminal health and restores
configuration. A token set during cleanup invalidates completion but does not
interrupt restoration. Failed clients require reconnection. The caller must
join the worker before closing its context. The final cancellation decision is
after the finite IQ copy/hash and before terminal outcome construction; a token
set after that decision cannot retroactively undo the committed outcome.
Offline queue/lifecycle tests do not qualify actual Ethernet performance, DMA
completion or live-radio timing.
