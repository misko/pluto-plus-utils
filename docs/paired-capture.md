# Finite paired PSS / pilot recorder

`pluto_plus.hardware.paired_capture` composes the actual native pilot, coarse
map and fine-result clients. It is a one-shot **15 MS/s, shared-XFFT, PSMA ABI
1.6** transport workflow, not an RF detector, automatic candidate scheduler,
hardware qualification, firmware promotion, or continuous 300-second recorder.
Legacy interfaces and production radio exclusions are unchanged.

## Admission and ownership

Use only after the complete stop-enabled FPGA/kernel image has passed physical
qualification and the exact radio has been exclusively reserved. `.18` is the
local canary; outdoor `.17` follows only after the relevant canary gates.
`NativePairedBackend.connect(uri, observation)` creates three distinct IIO
contexts. It requires matching serial/boot metadata, and rejects shared or
aliased contexts. Context construction uses libiio's connection timeout.

The owner must separately provide a fresh `PairedAttestation` callback before
and after recording. Its `ObservationIdentity` binds serial, boot, session,
visit, RF/rate and processing fingerprint; bounded raw external evidence is
retained. Cached IIO metadata does not replace this attestation. No identity is
invented from PIL1. The recorder does not acquire/release a lease, retune RF,
flash firmware, install coefficients, enable TX, or restore scheduler settings.
The external owner remains responsible for those lifecycle obligations.

Construct `PairedFinePlan` with an explicitly selected phase, Q32.32 cadence,
finite request count and already-installed coefficient generation. The first
center is relative to the actual first pilot sample center, not host start
time. The schedule must fit the two-second envelope with future command lead
and span at least one second between fine anchors. This is a diagnostic
schedule; successful delivery must not be called coarse-to-fine acquisition.

`FinitePairedRecorder(backend, observation, fine_plan, attest).record(new_path)`
takes exclusive ownership of the backend. The output directory must be new,
have an existing non-aliased parent, and never overwrites earlier evidence.

## Native flow and qualification

1. Require a completely unused stop/reset epoch, then open the map buffer
   **before** pilot ARM, because opening maps flushes acquisition.
2. Run independent map, fine and pilot workers. Pilot capture is exactly
   5,000,000 complex samples (20 MB), in 25,000-sample refills at 2.5 MS/s.
3. Persist raw pilot progress and raw map/fine batches with file and directory
   fsync before adopting their decoded evidence. The authoritative pilot result
   is also retained; duplicate evidence and temporary copies add memory/disk
   overhead beyond the 20 MB payload.
4. Use serialized driver delivery counters before each 200-chunk/one-map
   refill. Poll stop between map operations, never concurrently on that client.
   Retain the stop ticket, terminal generation/bounds, driver-enqueued counts,
   host-reassembled prefix and fresh terminal health as distinct evidence.
5. Drain every finite fine request ID and verify submission, result and fault
   accounting. Join readers before ordinary buffer/context destruction.
6. Join actual pilot filter support, conservative coarse FFT support and fine
   search windows. Require a common anchor envelope of at least one second.
   Fine windows are sparse, **not** a continuous full-rate IQ recording.

Native operations use finite client timeouts. The overall deadline defaults to
10 seconds and the cleanup join budget to five seconds; arbitrary external
attestation callbacks, native binding bugs and stalled filesystems cannot be
given a hard wall-clock guarantee by this Python API. A late completion cannot
qualify within an expired recording deadline.

The receipt's `finite_transport_complete` is deliberately separate from
`persistent_30_300_second_qualified` and `rf_or_lock_qualified`, which remain
false. The tests execute real public clients over fake native devices; their
success does not establish ADC, DMA, Ethernet, sustained-rate or live RF truth.

## Cancellation and incomplete evidence

`cancel()` requests cooperative cancellation and returns true until final
terminal sealing is admitted. It returns false afterward. Internal producer
shutdown uses a separate signal, so late external cancellation during final
qualification or owner attestation cannot be mistaken for healthy cleanup.
Native `Buffer.cancel()` is never used.

`PairedCaptureError.receipt` retains incomplete status and available artifact
references. Storage failure quarantines the journal; raw prefixes may exist
without a durable terminal record and must remain unqualified. Process-control
exceptions (`KeyboardInterrupt`, `SystemExit`) are re-raised after cleanup with
their `paired_capture_receipt` attached, rather than silently translated.

If any worker remains unjoined, its context is **not** destroyed concurrently.
The caller retains ownership, and the INCOMPLETE receipt is a provisional
snapshot: the late worker may still append failure/raw evidence. An explicit
later `join_and_close()` can finish teardown, never retroactively qualify the
capture. A failed close remains sticky on subsequent calls; destruction is
not retried and an empty cached receipt cannot masquerade as recovery.
The backend must not be reused or the radio lease released while workers remain.

Independent blind GLRT, automatic coarse-to-fine scheduling, continuous
recording, hop boundaries, 30/60 MS/s profiles, RF restoration and actual `.18`
qualification remain separate stages.
