# Source-coordinate support for paired observations

`pluto_plus.hardware.source_support` is a pure coordinate library. It opens no
radio, reads no IIO attributes, writes no files and selects no GLRT candidates.
It does not implement the paired recorder or qualify RF, continuity, transport,
disk persistence or timing lock.

The first explicit processing profile is
`ProcessingProfile.PAIRED_15_SHARED_XFFT_512_447_V1`: 15 MS/s, shared-transform
PSMA ABI 1.5, 66-sample template, 512-point FFT, 447 candidates per block, 20,000
phases and 64 frames/map. Selecting this profile is mandatory; a generic rate
or older ABI cannot silently inherit its geometry. Separately admitted profiles
and tests remain required for the later 30/60 MS/s stages, not removed from the
development goal.

## Separate timing anchors from input dependencies

All source intervals are half-open `[start, stop)` in original ADC sample units.
Starts must be valid u64 indexes; an exclusive stop of `2**64` is permitted.
Underflow, overflow, empty intervals and bool/float indexes are rejected. A
`SourceLattice` describes actual exported sample centers: its bounding interval
does not manufacture the intervening full-rate IQ. The endpoint separation of
N pilot samples is `6*(N-1)` source samples; `N/2500000` exposure is different.
For 300,000 outputs, first-to-last center separation is 119.9996 ms and the
half-open `bounds` interval through `last+1` spans 119.9996667 ms at 15 MS/s,
not the nominal 120 ms dwell. Joining uses strict center containment: a caller
that needs nominal `count*step` grid duration must carry that separately, not
extend the last observed center or silently relabel its bounds.

| Record | Timing anchors | Input dependency envelope |
| --- | --- | --- |
| Pilot output j | `n0 + 6*j - 269` | `[n0 + 6*j - 538, n0 + 6*j + 1)` |
| Map with start a | Candidate starts `[a, a+1280000)` | Ideal template inputs extend the stop by 65; actual FFT processing has the separate envelope below. |
| Fine packet centered on p, winning lag l | First-tap winner `w=p+l`, not a window midpoint | Winner `[w,w+66)`; complete admitted search capture `[p-32,p+98)`. |

For a canonical candidate k and an externally attested scheduler origin S:

`B(k) = S + 447*floor((k-S)/447)`.

The exact full-block processing envelope for candidate interval `[a,b)` is
`[B(a), B(b-1)+512)`. Without S, use the conservative bound `[a-446,b+511)`.
This is a dependency bound, not an assertion that all included samples have
equal influence. Quantized kernels and block-floating arithmetic mean the
ideal 66-tap envelope alone is insufficient as a full implementation bound.
Phase zero is relative to the acquisition epoch, not absolute index modulo
20,000. The API checks a supplied S against that phase relation; it cannot
attest S or invent it from the first map received.

These constants are pinned to the named FPGA processing contract, not inferred
from arbitrary future PSMA versions. Corresponding firmware sources are
`starlink_pss_overlap_scheduler.v`, `starlink_pss_ifft_qualifier.v`,
`starlink_pss_score_phase_tagger.v`, `starlink_pss_candidate_scheduler.v` and the
31/255-tap pilot filters. Changing those semantics requires a new profile.

## Pure API and evidence boundaries

`ObservationIdentity` requires caller-supplied serial, boot, session, visit,
source rate, processing profile, frequency-plan ID and a SHA256 identifying the
processing manifest. That manifest must bind firmware, filters and coefficients.
The library checks exact identity agreement; these strings are not independent
attestation. PIL1/map/fine payloads do not contain every field, so the external
owner must establish the association. Missing identities must not be guessed.

- `pilot_slice_support(snapshot, observation=..., expected_samples=...,
  received_bytes=..., start=..., stop=...)` requires a complete finite PIL1 count
  receipt and the actual reader byte count. It returns the output slice's
  absolute source-center lattice and complete filter-input envelope.
- `map_support(map, observation=..., fft_origin=None)` validates the complete
  ABI 1.5 map and returns candidate, ideal-template and exact/conservative
  processing intervals separately. It never crops bins or scores a map.
- `fine_support(packet, observation=..., coefficient_generation=...)` binds raw
  packet words and the expected generation, then returns winner and complete
  capture support separately.

Keep actual IQ, raw map bins, packets, source receipts and failure artifacts in
the caller's immutable ledger. `SourceRecord.record_id` refers to that ledger;
the coordinate library does not take ownership of raw payloads. Records may be
`COMPLETE`, `INCOMPLETE` or `UNOBSERVABLE`, with explicit reasons for the latter
two. Detection is separate: `NOT_EVALUATED`, `TRIGGER` or `NO_TRIGGER`.

`join_source_interval(records, observation=..., comparison=...,
available_inputs=...)` returns one decision for **every** input record in the
same order. The caller chooses comparison bounds independently of triggers:

- `comparison` is the timing-anchor/center interval being compared.
- `available_inputs` is the declared common input interval, including filter
  history and detector margins. It is not inferred from host arrival times.
- Complete maps must fit in their entirety; partial overlaps are unobservable.
- Pilot selections contain integer output indexes whose centers lie in the
  chosen comparison, with complete filter dependencies inside available inputs.
- Fine winners must lie inside comparison and their full admitted capture must
  fit inside available inputs. This does not say that fine continuously observed
  every sample of the interval.

`INCLUDED` means only per-record geometric containment. It does not check that
maps collectively cover one second, map generations are contiguous, every
scheduled fine request returned, or health stayed clean. Those checks belong
to the recorder/analysis contract. An incomplete or unavailable receipt is
retained with its reason, never converted to a negative detection. Changing a
record from `NO_TRIGGER` to `TRIGGER` leaves the pilot IQ slice unchanged.

Blind GLRT must still run without FPGA timing/CFO seeds and report the actual
pilot sample/symbol ranges it consumed. An epoch estimate alone does not specify
its integration support. Known filter/CFO limitations remain explicit
unobservable outcomes, not automatic FPGA false positives.

## Initial-boundary example and duration

At an epoch beginning at source 0, the first supported pilot output has newest
index 540, source center 271 and raw-input envelope starting at 2. A first map
starting at 0 cannot use a conservative negative FFT bound. `map_support`
rejects that bound; retain the raw map and add an `UNOBSERVABLE` record with its
original ledger ID and the reason. Never clamp the bound to zero. Even a proven
FFT origin of zero does not move the pilot's available raw support back to zero.
The first comparable triple may therefore be maps 2–4, not maps 1–3.

Three maps give 256 ms nominal candidate exposure; twelve give 1.024 s. Two
seconds of pilot IQ is a useful bounded initial envelope, but actual containment
governs which complete records qualify geometrically. Map alignment, FFT tails,
IIO buffering, host scheduling lead and future fine capture still add latency.
No fixed capture duration alone guarantees a one-second paired timing result.

The tests exercise every FFT-block phase, high u64 coordinates, filter history,
boundary rejection, missing bytes, identity mismatches, incomplete/unobservable
records and invariant pilot selection for triggers and negatives. They are
offline geometry tests, not hardware/RF evidence.
