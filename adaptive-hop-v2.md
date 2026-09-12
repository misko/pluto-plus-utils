# Adaptive capture V2: explicit host boundary

2026-09-09. Offline integration, default-off; not a radio deployment or detector
qualification. Existing fixed V1 readers and sessions still reject adaptive
records. No firmware, FPGA or kernel changes.

## Public components

- `adaptive_hop` owns immutable HOPR/HOPS/HOPT V2 byte codecs and exact policy
  admission. Common V1 objects are numeric geometry, not fixed-order sessions.
- `AdaptiveHopStreamV2` validates contiguous blocks, stream generation, actual
  event chains, source-time decisions, tuning/guards, complete dual-RX IQ and
  terminal inventory. It never uses a visit modulo eight as an actual channel
  or invents a sweep. An invalid block permanently faults its stream.
- `AdaptiveHopClient`/`AdaptiveHopSession` own admission, iteration, bounded
  classifier drain, cancellation and backend release. A capture receipt wraps
  V2 stream facts and the separate host lifecycle/clock/readback facts. Extension
  callback errors are advisory; scientific quality is reported by the extension,
  not inferred from a successful capture receipt.
- `IioAdaptiveHopBackend` and `iio_adaptive_hop_client` explicitly select V2.
  They reuse exact physical-LAN/serial checks, volatile profile preparation,
  dual-RX geometry, base-header binding and restoration. An incompatible
  classifier cannot silently turn an adaptive request into a fixed recording.

The metadata extension port consumes shared numeric event/status geometry only
after V2 validation. The application must provide an explicitly V2-aware request
extension; the existing fixed request extension correctly refuses V2. The
application's immutable V2 publication and UI adapters remain separate work.

## Resource and accounting limits

120 ms valid dwells, two receivers recorded, 300 s plan, both existing rates.
IQ retention is one dwell plus two explicitly permitted event-lag blocks plus
one boundary refill; lag is configurable within 0..8 blocks. Missing metadata
beyond that bound fails closed. Emitted arrays own their samples. Event and
decision history is bounded by the requested maximum of 2,500 visits.

Only a following attested transition or successful terminal status closes a
full visit. Cancellation retains all delivered events/decisions and distinguishes
complete dwells, invalid transitions, unclassified tail time and its unreceived
suffix. Incomplete time is not counted as a valid 120 ms dwell. Duty counts both
receivers once, using source-counter elapsed time. A low-duty receipt reports
`duty_target_met=False`; it does not erase already received IQ.

Consumers must exhaust the visit iterator or call `close()`. After closure,
`take_terminal_visits()` retrieves any ready/full terminal visits not yet yielded,
exactly once. There is no destructor-based acquisition cleanup promise.

## Verification limits

Synthetic tests cover both rates and modes, uneven block boundaries, delayed
events, counters above 2**53, exact sample placement, corruption, compatibility,
negotiation failure and restoration. The application's real TCP fixtures also
exercise full 300 s accelerated counter spans and cancellation through this
client and backend. No live radio or independent sensitivity pass is implied.

The verification interpreter is Python 3.12. The shared workspace currently has
NumPy stubs that the Python-3.11 type checker cannot parse; strict checking of
the changed modules passes with the actual Python-3.12 target. The project's
Python requirement and NumPy dependency pin are not weakened to hide this.
