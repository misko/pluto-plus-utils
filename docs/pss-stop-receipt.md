# Offline map-stop receipts

`pluto_plus.hardware.pss_stop.PssMapStopReceipt` decodes the proposed `PSST 1 12`
map-publication fence receipt. It performs no IIO calls and does not add a new
firmware ABI to any radio client. The device/controller protocol and hardware
qualification are separate work; this decoder does not assert they exist on a
deployed radio.

The text contains twelve eight-digit lowercase hexadecimal words:

| Word | Meaning |
| --- | --- |
| 0, 1 | `50535354`, `0001000c`: magic and window version/count |
| 2 | Pending, terminal-valid, boundary-complete, failed, has-map, live-enable bits 0–5 |
| 3, 4 | Engine-accepted and terminal tickets |
| 5 | Actual terminal hardware map generation |
| 6, 7 | Terminal candidate start, low/high u32 |
| 8, 9 | Candidate end-exclusive, low/high u32 |
| 10 | Failure reasons, bits 0–5 |
| 11 | Command result code, 0–5 |

Failure bits retain detector/upstream, map, bridge, explicit-abort,
unrepresentable-bound, and exhausted-generation causes, respectively. Command
codes name accepted/idempotent (or reset-idle), malformed, invalid sequence,
busy, acquisition disabled, and known fatal health.

```python
from pluto_plus.hardware.pss_stop import PssMapStopReceipt

receipt = PssMapStopReceipt.decode(raw_text)
# Keep raw_text even if decoding fails; persist receipt.raw if it succeeds.
receipt.require_boundary_complete(expected_ticket=7)
```

Decoding checks the bounded ASCII envelope, word grammar, known version, and
reserved bits. It retains failed, pending, empty and invalidated historical
tuples for diagnostics. Direct construction must match the raw text exactly.

`require_boundary_complete` additionally requires the exact nonzero ticket,
terminal/non-pending structural completion, disabled coarse production, and
no retained failure or rejected command. A last published map must have a
unique nonsaturated generation and exactly `[S, S + 1,280,000)` representable
candidate-start support for the explicitly admitted shared-15 profile. Empty
history (`HAS_MAP=0`) is permitted only with zero generation/coordinates and
provides **no observed sample interval**.

The caller must separately admit the stop-capable firmware/geometry, bind the
receipt to serial/boot/observation, validate fresh health, and retain every map
through the returned generation. This method does not prove any of those facts.
A later fault or restart can invalidate a formerly successful immutable
receipt; do not reuse it in place of fresh evidence.

The endpoint is not the live ADC counter, the full FFT dependency endpoint,
or a pilot sample coordinate. For the 512/447 profile the FFT dependency is
`[B(S), B(E-1)+512)`, where `B` uses the separately established scheduler
origin. Stopping after host map N can finish at hardware map M greater than N.
Neither an empty ready mask nor a delivery counter proves all M generations
were retained by the host. Boundary completion does not imply RF health,
PSS lock, GLRT agreement, kernel drain, host persistence, or safe buffer closure.
