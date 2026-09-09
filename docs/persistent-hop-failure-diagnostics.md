# Failed persistent-hop iterator cleanup

`PersistentHopSession.failure_diagnostics` is an optional, read-only
`PersistentHopFailureDiagnosticsV1`. It is available after a failed decoded-IQ
iterator finishes its cancel/status/release attempt. It is **not** a capture,
cancellation, continuity, duty, or complete-restoration receipt. Existing
successful/cancelled receipt and wire formats are unchanged.

The snapshot contains:

- the requested session ID;
- a decoded, same-session terminal status, if one was obtained;
- the host lifecycle returned by the backend, if one was obtained;
- bounded cancellation/status, metadata-extension and release error strings.

A terminal status may explicitly contain a counter discontinuity or a failed
restoration. A missing lifecycle is not a successful restoration. Foreign,
nonterminal or malformed status is rejected rather than attached as terminal
evidence. The ordinary `receipt` property still raises if the IQ session did
not qualify. No missing samples are padded, no valid visit is fabricated, and
no failure snapshot is converted into a successful or cancelled recording.

The original iterator exception is re-raised as the same object and type.
Cleanup errors are attached as bounded Python exception notes, including both
errors when cancellation and backend release fail. A release exception no
longer replaces the primary counter/transport error. The optional detector
extension is failed independently before cleanup; its failure cannot prevent
the backend release attempt.

After such a snapshot is published, the PPU client is closed and must not be
cancelled again to try to obtain a normal receipt. This describes client
lifetime, not successful hardware restoration: callers must retain the
snapshot's cleanup errors and apply their external safety/restoration policy.

Scope: this snapshot covers `_decoded_blocks` failure cleanup, not every
possible startup, caller-side visit assembly, direct cancellation or successful
completion/release exception. These other paths retain their existing
semantics. The snapshot is an in-memory public adapter API; durable failure-IQ
publication remains the caller's separate responsibility.

The component tests inject an original IQ error or interruption, cancellation
failure, status-read failure, close failure, two simultaneous cleanup errors,
foreign/nonterminal status and failed restoration. They also retain a real
host-lifecycle object while proving that no IQ receipt is created. No radio,
firmware or FPGA operation is part of these tests.
