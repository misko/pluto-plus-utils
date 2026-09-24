# Adaptive scan variable dwell policy

The production launcher selects independently, once per radio and ten-minute
scan slot: 2.5 or 10 MS/s (equal probability), 120/240/360 ms active dwell
(equal probability). Domain-separated SHA-256 rejection sampling makes retries
reproducible. Gain remains manual at 40 dB on both receivers. The selected
lower/upper edge policy is unchanged.

Protocol v3 uses the existing record sizes and explicit `SCANCAPS3` negotiation.
Setup `dwell_ms` is the active base. Unknown, quiet, and expired-active targets
receive 120 ms. Applied ACTIVE feedback selects the configured base; QUIET
immediately returns to 120 ms even if the selection boost has not fully decayed.
The existing weighted target lottery remains unchanged. Weight does not multiply
one continuous visit; repeated selections provide multiples and retain the
existing same-target no-retune behavior. Actual visit start/end counters are
authoritative. V1/v2 retain their fixed dwell contracts.

The client refuses old firmware rather than silently falling back. Manual
gain is programmed on both receivers and read back. The pre-scan receiver settings and kernel buffers
are restored by the existing capture lifecycle. Archives record the selected
mode and dwell settings as well as actual receiver readback.

Use `run_v052_adaptive_live.py --dry-run` with the normal required paths to
inspect choices without RF access. Before production cutover, deploy the matching
v3 iiOD and the Leo variable-duration archive reader. A fixed-120-ms importer
must not consume these archives. Qualification uses bounded captures, at most
300 seconds each; the regular production slot remains 300 seconds.
