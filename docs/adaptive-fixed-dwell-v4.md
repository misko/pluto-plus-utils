# Adaptive scan fixed dwell v4

Protocol v4 selects exactly one dwell of 120, 240, or 360 ms before a scan.
Every complete visit in that scan has the same counter span and IQ length.
UNKNOWN, ACTIVE, QUIET, expired feedback, target weights, and consecutive
selection of one target affect scheduling only.

The host explicitly requests `SCANCAPS4 96`. It requires version 4, dual RX,
CI16, the 2.5 MS/s capability bit, dwell bounds 120..360, and all unchanged
limits. An unsupported command, malformed reply, different version, or setup
rejection fails the request. The host never substitutes v1/v2/v3 or a shorter
dwell.

The setup and visit layouts retain their sizes and carry version 4. Feedback,
acknowledgement, terminal, and counter-time records retain their existing
versions. A delivered visit must contain exactly
`floor(2_500_000 * dwell_ms / 1000)` sample periods and eight bytes per dual-RX
sample period. Truncated records fail qualification.

This initial contract is restricted to dual-RX 2.5 MS/s. Existing v1/v2
runtime-rate behavior remains available through its original negotiation and
does not imply v4 support.
