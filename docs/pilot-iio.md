# Experimental paired pilot IIO accounting

`pluto_plus.hardware.pilot_iio` parses `PIL1-1.0-upper-only` snapshots without
importing libiio or opening a radio. This is reusable offline tooling, **not** a
firmware promotion or evidence that paired pilot capture is hardware-qualified.
The single-RX ABI is separate from the production equal-rate dual-RX TAG2/HOPS
interfaces and does not alter their device exclusions or safety checks.

The FPGA exports 2.5 MS/s CI16 after decimation while the PHY stays at its full
15/30/60 MS/s source rate. One 120 ms valid capture is 300,000 complex samples,
1,200,000 bytes. FPGA coarse/fine PSS and the pilot stream share the source
sample counter. The signal-center coordinate of exported sample `j` is
`(first_newest_canonical_index + 6*j - 269) * source_rate_hz / 15000000`.
Upstream conditioner delay is already included in that counter convention;
do not subtract it again. Endpoint separation is `(N-1)/Fs`; exposure is `N/Fs`.

`PilotSnapshot.decode(text)` preserves known hardware, clipping, DMA and recovery
faults for diagnostics while rejecting malformed/unsupported or internally
inconsistent records. `require_complete_prefix(...)` additionally requires the
expected visit and source rate, a stopped/drained, fault-free, unclipped capture,
exact finite sample counts and the actual IIO reader's received byte count.
Passing it establishes a count/health gate for analysis, not IQ content, DDR
integrity, disk persistence, RF settling, a GLRT detection or FPGA PSS lock.

The eventual reader must independently attest serial/boot/session ownership,
bind snapshots to the exact buffer lifecycle, hash/persist the actual IQ bytes,
retain frequency/filter identities and every FPGA result, and use bounded waits
and explicit stop/drain/recovery. PIL1 itself contains no boot or serial identity.
Fault coordinates are diagnostic except for the narrowly documented output-FIFO
overflow case; they must not be relabeled as exact first-missing RF samples.

Live completion still requires blind host GLRT on the same capture (without
FPGA acquisition seeds) and qualified FPGA PSS timing agreement. Synthetic test
vectors, successful parsing, and byte-count agreement are not live-lock evidence.
Firmware remains on its do-not-merge branch; .18 must qualify before outdoor .17.

## Experimental shared-transform PSS companion

The paired 15 MS/s receiver candidate identifies its phase-map device as PSMA
ABI 1.5, capabilities `0x13f`. `PssIioClient.connect(...,
expected_serial=..., experimental_shared_xfft=True)` selects this exact
contract explicitly. The default remains the dedicated-transform ABI for each
legacy rate. Shared 30/60 MS/s, a missing expected serial, wrong capabilities,
wrong map geometry, and latched driver faults are rejected. Every returned map
chunk must match the ABI admitted from its IIO context, including legacy streams.

Offline `PssMapChunk.decode(..., allow_experimental_shared_xfft=True)` permits
the known 1.5 envelope; it does not attest hardware. `analyze_phase_maps(...,
rate_msps=15, experimental_shared_xfft=True)` retains the existing three-map
numerical algorithm and canonical source coordinates. Its 256 ms window is
still unsuitable for a single 120 ms hopping visit. No short-dwell sensitivity,
live lock, firmware promotion, or hardware qualification follows from this
additive host support. The matched kernel must reject shared-service health
bit 14 before exposing a map. Production TAG2/HOPS exclusions are unchanged.
