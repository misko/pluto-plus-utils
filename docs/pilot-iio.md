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

The paired recording orchestrator must independently attest ownership and boot,
persist the actual IQ bytes, retain frequency/filter identities and every FPGA
result, and join the pilot and PSS records by their actual source support. The
finite reader below provides the pilot buffer lifecycle, not this orchestrator.
PIL1 itself contains no boot or serial identity.
Fault coordinates are diagnostic except for the narrowly documented output-FIFO
overflow case; they must not be relabeled as exact first-missing RF samples.

Live completion still requires blind host GLRT on the same capture (without
FPGA acquisition seeds) and qualified FPGA PSS timing agreement. Synthetic test
vectors, successful parsing, and byte-count agreement are not live-lock evidence.
Firmware remains on its do-not-merge branch; .18 must qualify before outdoor .17.

## Explicit finite reader

`PilotIioClient` is a bounded first-stage reader for the experimental PIL1 device,
not the persistent 300-second hopping recorder. It requires an explicit URI and
exact expected serial, verifies every available serial alias in the context,
and rejects the legacy raw/dual-RX interface. It does not discover radios,
acquire the caller's serial-specific ownership lease, retune the PHY, enable TX,
or flash firmware. It keeps the existing PSS map restart protection unchanged.

After separately qualifying the image and acquiring the exact .18 radio lease:

```python
from pluto_plus.hardware.pilot_iio import PilotIioClient

with PilotIioClient.connect(
    "ip:192.168.1.18",
    expected_serial="1040007c4a94000211000b009186843ef2",
    source_rate_hz=15_000_000,
) as pilot:
    capture = pilot.capture(visit_id=17)  # 300000 samples, twelve 25000-sample refills
    # Persist capture.iq, capture.iq_sha256 and its snapshots with the paired
    # session/visit manifest before running independent host GLRT.
```

The reader verifies the upper-only ABI, ordered signed LE16 I/Q channels, the
2.5 MS/s export rate, and the separate FPGA/actual-PHY source rate. Finite sample
limits must be divisible by the refill length, and refill lengths must be even
to align to an eight-byte paired DMA beat. The public buffer byte length and
stride must agree with the request; an exposed binding sample count is checked
but never rewritten. Buffer construction invokes the matched kernel's
DMA-submission-before-ARM ordering. The host never writes an ARM register itself.

Each successful result retains the actual IQ bytes and SHA256, context serial,
host-generated session UUID, visit, source/output rates, and before/armed/final
snapshots. The reader checks the final complete finite count/health gate before
and after buffer destruction, then restores and reads back the original
visit/limit attributes and scan selection. Multiple finite pilot captures can
share one context; that does **not** authorize reopening the separate PSS map
stream within its reset epoch.

Memory is bounded to one second of requested IQ (2.5 million complex samples,
10 MB); a normal 120 ms result is 1.2 MB. The default overall capture deadline is
5 seconds and each IIO operation has a timeout of at most 1 second. The initial
libiio context constructor uses the library's connection timeout; recovery has
its own finite per-operation timeout budget after the capture deadline.
`cancel()` is cooperative: it is checked between operations and after refills,
so an outstanding read ends or times out before ordinary destruction.

Native `Buffer.cancel()` is deliberately **not** used during ordinary cleanup:
the network backend's cancellation path can skip acknowledged remote CLOSE.
Direct destruction preserves the matched driver's STOP → drain → DMA-abort
ordering. A terminal snapshot and direct-mode configuration restoration are
required afterward; an unavailable or failed cleanup receipt invalidates the
capture. Mid-descriptor hardware faults may yield no partial IIO buffer at all.
`PilotCaptureError` preserves already-received bytes, available snapshots, and
cleanup errors; the failed client cannot capture again without reconnection.

The optional `expected_boot_id` is checked against a context `boot_id` attribute;
if unavailable it cannot be invented from the serial or host session UUID.
Context attributes do not constitute a continuously authenticated boot/firmware
attestation. The external owner must supply that deployment evidence.
`upstream_health_qualified`, `live_signal_qualified`, and `disk_persisted` remain
false: PIL1 does not expose all upstream conditioner/PSS health, does not prove
RF settling or timing lock, and this API only hashes/retains IQ in memory.
The finite-reader tests use an IIO lifecycle model, not an actual DMA engine,
Ethernet link, or radio. Real .18 qualification is still required.

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

A chunk-zero restart while a previous map is incomplete is now an explicit
error naming the abandoned generation. It cannot silently erase a negative or
missing visit. Intentional hop-boundary discards still require an explicit
reset plus a recorder-owned discard receipt; this parser change does not add
the future persistent hop lifecycle.
