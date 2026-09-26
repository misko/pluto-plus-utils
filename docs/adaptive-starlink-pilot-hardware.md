# Adaptive Starlink pilot hardware gate

Every firmware release must run
`tests/hardware/test_adaptive_starlink_pilot_hardware.py` on each radio wired as
TX2 -> attenuator -> tee -> RX0/RX1. The test sends the published Qin lower-edge
pilot at 960 MHz, scans target 0 in adaptive dual-receiver mode at 2.5, 5, 7.5,
and 10 MS/s, and runs independent GLRT recovery on RX0 and RX1 at every rate. A
short two-target test proves recovery after a real Fast Lock hop away and back.

The same pytest then runs two consecutive 200-second protocol-v3 campaigns at
2.5 and 10 MS/s. Each campaign scans 960, 1210, 1460, and 1710 MHz with the
pilot injected only at 960 MHz. An asynchronous GLRT pool analyzes both RX0 and
RX1 for every complete visit without delaying IQ draining. Every injected-target
visit must pass the exact/control GLRT gate on both receivers; every visit to the
other three targets must be GLRT-negative on both receivers. Full level, SNR,
timing, and CFO parity remains the responsibility of the preceding four-rate
test. The long test fails if any visit is omitted from analysis, any target
receives no IQ, adaptive classification drops, or the campaign delivery gate
fails.

The default protocol is adaptive-scan v3. Set `PLUTO_ADAPTIVE_PILOT_PROTOCOL=1`
only when qualifying an older fixed-dwell image. The selected Python environment
must contain the release-local metadata runtime receipt and load its matching
native libiio.

Example for one wired release fixture with no physical attenuation credited:

```bash
export PLUTO_ADAPTIVE_PILOT_TARGETS='SERIAL@ip:192.168.1.18'
export PLUTO_ADAPTIVE_PILOT_PROTOCOL=3
export PLUTO_TX2_LOOPBACK_ATTENUATION_DB=0
export PLUTO_TX2_LOOPBACK_TX_GAIN_DB=-30
export PLUTO_ADAPTIVE_PILOT_REPORT="$PWD/adaptive-starlink-pilot.json"
export PLUTO_ADAPTIVE_PILOT_LONG_REPORT="$PWD/adaptive-starlink-pilot-long.json"
pytest -vv tests/hardware/test_adaptive_starlink_pilot_hardware.py
```

The test refuses unlisted serials, frequencies outside the authorized ~1 GHz
injection band, gain above -10 dB, or less than 30 dB of credited effective
attenuation. It requires both transmitters to be muted before entry and always
returns TX1/TX2 to -80 dB, disables DMA/DDS, closes the cyclic buffer, and
restores radio tuning on exit.

The release gate requires both receivers to distinguish the exact Qin pilot
from a symbol-rolled control and meet all of these parity bounds:

- GLRT score at least 0.35 and exact/control margin strictly greater than 0.5
  on each RX;
- fitted pilot SNR at least -20 dB and level between -70 and -3 dBFS (the
  exact/control GLRT is the presence decision at every rate);
- RX0/RX1 level delta at most 3 dB and fitted-SNR delta at most 4 dB;
- GLRT-score delta at most 0.20, timing delta at most four samples, and CFO
  delta at most 100 Hz;
- a passing adaptive campaign integrity gate at every rate, including the
  release-qualified greater-than-99% planned-valid delivery gate at 10 MS/s.

The JSON reports are release evidence and record both per-receiver GLRT results,
level/SNR/timing/CFO parity, adaptive delivery, radio identity, protocol, RF
frequency, sample rate, RF bandwidth, RX mask, TX path, and bounded TX gain.
The long report also retains per-visit decisions and metrics for all four scan
targets so a release reviewer can audit complete positive and negative coverage.

## v0.54 raw-IQ counter-marker incident

The v0.54 10 MS/s raw capture identifies counter-marker contamination as the
cause of the intermittent RX0 GLRT/residual anomaly; it is not evidence of RF
settling. In 215 of 236 retained visits, an eight-byte dual-RX CI16 row encodes
the little-endian 64-bit value `valid_start + row_index + 2` at a million-sample
cadence. For example, counter `597427418944` is the four little-endian signed
16-bit words `[-2240, 6514, 139, 0]`, which overwrite one simultaneous RX0/RX1
sample row.

An offline replay that detects those rows and interpolates across them changes
quiet visit 21's exact/control margin from 0.2088 to 0.0058 and injected-pilot
visit 203's margin from 0.4867 to 0.9005. This is a diagnostic only: the
original sample is overwritten and interpolation cannot recover it. The v0.58
report retained metrics but not raw IQ, so it cannot establish whether its
anomalies contain the same rows.

Native trace and RTL/DMA reconciliation identify the cause in
`ad9361_counter_acquire`. The FPGA consumes the interval from
`GP_CONTROL[31:1]`. The old driver wrote `N` samples per channel for both scan
masks. That is correct for single-RX, but dual-RX must program `2N`: writing
`N` in dual-RX makes the FPGA emit a counter marker every `N/2` packed rows.
For the one-million-sample request, markers were emitted every 500,000 rows.
The capture path strips the marker at each one-million-row DMA-block prefix,
but retains the interior 500,000-row marker; the retained corrupt rows therefore
appear one million rows apart. The corrected kernel programs `N` for single-RX
and `2N` for dual-RX, so every expected marker is a DMA-block prefix and is
stripped before IQ reaches the host.

The v0.59 source graph pins this correction and its mapping/bounds regression
coverage at Linux commit `a008394055c72ad88e45b30e0979d0e5f09642ec`
(`adaptive-multirate-agc-v059-source/linux-v2`). [Firmware PR
#118](https://github.com/misko/plutosdr-fw/pull/118) and its [immutable build
36215189374](https://github.com/misko/plutosdr-fw/actions/runs/36215189374)
produce the expected final identity
`v0.59-plutoplus-spf-dual-rx-counter-fix`.

A RAM-boot 10 MS/s raw-IQ preflight confirmed the source cause: the corrected
dual-RX register was `0x1e8480` (`2N` for one million samples per channel) and
found zero marker out-of-range-word visits in 46 visits, while the stock v0.54
comparison found 41 out-of-range-word visits in 46 visits. The standard
four-rate gate then passed at 2.5, 5, 7.5, and 10 MS/s, with final maximum
level parity delta 0.508715 dB and zero timing delta.

The first 10 MS/s long campaign did not satisfy the planned-valid delivery
gate (1,397 delivered of 1,549 planned, 90.187%) even though the GLRT and exact
counter invariant passed. That was a host observer throughput issue, separate
from the firmware counter cause: the observer decoded every complete 120 ms
dual-RX payload synchronously before retaining only the eight frames used by
GLRT. The full counter check accounted for 2.48 ms per visit; the old observer
averaged 13.55 ms and reached 55.5 ms. The bounded-decode change retains the
full-payload exact-counter check and decodes only the GLRT prefix. On the same
firmware and source plan, a 30-second 10 MS/s observer run delivered all 234
planned visits, versus 217 of 234 with the old GLRT observer. The second
200-second 10 MS/s campaign using the bounded observer passed the delivery
gate. The host fix is [PPU PR #133](https://github.com/misko/pluto-plus-utils/pull/133).

The final RAM-boot qualification ran both hardware tests in 429.61 seconds.
At 2.5 MS/s it delivered all 1,569 planned visits: 777 injected-target visits
were GLRT-positive on both receivers, 792 quiet visits were GLRT-negative on
both, and the exact-counter invariant and classification-delivery checks passed
for every complete payload. At 10 MS/s it delivered 1,534 of 1,548 planned
visits (99.0956%, strictly above the 99% gate); the 14 skips were explicit
capacity skips. All 746 injected-target visits were positive on both receivers,
all 788 quiet visits were negative, and there were zero counter-marker failures
and zero dropped classifications.

The long-campaign GLRT decision does not apply the four-rate SNR-parity bound.
Two 10 MS/s visits (873 and 1040) exceeded that bound at 4.666 dB and 4.606 dB
respectively; their level deltas were 1.69 dB and 1.67 dB, timing differed by
one sample, CFO deltas were 0.11 Hz and 0.06 Hz, and both receivers retained
approximately 0.999/0.998 GLRT scores with margins near 0.90. These SNR-parity
flags are retained as a limitation of the long campaign; the separate four-rate
gate remains the parity qualification. Future capture gates also record and
reject this exact marker pattern with its visit and row coordinates.
