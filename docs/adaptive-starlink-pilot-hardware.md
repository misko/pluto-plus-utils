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
anomalies contain the same rows. A native transport fix that prevents markers
from entering the IQ payload remains required; future capture gates should also
record and reject this exact marker pattern with its visit and row coordinates.
