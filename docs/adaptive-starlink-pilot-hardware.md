# Adaptive Starlink pilot hardware gate

Every firmware release must run
`tests/hardware/test_adaptive_starlink_pilot_hardware.py` on each radio wired as
TX2 -> attenuator -> tee -> RX0/RX1. The test sends the published Qin lower-edge
pilot at 960 MHz, scans target 0 in adaptive dual-receiver mode at 10 MS/s, and
runs independent GLRT recovery on RX0 and RX1. A second 1.19 GHz target proves
that the signal is recovered after a real Fast Lock hop away and back.

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
pytest -vv tests/hardware/test_adaptive_starlink_pilot_hardware.py
```

The test refuses unlisted serials, frequencies outside the authorized ~1 GHz
injection band, gain above -10 dB, or less than 30 dB of credited effective
attenuation. It requires both transmitters to be muted before entry and always
returns TX1/TX2 to -80 dB, disables DMA/DDS, closes the cyclic buffer, and
restores radio tuning on exit.

The release gate requires both receivers to distinguish the exact Qin pilot
from a symbol-rolled control and meet all of these parity bounds:

- GLRT score at least 0.35 and exact/control margin at least 0.15 on each RX;
- fitted pilot SNR at least 0 dB and level between -70 and -3 dBFS;
- RX0/RX1 level delta at most 3 dB and fitted-SNR delta at most 4 dB;
- GLRT-score delta at most 0.20, timing delta at most four samples, and CFO
  delta at most 100 Hz;
- adaptive 10 MS/s / 120 ms planned-valid delivery above 99%.

The JSON report is release evidence and records both per-receiver GLRT results,
level/SNR/timing/CFO parity, adaptive delivery, radio identity, protocol, RF
frequency, sample rate, RX mask, TX path, and bounded TX gain.
