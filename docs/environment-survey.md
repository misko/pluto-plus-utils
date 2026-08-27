# Frozen RX-only environment survey contract

This Stage-1 workflow chooses one reproducible 2.4 GHz receive control for four
reserved Pluto+ radios in an RF-enclosed fixture. It uses local USB-IIO only;
the Pluto never transmits. Acquisition and DSP parameters are fixed rather than
CLI-tunable.

## Safety and ownership

Planning is passive. It binds one exact serial, direct sysfs topology,
bus/device address, interface-5 USB-IIO URI, clean `pluto-plus-utils` commit,
private result root, and a hash-pinned worst-normal emitter inventory. It never
opens IIO. Execution requires the exact printed plan SHA-256, confirmation, and
a second explicit `--ensure-mute` authorization. Every command that claims the
tool source also proves its imported `pluto_plus` package is the tracked
`src/pluto_plus` tree inside that exact clean checkout and HEAD.

Each radio execution does the following in order:

1. Validate the canonical mode-0600 plan against the separately supplied
   SHA-256, clean tool commit/source, confirmation, and mute authority before
   hardware access.
2. Require at least `5,368,709,120` free bytes (5 GiB) in that radio's result
   filesystem.
3. Acquire the user-scoped per-serial nonblocking lock. Its default path is
   `/tmp/pluto-plus-utils-radio-locks-UID/radio-SHA256.lock`, where the key is
   SHA-256 of the stripped UTF-8 serial. The mode-0700 directory and owned
   mode-0600 regular lock file are verified; the exclusive `flock` is held for
   the entire USB session.
4. Revalidate serial, topology, bus/device address, Pluto+ identity, and USB
   interface count from sysfs, then open only `usb:BUS.DEVICE.5`.
5. Before any mutating open, require and retain both TX gains; TX buffer, data,
   and scan-mask state; all eight DDS raw/scales; all four DAC selectors; and tandem
   state, FIFO level, faults, and overflow count.
6. Apply the controlled mute and require both gains at or below -80 dB, no TX
   buffer/data/scan ownership, zero DDS raw/scales, all selectors equal to 3
   (FPGA ZERO), and tandem IDLE/FIFO0/fault0/overflow0.
7. Open RX, re-attest that complete predicate, snapshot RX settings, and capture
   the frozen matrix.
8. Destroy the RX buffer, search only the proven bounded ±16 Hz nearby LO write
   requests needed
   to reproduce the exact original LO readback, restore the original RX channel
   subset/modes/shared settings and each manual gain exactly, reapply the mute,
   and retain final safety evidence. An automatic-gain readback remains evidence
   but is not compared as settable state because AGC changes it dynamically.
9. Publish each completed center atomically; discard its private staging tree on
   any failure, then publish a durable typed manifest and receipt. Verification
   rejects every undeclared file or directory.

Cleanup uncertainty fails closed. The cooperative lock cannot exclude software
that ignores it, so unrelated IIO processes must be stopped first. The workflow
contains no SSH, route, DFU, reboot, QSPI, firmware-write, or TX-enable path.

## Hash-pinned emitter inventory

The required private canonical JSON schema is
`pluto-plus-utils.environment-survey-emitter-inventory.v1`. Its exact root keys
are `schema`, `schema_version`, `state`, and `emitters`; `state` is
`worst-normal`. Emitters are nonempty and sorted uniquely by `emitter_id`, with
exact keys:

```json
{"emitters":[{"band":"2.4-ghz","center_hz":2437000000,"channel":"6","channel_width_hz":20000000,"emitter_id":"internal-ap-24","occupied_start_hz":2427000000,"occupied_stop_hz":2447000000,"power_setting":"normal","traffic_state":"worst-normal"}],"schema":"pluto-plus-utils.environment-survey-emitter-inventory.v1","schema_version":1,"state":"worst-normal"}
```

Every record also permits band `5-ghz`. Integer physical fields are positive,
`occupied_start_hz < occupied_stop_hz`, and the center lies inside the closed
occupied span. At least one 2.4 GHz emitter is required; each 2.4 span intersects
the survey grid. The projected 2.4 spans are sorted and must neither overlap nor
touch (`next.start > previous.stop`). Five-GHz emitters remain bound context but
do not affect 2.4 GHz selection. Inventory bytes and SHA-256 are captured once
during planning and embedded in the plan; execution does not reread the source.

## Frozen capture matrix and chronology

The exact order is:

1. 32-window pre-anchor at 2.445 GHz;
2. 91-center sweep from 2.400 through 2.490 GHz inclusive in 1 MHz steps;
3. 32-window TX-muted authorizing baselines at 1.05, 1.55, 2.05, and 5.8 GHz,
   in that order; and
4. 32-window post-anchor at 2.445 GHz.

Both anchors therefore bracket every acquisition. The selected 2.4 GHz
per-radio/RX baseline derives from its sweep center; there is no redundant
fifth baseline capture.

| Setting | Frozen value |
| --- | ---: |
| Sample rate | `2,500,000 samples/s` |
| RX RF bandwidth | `1,500,000 Hz` |
| Gain | manual `40 dB`, RX0 and RX1 |
| Settling | `2` discarded buffers after each tune |
| Retained windows | `32` per center |
| Samples | `65,536` complex samples/RX/window |
| FFT / hop | `4,096` / `2,048` samples |
| Frames/window | `31` |
| Total windows/radio | `3,104` |

Each window retains little-endian CI16 `[65536,2,2]` in
`[sample, RX0/RX1, I/Q]` order, a little-endian float32 Welch PSD
`[2,4096]`, and little-endian float32 per-frame STFT
`[2,31,4096]`. Both spectral products are full fftshifted log-density in
dBFS/Hz. Every artifact has an exact path, size, shape, dtype, and SHA-256.

Each 32-window block also retains paired-RX settings readbacks immediately
after configuration and immediately after its final window. Both must show LO
within 2 Hz of the center, sample rate exactly 2.5 MHz, RF bandwidth exactly
1.5 MHz, RX0/RX1 both manual, and each gain within 0.26 dB of 40 dB. There are
no per-window attribute reads, so this gate does not perturb capture cadence.
The scalar sample rate and bandwidth are explicitly shared-PHY values; each
readback enumerates and checks every raw `ad9361-phy` RX channel exposing
`sampling_frequency` or `rf_bandwidth`. A required shared `temp0/input`
millidegree-C reading is retained beside both settings readbacks; missing or
out-of-range temperature fails the block.

The pre-survey snapshot is intentionally broader than the paired capture gate:
it accepts the canonical original enabled-channel subsets RX0, RX1, or RX0+RX1.
Cleanup must restore the exact subset, LO, shared sample rate/bandwidth and their
raw-attribute provenance, per-channel gain modes, and gains for channels that
were originally manual. Observed automatic-mode gains are retained before and
after cleanup but are not equality-gated because they are live AGC output, not a
restorable setting.

All four authorizing baselines and both anchors must be unclipped. The 5.8 GHz
baseline is fixed context/preflight and can never waive a later 5.8 GHz release
failure.

## Deterministic DSP and JSON metrics

Analysis starts from retained CI16. For `N=4096`, `Fs=2,500,000`, and
`n=0,...,N-1`, use the periodic Hann

```text
w[n] = 0.5 - 0.5*cos(2*pi*n/N)
D[k] = |fftshift(FFT(x*w))[k]|^2 / (Fs * sum(w^2) * 2048^2)
```

`sum(w^2)=1536`. The 31 frame densities are averaged in linear units for the
Welch PSD. STFT and PSD files contain `10*log10(D)`; an exact zero density may
be retained as float32 negative infinity. Bin width is `610.3515625 Hz`; the
first shifted offset is -1.25 MHz.

Per-window integrated full-scale power sums Welch density times bin width for
bin centers in the closed interval +/-750 kHz. It must be finite and strictly
positive. JSON retains that linear value and its finite
`10*log10(power)` dBFS value; NaN, infinity, zero, and negative integrated
powers are rejected.

For each receiver/center, NumPy Type-7 (`method="linear"`) p50/p95/p99 are
computed over the 32 **linear** integrated powers, then converted to dBFS. A
burst is strictly `power > linear_p50 * 10^(6/10)`; occupancy is the burst
fraction. A complex sample clips when `abs(I)>=2047` or `abs(Q)>=2047`, matching
the AD9361 12-bit code convention despite the CI16 container.

## Per-radio and fleet selection

For every declared 2.4 GHz emitter span `[start,stop]`, selection expands it to
`[start-750000,stop+750000]`. A candidate's closed occupied band is
`[center-750000,center+750000]`; endpoint contact counts as intersection. A
per-radio candidate is eligible only outside the expanded union and with zero
clips across both RX paths and all 32 windows. Local ranking is
`(max RX p99 dBFS, max RX occupancy, center_hz)`.

The full survey runs independently under a separate serial-scoped result root
and 5 GiB gate for these exact serials, in order:

1. `winbond-db6968136727402c`
2. `1040007c4a94000211000b009186843ef2`
3. `winbond-db620818a328172c`
4. `104000bac4950008230026001b440a003a`

The offline fleet selector consumes both the matching PASS receipt and manifest
for each serial. It re-verifies plans, tool source, cleanup/safe-state evidence,
inventory binding, every artifact hash, and raw-to-spectral/statistical
derivation. A global candidate must be AP-eligible and unclipped across all
four radios/eight RX paths. It ranks lexicographically by
`(max p99 over all radio/RX, max occupancy over all radio/RX, center_hz)` and
retains the selected sweep baseline for every radio/RX. No emitter-off or other
repeat is part of this authorizing workflow.

## Drift and storage gates

Pre/post drift is the maximum absolute p99 difference and maximum absolute
occupancy difference across RX0/RX1. Both use the independent 32-window anchor
statistics. Pass limits are inclusive: p99 <=3.0 dB and occupancy <=0.10, with
zero anchor clipping.

| Per-radio evidence | Bytes | MiB |
| --- | ---: | ---: |
| Raw dual-RX CI16 | `1,627,389,952` | `1,552` |
| Full PSD + STFT f32le | `3,254,779,904` | `3,104` |
| Fixed artifact payload | `4,882,169,856` | `4,656` |
| Failure flush reserve | `67,108,864` | `64` |
| Payload + reserve | `4,949,278,720` | `4,720` |
| Manifest allowance preserved during capture | `419,430,400` | `400` |
| Initial free-space gate | `5,368,709,120` | `5,120` |

The reserve is not preallocated and covers the bounded manifest+receipt failure
flush. Before every center, available space must remain at least the exact
uncaptured payload plus the 64 MiB failure reserve plus the full 400 MiB manifest
allowance. These three terms equal the initial 5 GiB gate before the first block.

## CLI workflow

Create a canonical mode-0600 inventory beneath an owned mode-0700 directory and
record its SHA-256. Create and execute one plan per radio, each with its own
result root:

```bash
uv run pluto environment-survey plan \
  --serial EXACT_SERIAL \
  --usb-path /sys/bus/usb/devices/3-7 \
  --emitter-inventory /private/chamber/emitter-inventory.json \
  --emitter-inventory-sha256 EXACT_SHA256 \
  --result-root /private/pluto-surveys/EXACT_SERIAL \
  --output /private/pluto-survey-plans/EXACT_SERIAL.json \
  --ensure-mute

uv run pluto environment-survey execute \
  --plan /private/pluto-survey-plans/EXACT_SERIAL.json \
  --expected-plan-sha256 EXACT_PLAN_SHA256 \
  --ensure-mute \
  --confirm 'EXECUTE RX ENVIRONMENT SURVEY EXACT_SERIAL SURVEY_ID'

uv run pluto environment-survey receipt-verify \
  /private/pluto-surveys/EXACT_SERIAL/SURVEY_ID/receipt.json
```

After all four PASS:

```bash
uv run pluto environment-survey fleet-select \
  --manifest RADIO1/manifest.json --receipt RADIO1/receipt.json \
  --manifest RADIO2/manifest.json --receipt RADIO2/receipt.json \
  --manifest RADIO3/manifest.json --receipt RADIO3/receipt.json \
  --manifest RADIO4/manifest.json --receipt RADIO4/receipt.json \
  --emitter-inventory /private/chamber/emitter-inventory.json \
  --emitter-inventory-sha256 EXACT_SHA256 \
  --output /private/pluto-surveys/fleet-selection.json

uv run pluto environment-survey fleet-verify \
  /private/pluto-surveys/fleet-selection.json
```

## Scope limit

Ambient RX evidence cannot measure later TX2-to-splitter-to-RX fixture loss.
Loopback attenuation still needs independent verification on both paths at each
release center, especially 5.8 GHz.
