# Local USB AD9361 Fast Lock prototype — 2026-08-27

> **Preliminary historical receipts.** These runs established that software Fast
> Lock works, but they predate the post-review timing hardening in the current
> source. The conventional-tune bracket included an empty
> `rx_destroy_buffer()` call, all conventional trials preceded all Fast Lock
> trials. Treat the 2.35x figure as indicative, not a final controlled latency
> ratio. The runs assume the selected local radios were otherwise idle; they do
> not claim exclusive ownership across radio transports.

## Outcome

Software Fast Lock worked on all four locally attached Pluto+ radios. Across 128
ordinary lower/upper LO writes and 128 Fast Lock recalls, the pooled host-observed
median fell from **1,374.8 us** to **585.8 us** (**2.35x faster**). These are USB
IIO attribute-write timings, not the AD9361's internal RF-lock time.

No `ip:` route was accepted or opened. In particular, production radios
`192.168.1.20` and `192.168.1.21` were not contacted. Each run used one exact
`usb:BUS.DEVICE.5` route and re-attested its full serial after opening.

## Workload

- Lower RX LO: 959.687500 MHz (Fast Lock profile 6)
- Upper RX LO: 1190.312500 MHz (Fast Lock profile 7)
- Separation: 230.625 MHz
- Per radio: 32 alternating ordinary writes, profile store/readback, then 32
  alternating Fast Lock recalls
- Host dwell: 1 ms after each operation
- RX buffer: never armed
- FPGA evidence: low-32 sample-counter read before and after each write
- Firmware: `v0.41-plutoplus-spf-tandem-agc-v8-rc20` on all four units
- Live workload duration: 0.73–0.91 seconds per radio; less than four seconds total

## Results

| USB serial | URI | Ordinary p50 / p95 | Fast Lock p50 / p95 | Median speedup | Counter-bracket p50, ordinary / Fast Lock |
|---|---|---:|---:|---:|---:|
| `1040007c…43ef2` | `usb:3.49.5` | 1,441.8 / 1,587.3 us | 577.0 / 758.9 us | 2.50x | 2.324 / 1.418 ms |
| `104000ba…003a` | `usb:5.51.5` | 1,292.2 / 1,521.7 us | 539.9 / 593.1 us | 2.39x | 2.098 / 1.339 ms |
| `winbond-db6208…172c` | `usb:5.49.5` | 1,343.1 / 1,438.7 us | 636.5 / 821.8 us | 2.11x | 2.178 / 1.518 ms |
| `winbond-db6968…402c` | `usb:3.47.5` | 1,478.2 / 1,601.1 us | 678.7 / 825.4 us | 2.18x | 2.375 / 1.622 ms |
| **Pooled, n=128/mode** | — | **1,374.8 / 1,597.0 us** | **585.8 / 806.3 us** | **2.35x** | **2.222 / 1.433 ms** |

The counter bracket is wider than the timed write because it includes the two
USB register-read transactions. It bounds the control operation on the running
FPGA counter but does not reveal the exact sample where the RF synthesizer locked.

## Restoration and safety evidence

Every unit began with and returned exactly to:

- RX LO 915 MHz
- sample rate 2.5 MS/s
- RF bandwidth 1.5 MHz
- RX0/RX1 enabled
- manual gain 40 dB

The exact restoration helper succeeded on its first 915 MHz request for all four
radios. An independent post-run read found Fast Lock inactive (`EINVAL` on active
profile), RX LO 915 MHz, and TX0/TX1 at -80 dB on every unit. All JSON receipts
are mode `0600`.

Profiles 6 and 7 are volatile but remain populated and inactive after each run.
The driver does not expose the prior initialized/uninitialized flag needed for a
lossless slot restoration, which is why the guarded command uses high profile
slots and requires an otherwise idle radio.

## Driver readback quirk

The active-profile attribute correctly alternated `6, 7, 6, 7, …` with zero
mismatches. The two stored sixteen-byte profiles were distinct and were captured
immediately after verified conventional tunes. However, while Fast Lock was
active, the ordinary LO-frequency attribute remained cached at the last
conventionally tuned upper frequency. Consequently, all 16 lower-profile recalls
per radio showed a stale ordinary-frequency readback. The prototype treats the
active profile plus stored profile bytes as authoritative and records the cached
frequency only as diagnostic evidence.

## What this establishes

- Current RC20 firmware and its AD9361 driver already expose usable software Fast
  Lock over local USB; no FPGA image or firmware flash was required.
- The present host path can issue a verified profile recall in roughly 0.5–0.8 ms
  typically, about twice as fast as a conventional calibrated LO write.
- Profile store/recall, exact serial binding, FPGA counter brackets, TX mute, and
  exact RX restoration can coexist in one bounded tool.

The current implementation now attests serial and sysfs path before mutation,
requires the FPGA counter to advance, and interleaves comparable bufferless
writes. It deliberately relies on the operator's idle-radio confirmation rather
than acquiring cross-transport ownership. These older JSON files do not contain
the newer timing and assumption fields and were intentionally not rewritten.
They remain immutable control-plane-v1/schema-v1 evidence.

The controlled schema-v2 rerun on `1040007c…43ef2` used balanced O-F-F-O cycles
after warmup. Its ordinary median was **1,570.1 us**, its Fast Lock median was
**750.3 us**, and its median speedup was **2.09x** across 32 hops per mode. The
complete workload lasted 0.88 seconds and restored the original settings.

## What it does not establish

- No IQ buffer was armed, so this does not measure first-valid post-hop IQ or PLL
  lock time.
- The low-32 counter does not by itself mark the switch instant.
- Cross-hop carrier phase is not preserved or measured.
- A 230.625 MHz synthetic-aperture TOA estimate is not yet justified.
- Metadata ABI 2 cannot currently be armed at the same time: tandem metadata owns
  the PHY, and the driver returns `EBUSY` for LO/Fast-Lock writes while that owner
  is active.

If the 585.8 us pooled median stayed unchanged, it would span about 17,600 samples
at 30 MS/s or 35,200 samples at 60 MS/s. That is only a wall-time conversion, not
a measurement at those rates. The next truthful experiment needs a firmware event
that records profile ID and the counter value at the actual recall/lock boundary,
or an external RF marker. Hardware-pin Fast Lock is another route, but the current
CTRL_IN pins are occupied by tandem AGC and would require an explicit HDL/device-
tree design change.

## Receipts

- [`full-1040007c.json`](full-1040007c.json)
- [`full-104000ba.json`](full-104000ba.json)
- [`full-winbond-db6208.json`](full-winbond-db6208.json)
- [`full-winbond-db6968.json`](full-winbond-db6968.json)
- [`smoke-1040007c.json`](smoke-1040007c.json)
- [`v2-assume-idle-1040007c.json`](v2-assume-idle-1040007c.json)
