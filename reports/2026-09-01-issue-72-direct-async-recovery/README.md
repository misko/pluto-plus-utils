# Issue #72 direct-async recovery qualification

## Outcome

Firmware `v0.48-plutoplus-spf-iq-direct-async-v3` fixes the long-session
`ENODATA` failure reproduced on v0.47. Under a deliberately overloaded USB
Ethernet path, the candidate returned every requested frame in both 10-second
and 60-second sessions. Over physical 1 GbE, the 47-frame direct DMA queue
delivered 73.06, 75.07, and 72.86 MB/s for 3-, 10-, and 60-second 25 MS/s
captures. The 60-second result is one 1,431-frame, 6.002 GB session; it did not
segment or re-arm.

![Issue 72 recovery summary](issue-72-recovery-summary.png)

This is a capture-completion and loss-accounting result. A 25 MS/s CI16 source
offers 100 MB/s, so gaps remain whenever the consumer is slower. The fix does
not fabricate continuity: every discontinuity remains represented by the FPGA
sample counter and `missing_sample_count`.

## Root cause and fix

The SPF gain/RSSI timeline has a finite coverage window. During a long direct
session under backlog pressure, a DMA frame can age beyond that coverage before
iiOD asks the metadata provider to describe it. V0.47 returned `ENODATA` for
this condition and the direct producer treated it as terminal, ending the host
request even when `drop-backlog` was selected.

The v0.48 stack makes the condition explicit and recoverable:

1. the SPF provider returns `ESTALE` when either gain or RSSI coverage is no
   longer available for a real IQ frame;
2. in `drop-backlog` mode, iiOD retires the uncovered frame, frees every
   queued-but-unsent frame, and continues filling the same finite request;
3. the in-flight TCP frame is never withdrawn, and the host target is not
   shortened;
4. a valid frame resets the stale streak; more than `DMA capacity + 8`
   consecutive stale frames still fail closed with `ESTALE`; and
5. host libiio snapshots terminal status before cancelling a failed direct
   socket, so PPU can report the radio's last status after an exception.

`preserve-backlog` remains fail-closed when metadata cannot be proven. The
status reason currently uses the protocol's broad `dma_error` bucket, while
the exact `error_code=-116` identifies `ESTALE`.

## Exact tested stack

| Component | Exact tested version |
| --- | --- |
| firmware integration | `322b67f9580d215c1f8362735c877f7c5ee2f89e` |
| Buildroot/rootfs | `1c337a0b8d8126c9d1ed785607bc5ea52e7fed22` |
| radio iiOD and host libiio | 0.25 at `0d323080a0a1067da8c7adbadfd03ee186a40ec2` |
| PPU terminal-status/runtime pin | `7ff398aa67b36f5b5f3978153674c1b46c836110` |
| PPU 200 MB DMA ladder guard | `7d412dfc60f7ad58601092b7332b21a74d5a3ff0` |
| SPF metadata provider | ABI 3, `3294365ff44da26b261be4a2ccb241b7896d23ad` |
| HDL | `145bd47e55d5c5537e0ba49d53cb25a5393f66ba` |
| Linux | `93174a1c049ca6ee42f042dbe93f0fb06fbc9cd7` |
| U-Boot | `1ff0468e9bea29b0a768a7bf52db8d025c521b9a` |

The tested DFU SHA-256 is
`4f981697af03a2c8fe041c7c5a932da7ce0cf66bf78e24518f7574e3738ac6a4`;
its FIT body is
`958e4e1d3f128bd3c90c449d674ef7f79c23afebcb23f1af9627c8e6f6f93d7e`.
The image reports `--rw-cpu-affinity 1`, which is the supervised equivalent of
the historical `iiod -r 1` shorthand.

Host ABI 3 must use the matching native library and generated Python binding:

```bash
scripts/install_native_libiio.sh \
  --uv-bin "$HOME/.local/bin/uv" \
  --metadata-abi 3
uv run pluto environment
```

The expected environment line is `libiio version 0.25 (0d32308)`. The installer
fetches the full immutable SHA and writes a content-bound runtime receipt; PPU
rejects a different loaded library even if its version string looks similar.

## Red/green long-session result

Both runs used 25 MS/s, 1,048,576 samples/frame, 11 DMA frames, 32 RAM slots
(128 MiB), `drop-backlog`, and the same local USB Ethernet path.

| Firmware | Window | Result | Payload | Gap frames | Missing samples |
| --- | ---: | --- | ---: | ---: | ---: |
| v0.47 | 10 s | 239/239 | 19.783 MB/s | 30 | 904,921,088 |
| v0.47 | 60 s | **terminal `ENODATA`** | — | — | — |
| v0.48 | 10 s | 239/239 | 19.827 MB/s | 35 | 921,698,304 |
| v0.48 | 60 s | **1,431/1,431** | 19.517 MB/s | 218 | 6,063,915,008 |

The USB link intentionally cannot keep pace. Success here means that v0.48
kept one direct session alive, returned the finite target, and accounted for
loss instead of aborting.

## Twenty-second policy matrix

| Queue | Policy | Result | Gap frames | Missing samples | Payload |
| --- | --- | --- | ---: | ---: | ---: |
| 11 DMA | preserve | 477/477 | 464 | 1,715,470,336 | 22.053 MB/s |
| 11 DMA | drop | 477/477 | 118 | 1,734,344,704 | 21.981 MB/s |
| 11 DMA + 128 MiB RAM | preserve | **`ESTALE` after 114 frames** | — | — | — |
| 11 DMA + 128 MiB RAM | drop | **477/477** | 68 | 1,880,096,768 | 19.659 MB/s |

Ringless drop mode reduced the number of gap-bearing frames by 74.6%. With RAM,
drop mode converted a terminal preserve failure into a complete capture. It did
not reduce missing sample count: dropping the stale queue intentionally creates
fewer, larger discontinuities and returns to fresher RF time sooner.

RAM slots extend the existing ordered queue. They do not create a second DMA
session, and reaching RAM high-water does not clear the in-flight TCP frame or
re-arm capture.

## Physical-GbE performance

The full RAM-ring ladder was gap-free through 15 MS/s. At 25 MS/s, RAM copies
limited the 3- and 10-second cells to 69.42 and 60.25 MB/s. That configuration
therefore failed the 70 MB/s performance gate even though it completed both
requests.

The intended performance profile is ringless with 47 × 4 MiB DMA frames:
197,132,288 bytes, below the radio's 200,000,000-byte advertised limit. PPU
commit `7d412df` replaces an obsolete 64 MiB host-only guard and still rejects
48 frames (201,326,592 bytes) before opening the radio.

| Window | Returned | Payload | Gap frames | Missing samples |
| ---: | ---: | ---: | ---: | ---: |
| 3 s | 72/72 | **73.063 MB/s** | 2 | 20,971,520 |
| 10 s | 239/239 | **75.070 MB/s** | 7 | 72,351,744 |
| 60 s | 1,431/1,431 | **72.860 MB/s** | 53 | 550,502,400 |

Example PPU-only performance command for a newly flashed radio:

```bash
uv run pluto radio direct-async-ladder RADIO_IP \
  --transport ip \
  --expect-serial RADIO_SERIAL \
  --rates 25M \
  --durations 3,10,60 \
  --channels rx0 \
  --samples 1048576 \
  --kernel-buffers 47 \
  --ram-ring-slots 0 \
  --drop-backlog-on-overrun \
  --tandem-mode hold \
  --iq-decoder pyadi \
  --format json \
  --report "$PRIVATE_REPORT_DIRECTORY/25m-k47-drop.json"
```

For the complete lower-rate ladder, replace `--rates 25M` with
`--rates 5M,10M,15M,25M` and use `--durations 3,10`.

## Fleet and compatibility checks

The exact DFU was RAM-booted with PPU on four serial/path-bound local USB
radios. Every receipt attested v0.48, AD9361, and TX-safe state without writing
QSPI. Each radio then returned 15/15 frames at 5 MS/s over USB with zero gaps,
zero missing samples, and zero overflow; payload rates ranged from 17.956 to
18.083 MB/s.

On serial `winbond-db6968136727402c`, ordinary dual-RX capture kept pace at
2.5 and 5 MS/s (20.012 and 40.046 MB/s). A bounded PPU Fast Lock probe tuned
ordinary and volatile-profile paths between 2.4 and 5.8 GHz, verified the
5.8 GHz ordinary readback, kept TX muted, and restored the exact original RF
settings.

## Reproduction and retained data

[`data.json`](data.json) is the compact canonical input to
[`plot_recovery_summary.py`](plot_recovery_summary.py). Regenerate the figure
from the repository's locked environment:

```bash
uv run --with matplotlib python \
  reports/2026-09-01-issue-72-direct-async-recovery/plot_recovery_summary.py
```

Raw PPU reports and serial-bound deployment/isolation receipts remain in the
private qualification archive. They are intentionally not copied into the
public repository because they contain host topology and local absolute paths.
