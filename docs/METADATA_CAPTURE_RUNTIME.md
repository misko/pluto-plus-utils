# Metadata capture runtime and lifecycle

`IioRadioDevice.begin_metadata_capture()` is intentionally unavailable through
stock pylibiio. The radio firmware, native libiio, and Python binding form one
matched metadata ABI. Loading `/usr/lib/libiio.so.0` with the PyPI binding does
not make continuity observable and must not be accepted as a fallback.

## Matched runtimes

| Radio capability | Metadata header | Host source tag | Exact commit |
| --- | --- | --- | --- |
| `iio,buffer-metadata=1` | strict `RadioMetadataV3` | `spf-frame-metadata-source/v0.25-final-v3` | `c26258bfa33098c2b215e19cf85d448e89499b1a` |
| `iio,buffer-metadata=2` | strict `RadioMetadataV5` | `tandem-agc-v8-rc2-source/libiio-v1` | `6305ea1d43436ff8bdd83aa6c9e5abf7244aa5f7` |
| `iio,buffer-metadata=3` | strict `RadioMetadataV6` | `iq-direct-async-v2-source/libiio-v1` | `8f66f353c9a70a5524988ceb588b0e9271c2390d` |
| `iio,buffer-metadata=3` plus `iio,buffer-metadata-abi-versions=1,2,3,4` | strict `RadioMetadataV7` selected as ABI 4 | gain-timeline v8 release source | frozen by the release candidate plan |

The released direct-async v2 firmware advertises ABI 3. Radios still running an
older release may advertise ABI 1 or 2; the host must select from the radio's
attested capabilities rather than choosing a newer parser only because it is
available.

ABI 3 is the additive single-RX release. The radio must also advertise the
exact capability string
`00000003:1:4:2,0000000c:1:4:2,0000000f:2:8:1`: RX0 and RX1 use four bytes
per sample with an even sample count, while dual RX uses eight bytes per sample.
V6 records arbitrary FPGA-counter gaps exactly; ABI 1/2 parsing and geometry
remain unchanged.

ABI 4 uses additive negotiation so old hosts remain operational: the legacy
scalar stays at ABI 3, while a new host must parse the canonical version set
and explicitly select ABI 4 before buffer creation. A missing, malformed,
non-increasing, or scalar-inconsistent version set is an admission failure for
ABI 4; ABI 1-3 firmware that has no version-set attribute continues to use its
legacy scalar unchanged.

ABI 3 also supports an opt-in, per-buffer device-DDR cache when the radio
advertises `iio,buffer-ddr-burst=1`. A zero or omitted byte budget is the
ordinary streaming path. A positive budget is rounded down to complete IQ
frames and its requested/admitted geometry is observable from Python:

```python
with radio.begin_metadata_capture(
    samples_per_refill,
    kernel_buffers=4,
    ddr_burst_bytes=100_000_000,
) as capture:
    assert capture.ddr_burst_enabled
    print(capture.ddr_burst_admitted_bytes, capture.ddr_burst_frames)
    blocks = [capture.read_block() for _ in range(capture.ddr_burst_frames)]
```

The burst cache is supported only for one selected receiver. It captures the
admitted whole frames before exposing the first refill, rejects discontinuity
or overflow atomically, and drains through the same metadata/IQ refill API as
an ordinary buffer. `radio metadata-ladder --ddr-burst` qualifies that path;
omitting the flag is the explicit control case.

ABI 3 additionally supports the optional streaming DDR ring when the radio
advertises `iio,buffer-ddr-ring=1`, the exact modes `finite,continuous`, and
`iio,buffer-metadata-status=1` or `2`. ABI 4 keeps the legacy scalar at `1` and
requires `iio,buffer-metadata-status-versions=1,2`, selecting status V2; ABI 3
continues to use the V1 wire status. Ring and burst capture each require
one selected receiver. Unlike a sealed burst, a ring producer and the
ordinary IIO consumer run concurrently. The first committed frame is eligible
for transport immediately; iiOD has no startup prefill or low-water rebuffering
phase. During a longer capture, unread ring frames are
never overwritten; if finite DDR plus the kernel queue cannot absorb sustained
source-versus-transport pressure, later IQ gaps are carried explicitly by ABI 3
metadata instead of terminating the capture. Capacity is independent of capture
length:

```python
with radio.begin_metadata_capture(
    samples_per_refill,
    kernel_buffers=4,
    ddr_ring_bytes=100_000_000,
    ddr_ring_frames=50,
) as capture:
    blocks = [capture.read_block() for _ in range(capture.ddr_ring_capture_frames)]
    status = capture.ddr_ring_status()
    assert status["state"] == "complete"
    assert status["produced_frames"] == status["consumed_frames"] == 50
```

Set `ddr_ring_continuous=True` and leave `ddr_ring_frames=0` for a stream that
runs until buffer close/cancel. A zero `ddr_ring_bytes` selects the unchanged
ordinary IIO path. DDR ring and sealed DDR burst are mutually exclusive.
`radio metadata-ladder --ddr-ring-bytes BYTES` exercises finite capture and
requires clean target completion, exact producer/consumer closure, a valid
bounded high-water mark, first-frame latency, and a counter-proven initial
contiguous span. Its report separately records later gaps and delivery
fraction. Transport qualification
uses tandem HOLD by default so gain transitions do not confound the data-path
result; pass `--tandem-mode auto` to exercise both systems together.

### ABI-3 direct async and RAM queue extension

The `iq-direct-async-v2-source` runtime adds one finite direct mode to ABI 3,
allows its target to span as many as 4,096 frames without re-arming, and makes
radio-side overrun handling explicit. The hardware-test package set is:

| Component | Exact released version | Qualified source commit |
| --- | --- | --- |
| persistent firmware | `v0.47-plutoplus-spf-iq-direct-async-v2` | `2bab87dcd9b18c8f957ae781603e88160c8509cc` |
| firmware Buildroot/rootfs | `iq-direct-async-v2-source/buildroot-v1` | `3e1dd15acf361cc06e202e9e59e907dd379a13c3` |
| firmware Linux / CMA geometry | `ddr-burst-v1-rc3-source/linux-v1` | `93174a1c049ca6ee42f042dbe93f0fb06fbc9cd7` |
| radio iiOD and host libiio | 0.25 / `iq-direct-async-v2-source/libiio-v1` | `8f66f353c9a70a5524988ceb588b0e9271c2390d` |
| radio metadata provider | ABI 3 / `RadioMetadataV6` | `3294365ff44da26b261be4a2ccb241b7896d23ad` |
| Pluto Plus Utils | 0.1.0, Python 3.11+ | `9f9a2bd6d059833bc7d9259a48eabff8e20642ad` or later |

Both the native host library and Python binding must be generated from the
same `8f66f35` tree. The ABI-3 runtime receipt deliberately rejects older
ABI-3 libiio commits, upstream libiio, and a PyPI-only binding.

Ringless direct mode requires `iio,buffer-direct-async=1`. The producer leases
DMA blocks while the existing TCP worker consumes one ordered queue; RAM is
not allocated when `ddr_ring_bytes=0`:

```python
with radio.begin_metadata_capture(
    1_048_576,
    kernel_buffers=15,
    direct_async_frames=250,
    ddr_ring_bytes=0,
    drop_backlog_on_overrun=True,
) as capture:
    blocks = [capture.read_block() for _ in range(250)]
```

Combined mode additionally requires `iio,buffer-direct-async-ring=1`. RAM is
overflow capacity within the same descriptor FIFO: a queued DMA-backed frame
may be copied into a RAM slot and release its DMA lease without changing FIFO
position. `direct_async_frames` remains the only finite target, so the ring
target and continuous switch must remain disabled:

```python
with radio.begin_metadata_capture(
    1_048_576,
    kernel_buffers=10,
    direct_async_frames=23,
    ddr_ring_bytes=13 * 4_194_304,
    ddr_ring_frames=0,
    ddr_ring_continuous=False,
    drop_backlog_on_overrun=True,
) as capture:
    assert capture.direct_async_ring_extension
    blocks = [capture.read_block() for _ in range(23)]
    status = capture.ddr_ring_status()
    assert status["state"] == "complete"
    ram_dropped_frames = status["produced_frames"] - status["consumed_frames"]
    assert ram_dropped_frames >= 0
```

Combined ring status counts actual RAM spills and network drains; it does not
count DMA-backed frames, and its target is zero because direct mode owns
completion. With backlog dropping enabled, `produced_frames - consumed_frames`
is the number of RAM-backed frames evicted before transport. The ladder exposes
that value directly as `ram_dropped_frames` and requires
`ram_spilled_frames == ram_drained_frames + ram_dropped_frames`.
At least three kernel buffers are required. With five or more, iiOD reserves
three DMA periods as ingestion headroom while a 4 MiB RAM copy is in progress.
DDR burst and direct mode are mutually exclusive, and direct mode supports
exactly one selected receiver.

The v2 hardware comparison used `iiod -r 1`, single-RX 25 MS/s,
1,000,000-sample frames, and one 250-frame request. Every row returned all 250
requested frames into an exact 1.000 GB file; there was no host request re-arm:

| Queue and policy | Payload | Gap events | Missing samples | Source coverage |
| --- | ---: | ---: | ---: | ---: |
| 12 DMA, preserve | 73.83 MB/s | 74 | 74,000,000 | 77.16% |
| 12 DMA, drop backlog | 73.02 MB/s | 8 | 80,000,000 | 75.76% |
| 12 DMA + 200 MB RAM, preserve | 65.69 MB/s | 66 | 66,000,000 | 79.11% |
| 12 DMA + 200 MB RAM, drop backlog | 61.40 MB/s | 4 | 132,000,000 | 65.45% |

The final 200 MB drop run recorded 169 RAM spills, 74 network drains, 95 RAM
evictions, high-water 26, and clean `target_complete`. A separate 15-DMA pair
measured 72.87 MB/s with 74 one-frame gaps in preserve mode and 73.62 MB/s with
six 13-frame gaps in drop mode. These results define the policy honestly:
dropping minimizes the number of discontinuity events and stale-data latency,
not missing-sample count or source-time coverage. RAM copies also consume Zynq
CPU and are not the maximum-throughput configuration.

The radio advertises both supported values through
`iio,buffer-direct-async-overrun-policies=drop-backlog,preserve-backlog` and
advertises `drop-backlog` as its default. The Python API and CLI default to
`drop_backlog_on_overrun=True`. Set it to `False`, or pass
`--preserve-backlog-on-overrun`, to deliver every already queued frame. In both
modes the frame currently entering TCP is never freed, exact V6 gap metadata is
rebased against the last delivered frame, and replacement frames are acquired
until the original host target is satisfied.

Run the release speed matrix with one Pluto Plus Utils command:

```bash
uv run pluto radio direct-async-ladder 192.168.1.15 \
  --transport ip --expect-serial EXACT_SERIAL \
  --rates 5M,10M,15M,25M --durations 3,10 \
  --samples 1048576 --kernel-buffers 15 \
  --format json --report /ABSOLUTE/PRIVATE/PATH/direct-matrix.json
```

Add `--ram-ring-slots 13 --kernel-buffers 10` for the RAM-extension matrix.
The command defaults to `--drop-backlog-on-overrun`; use
`--preserve-backlog-on-overrun` for the control policy.
For a local gadget among several radios that all use `192.168.2.1`, add the
exact `--usb-sysfs-path`, `--isolate-usb-route`, and
`--isolation-confirm 'ISOLATE USB SSH INTERFACE'`. Route isolation covers the
whole matrix, restores every peer interface afterward, and emits a durable
receipt; the ladder remains IP/TCP rather than silently switching to USB bulk.
The direct protocol and the ladder both cap a cell at 4,096 frames. Every
supported cell is therefore one bounded session: the same DMA queue is recycled
until the target completes, and there is no periodic request re-arm.
Counter-observed gaps remain evidence in a completed speed cell, while
protocol, readback, cleanup, or capture failures make the command exit nonzero.

The immutable `iq-direct-async-v2-source/libiio-v1` ref supplies the matched
host runtime. Early comparison runs used a volatile iiOD/library overlay on the
version-stamped CMA prototype; those results are historical prototype evidence,
not installation artifacts. The persistent image containing exact `8f66f35` is
now published as
[`v0.47-plutoplus-spf-iq-direct-async-v2`](https://github.com/misko/plutosdr-fw/releases/tag/v0.47-plutoplus-spf-iq-direct-async-v2).
Its firmware source requirements, submodule commits, binary hashes, guarded
installation steps, and rollback rules are recorded in
[`IIO_DIRECT_ASYNC_INSTALL.md`](https://github.com/misko/plutosdr-fw/blob/main/IIO_DIRECT_ASYNC_INSTALL.md).

Build the matched native library and binding into a release-local virtual
environment:

```bash
scripts/install_native_libiio.sh \
  --uv-bin /srv/leo/releases/RELEASE/.release-tools/uv \
  --metadata-abi 3 \
  --python /srv/leo/releases/RELEASE/.venv/bin/python \
  --prefix /srv/leo/releases/RELEASE/.venv
```

An installed release can invoke the same package-owned script through
`pluto-install-metadata-runtime`. The explicit `--uv-bin` must name the
release-sealed, non-symlink executable; the installer never upgrades pip or
setuptools and never falls back to an ambient `uv`.

The installer resolves an immutable Git tag, verifies its exact commit, builds
native and Python pieces together, and validates the `MetadataBuffer`
constructor for the selected ABI. It writes a release-local
`share/pluto-plus-utils/metadata-runtime.json` receipt containing both installed
file hashes. `verify_metadata_runtime(expected_abi=3)` resolves and hashes the
receipt files, explicitly preloads that absolute native library, verifies the
loaded native and Python paths, and checks the constructor ABI before radio
capture. `begin_metadata_capture()` invokes this gate automatically. A missing
or mismatched receipt is an admission failure; ambient stock libiio is never a
fallback.

Staging should record and compare all of the following before opening a radio:

- application release commit;
- pluto-plus-utils commit;
- native libiio real path and version;
- pylibiio module path;
- `MetadataBuffer.__init__` signature;
- radio serial, firmware version, and `iio,buffer-metadata` value.

A mismatch is an admission failure, not a reason to fall back to legacy
`read_block()`. The legacy method remains usable only for callers that
explicitly accept `continuity=unobservable`.

## Capture lifecycle

For a repeated-refill dwell:

```python
with radio.begin_metadata_capture(samples_per_refill, kernel_buffers=8) as capture:
    blocks = [capture.read_block() for _ in range(refill_count)]
```

Construct a production IIO adapter with the release's declared ABI before
opening it:

```python
# ABI 3 is required for the direct-async candidate; deployed ABI-1 radios use 1.
radio = IioRadioDevice(uri, serial=serial, expected_metadata_abi=3)
radio.open()
```

This preloads and verifies the receipt-bound native library before pyadi can
import pylibiio. The radio capability is compared to that declaration after
the context opens; a mismatch is fatal. Omitting `expected_metadata_abi` keeps
legacy host-timed reads available but deliberately leaves device-counter and
continuity-sequence capabilities false.

For each scanner target:

```python
radio.reset_receive_buffer()
actual_hz = radio.tune_center_frequency(target_hz)
# verify actual_hz and wait for the configured LO-settle interval
with radio.begin_metadata_capture(samples, kernel_buffers=8) as capture:
    block = capture.read_block()
```

`begin_metadata_capture()` resets any prior buffer, sets and reads back the
kernel-buffer count, performs an ordinary prime with the selected RX layout, destroys
that buffer, and opens a fresh metadata buffer. The returned session is the
only object allowed to read that generation. Closing and resetting are
idempotent; a closed session cannot read again.

The default tandem AUTO request scales its cooldown for the refill size so the
fixed 64-entry event array always covers the worst-case transition count. An
explicit caller-supplied request is never rewritten and still fails before I/O
when its event capacity cannot cover the requested refill.

Every `SampleBlockV2` carries IQ plus the actual metadata ABI, stream ID,
buffer sequence, FPGA first-sample sequence, flags, an upstream gap count, and
the fitted realtime/monotonic sample interval with uncertainty when counter
register anchors are available. Consumers must independently recompute gaps
from counters. ABI 3 additionally requires the header's exact gap count and gap
flag to agree with both FPGA counters and the buffer-sequence quotient.

Exercise each ABI 3 layout through the supported utility path:

```bash
uv run pluto radio metadata-ladder EXACT_SERIAL \
  --metadata-abi 3 --channels rx0 --samples 262144,131072
uv run pluto radio metadata-ladder EXACT_SERIAL \
  --metadata-abi 3 --channels rx1 --samples 262144,131072
uv run pluto radio metadata-ladder EXACT_SERIAL \
  --metadata-abi 3 --channels dual --samples 262144,131072
```

Both ordinary and metadata ladders support the explicit
`--iq-decoder raw-complex64` prototype. It reads the complete interleaved IIO
buffer once, then fills an owned `complex64` array directly. This avoids the
generic per-channel extraction and intermediate `complex128` allocation while
retaining the same signed I/Q values. The mode is fail-closed: it requires the
exact fully-defined Pluto LE16 scan geometry and never becomes an automatic
fallback for a different IIO device or layout. Metadata is read from the same
`MetadataBuffer` refill before that buffer can be reused.

When several USB-attached Plutos share the default `192.168.2.1` endpoint, bind
an IP ladder to one serial and sysfs path with the receipt-backed isolation
gate. `--report` writes an absent-only canonical JSON evidence file beneath an
existing owned mode-0700 directory:

```bash
uv run pluto radio metadata-ladder 192.168.2.1 \
  --transport ip --expect-serial EXACT_SERIAL \
  --usb-sysfs-path /sys/bus/usb/devices/EXACT_PORT \
  --isolate-usb-route --isolation-confirm 'ISOLATE USB SSH EXACT_INTERFACE' \
  --metadata-abi 3 --channels rx0 --sample-rate-hz 2500000 \
  --rf-bandwidth-hz 2500000 --samples 4194304,2097152,1048576,524288 \
  --frames 6 --kernel-buffers 4 --report /ABSOLUTE/PRIVATE/PATH/rx0.json
```

For the 20 MS/s, 20-second single-RX issue qualification over physical
Ethernet, use 1,000,000-sample frames (400 frames) and compare the ordinary path
with the 200 MB ring path:

```bash
uv run pluto radio metadata-ladder 192.168.1.17 \
  --transport ip --expect-serial EXACT_SERIAL --metadata-abi 3 --channels rx0 \
  --sample-rate-hz 20000000 --rf-bandwidth-hz 20000000 \
  --samples 1000000 --frames 400 --kernel-buffers 4 --tandem-mode hold \
  --acceptance capture-completion
uv run pluto radio metadata-ladder 192.168.1.17 \
  --transport ip --expect-serial EXACT_SERIAL --metadata-abi 3 --channels rx0 \
  --sample-rate-hz 20000000 --rf-bandwidth-hz 20000000 \
  --samples 1000000 --frames 400 --kernel-buffers 4 --tandem-mode hold \
  --ddr-ring-bytes 200000000 --acceptance capture-completion
```

The default `continuity` acceptance remains the throughput-ladder contract and
returns nonzero when no rung covers at least 95% of the device timeline. The
explicit `capture-completion` contract instead succeeds only when every requested
host frame returns with exact FPGA-counter accounting. It permits accounted gaps
caused by a slower transport; DDR-ring captures still additionally require a clean
`target_complete` terminal state and a counter-proven initial contiguous span.
Each successful cell also records `tandem_metadata_frames`, the exact
`gain_observation_interval_samples`, and aggregate gain-observation and overflow
counts. It separately records aggregate FPGA gain-event and event-overflow counts,
so sampler-cadence changes and AUTO transition preservation are directly auditable
from the canonical report without a separate capture parser.
