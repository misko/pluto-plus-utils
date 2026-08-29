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
| `iio,buffer-metadata=3` | strict `RadioMetadataV6` | `ddr-ring-v1-rc1-source/libiio-v1` | `739a250b92610184b12d773f6a367e549f0dfe29` |

The currently deployed `.20` and `.21` radios advertise ABI 1. ABI 2 is a
separate, gated firmware and host-runtime migration; it must not be selected
only because newer code is available.

ABI 3 is the additive single-RX candidate. The radio must also advertise the
exact capability string
`00000003:1:4:2,0000000c:1:4:2,0000000f:2:8:1`: RX0 and RX1 use four bytes
per sample with an even sample count, while dual RX uses eight bytes per sample.
V6 records arbitrary FPGA-counter gaps exactly; ABI 1/2 parsing and geometry
remain unchanged.

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
`iio,buffer-metadata-status=1`. Unlike a sealed burst, a ring producer and the
ordinary IIO consumer run concurrently. Before it starts transport, iiOD fills
the admitted ring completely (or captures the smaller finite target). That
prefix is strict and contiguous. During a longer capture, unread ring frames are
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
requires clean target completion, exact producer/consumer closure, a full
high-water mark, and a counter-proven contiguous admitted prefix. Its report
separately records later gaps and delivery fraction. Transport qualification
uses tandem HOLD by default so gain transitions do not confound the data-path
result; pass `--tandem-mode auto` to exercise both systems together.

Build the matched native library and binding into a release-local virtual
environment:

```bash
scripts/install_native_libiio.sh \
  --uv-bin /srv/leo/releases/RELEASE/.release-tools/uv \
  --metadata-abi 1 \
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
file hashes. `verify_metadata_runtime(expected_abi=1)` resolves and hashes the
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
radio = IioRadioDevice(uri, serial=serial, expected_metadata_abi=1)
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
`target_complete` terminal state and a counter-proven contiguous admitted prefix.
