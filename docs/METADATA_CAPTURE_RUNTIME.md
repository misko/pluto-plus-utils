# Metadata capture runtime and lifecycle

`IioRadioDevice.begin_metadata_capture()` is intentionally unavailable through
stock pylibiio. The radio firmware, native libiio, and Python binding form one
matched metadata ABI. Loading `/usr/lib/libiio.so.0` with the PyPI binding does
not make continuity observable and must not be accepted as a fallback.

## Matched runtimes

| Exact firmware profile | Radio capability | Metadata header | Host source tag | Exact commit |
| --- | --- | --- | --- | --- |
| production ABI-1 profile | `iio,buffer-metadata=1` | strict `RadioMetadataV3` | `spf-frame-metadata-source/v0.25-final-v3` | `c26258bfa33098c2b215e19cf85d448e89499b1a` |
| `v0.40-plutoplus-spf-tandem-agc-v7` | `iio,buffer-metadata=2` | strict `RadioMetadataV4` | `tandem-agc-v2-source/libiio-v9` | `015e4924113d4996667f80b880c34cbf7d1147de` |

The currently deployed `.20` and `.21` radios advertise ABI 1. The reviewed
tandem V7 radio also advertises ABI 2, but ABI 2 is not a unique profile: later
firmware can retain that capability while changing its metadata header and host
provider. Runtime selection therefore uses the exact `(firmware version, ABI)`
pair. An unknown ABI-2 firmware is rejected rather than guessed to be V7.

Build the matched native library and binding into a release-local virtual
environment:

```bash
scripts/install_native_libiio.sh \
  --uv-bin /srv/leo/releases/RELEASE/.release-tools/uv \
  --metadata-abi 1 \
  --python /srv/leo/releases/RELEASE/.venv/bin/python \
  --prefix /srv/leo/releases/RELEASE/.venv
```

For the reviewed tandem V7 runtime, identify both parts of the profile:

```bash
scripts/install_native_libiio.sh \
  --uv-bin /srv/leo/releases/RELEASE/.release-tools/uv \
  --metadata-abi 2 \
  --firmware-version v0.40-plutoplus-spf-tandem-agc-v7 \
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
ABI-1 receipt. The V7 call additionally supplies
`expected_firmware_version="v0.40-plutoplus-spf-tandem-agc-v7"`. The gate
explicitly preloads that absolute native library, verifies the loaded native
and Python paths, and checks the constructor ABI before radio capture.
`begin_metadata_capture()` invokes this gate automatically. A missing or
mismatched receipt is an admission failure; ambient stock libiio is never a
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
import pylibiio. For ABI 2, the adapter declaration must also name the exact
supported firmware version. The radio capability and firmware version are
compared to that declaration after the context opens; a mismatch is fatal.
Omitting the runtime declaration keeps legacy host-timed reads available but
deliberately leaves device-counter and continuity-sequence capabilities false.

For each scanner target:

```python
radio.reset_receive_buffer()
actual_hz = radio.tune_center_frequency(target_hz)
# verify actual_hz and wait for the configured LO-settle interval
with radio.begin_metadata_capture(samples, kernel_buffers=8) as capture:
    block = capture.read_block()
```

`begin_metadata_capture()` resets any prior buffer, sets and reads back the
kernel-buffer count, performs the required ordinary dual-RX prime, destroys
that buffer, and opens a fresh metadata buffer. The returned session is the
only object allowed to read that generation. Closing and resetting are
idempotent; a closed session cannot read again.

Every `SampleBlockV2` carries IQ plus the actual metadata ABI, stream ID,
buffer sequence, FPGA first-sample sequence, flags, an upstream gap count, and
the fitted realtime/monotonic sample interval with uncertainty when counter
register anchors are available. Consumers must independently recompute gaps
from counters. An upstream `missing_samples_before` value is convenience, not
the persisted integrity oracle.

## Bounded continuous DDS capture

The V7-only helper captures multiple refills from one buffer generation while
one reviewed DDS port is active:

```python
result = capture_continuous_safe_dds_tone(
    plan,
    samples_per_frame=100_000,
    frame_count=100,
    kernel_buffers=8,
    block_consumer=persist_block,
)
```

At 1 MS/s this is a 10-second, 100-frame capture. The call destroys any old RX
buffer, configures and reads back more than two kernel buffers, performs the
required ordinary-buffer prime/destroy, and creates one fresh metadata buffer.
The first accepted refill must have `buffer_sequence == 0`; every later refill
must increment it by one and begin at the prior refill's exclusive FPGA sample
sequence. A stream-ID change, counter gap, overflow/read failure flag, wrong
shape, or ABI change aborts the capture. The synchronous consumer permits each
IQ block to be persisted without retaining all samples in memory.

The reviewed finite-call ceiling is 60 million samples. This permits a
10-second qualification at 5 MS/s (50 million samples) while keeping the RF
deadline and artifact size bounded; the synchronous consumer still streams
each frame instead of retaining the full capture in memory.

`CaptureWriter` accepts these `SampleBlockV2` refills and writes the exact
per-frame ledger under `pluto:continuity`. The authoritative continuity proof
is the tuple of stream ID, buffer sequence, FPGA first-sample sequence, sample
count, and validity/failure flags. The realtime and monotonic frame intervals
are host-derived affine estimates from bracketed FPGA counter reads. Their
uncertainty is persisted, and small estimated overlaps or gaps within that
uncertainty are not sample discontinuities. Phase-sensitive processing should
use stored sample indices or FPGA counters, not joins between host wall-clock
estimates.

The helper attenuates both TX paths and zeros/disables DDS before opening the
radio, before closing the metadata session, and again during device release.
This covers normal return and cooperative Python exceptions. A blocked
consumer, `SIGKILL`, Pi power loss, or USB failure can prevent process cleanup;
unattended transmission therefore also needs an independent hardware or
supervisor watchdog with a bounded RF deadline.
