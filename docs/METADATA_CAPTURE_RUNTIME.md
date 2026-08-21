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

The currently deployed `.20` and `.21` radios advertise ABI 1. ABI 2 is a
separate, gated firmware and host-runtime migration; it must not be selected
only because newer code is available.

Build the matched native library and binding into a release-local virtual
environment:

```bash
scripts/install_native_libiio.sh \
  --metadata-abi 1 \
  --python /srv/leo/releases/RELEASE/.venv/bin/python \
  --prefix /srv/leo/releases/RELEASE/.venv
```

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
