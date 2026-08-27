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
| `iio,buffer-metadata=3` | strict `RadioMetadataV6` | `single-rx-metadata-rc1-source/libiio-v1` | `5dc200af10961e50d3b019cd38bdb8dd3c0e8c3c` |

The currently deployed `.20` and `.21` radios advertise ABI 1. ABI 2 is a
separate, gated firmware and host-runtime migration; it must not be selected
only because newer code is available.

ABI 3 is the additive single-RX candidate. The radio must also advertise the
exact capability string
`00000003:1:4:2,0000000c:1:4:2,0000000f:2:8:1`: RX0 and RX1 use four bytes
per sample with an even sample count, while dual RX uses eight bytes per sample.
V6 records arbitrary FPGA-counter gaps exactly; ABI 1/2 parsing and geometry
remain unchanged.

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
