# Continuous 24-target position capture

The additive v6 mode scans Ch1-X, Ch1-Y, Ch1-Z through Ch8-Z, repeats until
STOP, and uses 10 MS/s, 8 MHz bandwidth, dual RX, 20 ms guard and 20 ms valid
IQ. Existing v5 setup, visit and control codecs retain their bytes and limits.

`PositionRadioOwner.start()` negotiates `SCANCAPS6` before opening the radio.
Preparation calibrates 24 immutable 16-byte images with checksums. The kernel
owns profile loading/recall and publishes the selected profile's verified IF
and generation in each receipt. Requested IF is an identity; verified profile
frequency can differ by up to 2 Hz due to synthesizer representation. The
ordinary clock-framework getter is allowed 4 Hz during preparation because
its rounding differs from the profile decoder.

Run with an ABI-3 matched host runtime and these sources on `PYTHONPATH`:

```sh
python -m pluto_plus.position_scan_record --uri ip:192.168.1.15 \
  --serial DEVELOPMENT_SERIAL --output /srv/bulk/leo/position-bench --duration 60
python -m pluto_plus.position_scan_verify /srv/bulk/leo/position-bench
```

The public recorder holds the shared serial lock through preparation, drain
and restoration. Its Python `before_start_hook` runs after preparation closes
and before OPENM. An explicitly authorized cabled fixture can enable TX there.
`after_close_hook` runs after host restoration, still under the lock, including
START failures, so a fixture can restore TX settings. Ordinary capture keeps
the existing transmit-mute behavior. Do not wrap the recorder in another
non-reentrant serial lock.

The output contains the canonical `plan.json`, exact prepared `setup.bin`,
`capture.json` with preparation/terminal/restoration evidence, `iq-hashes.jsonl`,
and `visits.bin`. Each binary frame is little-endian uint32 record size,
the native record, uint64 IQ byte count, and unmodified dual-RX CI16. A terminal
frame has size 128 and zero IQ. Visit records have size 224. The setup is 1120
bytes: the existing 144-byte prefix followed by 24 40-byte target/image entries,
12 reserved zero bytes and CRC32. Protocol headers use version 6. Capabilities,
control and status retain sizes 96, 48 and 128 respectively.

The independent verifier uses standard-library structs and CRCs, without the
acquisition codec. It checks plan/target identity, original profile checksum,
slot generation, verified IF, source-counter support, IQ hashes and terminal
accounting. At least two complete visits at every target are required by
default. A software receipt cannot establish that an RF signature was present;
the verifier reports physical-signature qualification separately as false.
The benchmark must identify tuning from saved known-source IQ.

Duration is bounded to 30 minutes. A failed device terminal, failed restoration
or failed fixture cleanup exits with an error while preserving evidence. IQ
gaps and partial/cancelled visits are retained with their original outcomes.
Absolute sky frequency, relay voltage and spacecraft association require
independent evidence; the fixed IF plan alone does not establish those facts.
