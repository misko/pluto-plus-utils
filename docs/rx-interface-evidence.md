# RX digital-interface matrix evidence

`pluto_plus.hardware.rx_interface_evidence.assess_rx_interface_timing` is a
hardware-free Python API for validating an AD9361 Linux driver's complete
16x16 `bist_timing_analysis` report. It performs no discovery, IIO, calibration,
setting changes or firmware promotion. Existing PPU defaults are unchanged.

```python
from pluto_plus.hardware.rx_interface_evidence import assess_rx_interface_timing

evidence = assess_rx_interface_timing(
    recorded_text,
    expected_sample_rate_hz=15_000_000,
    clock_delay=read_back_clock_delay,
    data_delay=read_back_data_delay,
    minimum_margin_steps=1,  # Example policy; freeze it before evaluation.
    margin_axis="data",     # Hold clock delay fixed; test both data-delay sides.
)
```

Rows represent **data delay**; columns represent **clock delay**. The report's
sample clock must match exactly. The supplied selected cell must pass, and the
complete neighborhood at the requested radius must have been measured passing.
Choose the policy explicitly: `data` tests a centered data-delay line at fixed
clock delay, `clock` tests a centered clock-delay line at fixed data delay, and
`square` tests the complete two-dimensional square including diagonals. These
are different claims: the driver's normal tuner can select zero on one axis,
so a margin on the other axis is not proof of a complete square margin.
The API never clips the neighborhood at a boundary or wraps delay
indices. A radius of zero explicitly tests only the selected cell. The radius
is in discrete matrix steps, not nanoseconds, bit-error probability or PVT
margin. No universal minimum is imposed or claimed sufficient for deployment.

Well-formed negative evidence returns `meets_matrix_policy=False` with reasons,
the original report, SHA256, complete matrix, selected coordinates, expected
and observed rates, and measured margin. Malformed/truncated/reordered reports
raise `ValueError`; retain the original failed capture separately. The object
is a frozen dataclass and can be serialized with `dataclasses.asdict`.

## Collection remains a separate, controlled operation

Do not treat `bist_timing_analysis` as an ordinary read-only health attribute.
In the reviewed experimental kernel (`4357f41a721df9d89a66be7a2a3f921a71d46bad`,
`drivers/iio/adc/ad9361_conv.c`), its report generator sweeps clock/data delays,
injects RX PRBS, changes ENSM/pin-control state, and attempts to restore the
saved delays, loopback/BIST, ENSM and TX attenuation afterward. The regular
`ad9361_dig_tune` path can also clear a tuning error when called with
`max_freq=0`. A successful command return is therefore not matrix evidence.
This source review is not proof of behavior on an unidentified installed kernel.

Before a future native collection operation:

1. Attest the exact serial, boot, firmware/kernel/FPGA and RX-only ownership.
   Stop conflicting captures, lock the device, and record all affected settings.
2. Pin and verify the intended physical RX rate, channel mode and TX safety.
   Do not infer them from a requested rate or an old matrix.
3. Run the explicitly authorized bounded test; retain raw output, errors,
   timing, and actual setting readbacks. Assess the selected setting, not an
   unrelated passing cell. A matrix at one rate cannot qualify another rate.
4. Verify restoration and TX-safe state independently, including failures and
   interruptions, before restarting acquisition or releasing the owner.
5. Keep matrix-policy success distinct from routed FPGA timing, board-level
   static timing/PVT coverage, ADC formatting, sustained DMA/IIO integrity and
   live RF/PSS performance. All remain separate release requirements.

The parser does not attest the source, freshness, test duration, register writes
or restoration. Bind its receipt to the external collection manifest; passing
synthetic text fixtures must never be reported as a radio calibration pass.
