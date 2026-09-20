# Counter-to-UTC timing

Adaptive capture can collect SCANTIME observations over an independent control
connection without changing IQ transport. `run_adaptive_scan_campaign` accepts
`counter_clock_sink` and `timing_policy`. The production adaptive script saves
the new evidence as `evidence.counter_utc_timing`, alongside the historical
start-call bracket. Unsupported firmware or clock failures preserve IQ and
record unqualified timing.

The collector takes up to eight startup queries, then one every five seconds.
Network and chrony calls have timeouts. Epoch, request, rate, counter progression,
query width, anchor gaps, host steps and endpoint coverage are checked. Each
anchor is propagated with an integer/rational rate envelope, and intervals are
intersected. A conservative full-span drift allowance expands the first-sample
interval for the nominal sample-rate projection used downstream.

The fixed `counter-utc-100ms-v1` policy requires a <=50 ms query interval and
<=100 ms maximum absolute UTC error throughout the capture. The bounds include
host UTC error, snapshot age, oscillator rate tolerance, and acquisition delay
(treated conservatively in both directions). This is a conditional engineering
bound, not a claim that NTP provides an unconditional physical guarantee.

Chrony is queried with `chronyc -c tracking`. The bound includes absolute system
offset, root dispersion, half root delay and an ageing allowance at reported
skew. Missing/unsynchronized/stale/local-reference evidence is unqualified.
Host realtime/monotonic agreement alone never qualifies UTC.

## Calibration and independent validation

Defaults intentionally cannot qualify hardware. The kernel supplies coherent
counter reads but no snapshot-age bound. `--timing-policy FILE` accepts the
following policy fields; values must come from a documented engineering bound
and independent validation, **not** fitting the test markers or TLE residuals:

- `calibration_reference`: immutable report/instrument receipt identifier.
- `calibration_radio_serial` and `calibration_boot_id`: exact qualified radio
  and boot UUID (32 lowercase hex digits without hyphens).
- `maximum_rate_error_ppm`: bound on actual sample-clock rate error.
- `maximum_snapshot_age_ns`: maximum coherent-register age when the device
  reports UINT64_MAX.
- `maximum_acquisition_delay_ns`: absolute bound on IQ/counter alignment delay.

Changing boot invalidates the calibration. A reviewed future firmware contract
can supply its own snapshot-age bound. Do not supply arbitrary numbers merely
to make `qualified` true.

Inject independently UTC-timed RF markers and record their sample counters,
UTC times and reference uncertainties. Account for generator/cable latency and
marker detection error. The reference JSON uses `IndependentReference` from
`counter_utc_verify.py`: source, instrument receipt SHA256, radio/boot/session/
generation/rate identity, first/final counters and a list of
`{counter, utc_ns, uncertainty_ns}` markers. It must cover both endpoints and
have no gaps longer than ten seconds. Then run:

```sh
python -m pluto_plus.counter_utc_verify manifest.json reference.json > verdict.json
```

The verifier performs no RF operations and never estimates a new calibration.
It hashes input artifacts and requires every absolute residual plus reference
uncertainty to fit the declared whole-capture bound. A failure exits nonzero.

Run one 300-second session at 10/15/20 MS/s (15 minutes), plus at most ten
minutes of loaded-transport, reboot and time-source-loss cases. Record counter
continuity and scheduling outcomes alongside timing. Use separate calibration
and verification evidence; test measurements alone do not prove worst-case
behavior. Neither this software change nor synthetic tests qualify a radio.
