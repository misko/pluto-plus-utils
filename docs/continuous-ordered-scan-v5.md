# Continuous ordered scan v5 host companion

`pluto_plus.continuous_scan` and `pluto_plus.continuous_scan_radio` add a
separate host API for continuous ordered IQ firmware. Adaptive scan v1–4
retain their accepted versions and finite duration meanings. This companion
contains no FPGA power worker, PWR1 MMIO helper, power protocol or detector.
It requires no new FPGA power personality.

## Firmware compatibility

Use the matched continuous-only iiOD/native runtime supplied by the firmware
release. Corrected device behavior comes from libiio commit `44efe08`. Every
COMPLETE window begins at least the configured transition budget after both
its selection counter and the actual Fast Lock recall end. The host checks:

```text
valid_start >= max(selection_counter, transition_after)
               + transition_budget_ms * 2500
```

The default budget is 20 ms, or 50,000 samples at 2.5 MS/s. This is a minimum
post-recall interval in the provider's hardware counter domain. It does not
independently measure analog settling or UTC. A COMPLETE receipt from the
earlier v5 candidate can fail this check despite advertising `SCANCAPS5`;
the capability shape alone does not attest the corrected guard. Existing saved
recordings and finite-mode receipts retain their original meanings.

`SCANCAPS5 96` must negotiate the exact v5 capability record before the radio
is prepared. Unsupported firmware fails before preparation. Only v5 admits
`duration_ms=0`, meaning until STOP. It requires exactly eight targets with
profiles 0–7, baseline weights one, maximum boost one, 2.5 MS/s and 20 ms dwell.
Targets are visited in order; global visit and sweep counters remain 64-bit
throughout one session and generation. RX1 and shared-LO RX1+RX2 are supported.
This is not an adaptive feedback campaign.

The existing native-runtime installer selectors retain their immutable pins.
In particular `--scanner-glrt` selects the v058 runtime, not this continuous
release. Install the exact native runtime identified by the firmware companion
manifest separately. The v5 client sends commands directly over the selected
iiOD TCP connection; public radio preparation uses the installed IIO runtime.
Record both source commits and installed artifacts when qualifying deployment.

## API and ownership

`build_continuous_setup` constructs a separate `ContinuousSetup`. Supply
nonzero session, generation and seed values, eight explicitly selected IFs,
and a 32-byte analysis/configuration digest. Select an explicit radio serial
and physical LAN URI. Public preparation snapshots original radio settings,
configures native capture geometry, and verifies all eight Fast Lock profiles
before `OPENM`. Use distinct IFs: preparation exits recalled Fast Lock through
a distinct cached LO transition.

`ContinuousRadioOwner.start(uri, serial, setup)` returns one prepared owner.
Its optional `before_start_hook(preparation)` runs after preparation and before
`OPENM`; failure restores preparation. A caller must separately authorize any
hook that enables a fixture transmitter. The ordinary scan API does not enable TX.

Consume `owner.visits()` with caller-owned bounded processing/storage queues.
Each `AdaptiveScanVisit` contains a v5 record and actual CI16 payload:

| Result | Counter support and bytes |
|---|---|
| COMPLETE | Exactly 50,000 samples, intact support, minimum guard satisfied |
| Noncomplete | Actual contiguous prefix of 0–50,000 samples, diagnostic support |

Every payload must contain `(valid_end - valid_start) * 4 * receiver_count`
bytes. Dual-RX COMPLETE is 400,000 bytes. Noncomplete IQ is retained without
padding or promotion to COMPLETE. The session checks counter support, payload
geometry, target order and terminal accounting. Transport completeness does not
establish unclipped ADC data, RF identity, power activity, Starlink evidence or
qualified tracking; those belong to downstream contracts.

`owner.status()` and `owner.stop(forced=False)` use independent connections.
The device/session/generation can also be controlled with a separate
`ContinuousClient.control(device, ContinuousControl(request, session,
generation), stop=...)`. STOP acceptance does not mean the stream has drained.
Graceful STOP finishes the active window. Forced STOP may retain a partial
diagnostic prefix. Continue consuming visits until the terminal, then call
`owner.close()` to restore host preparation. The device restored flag covers
its scan-owner lease; the host settings restoration receipt is separate.
Closing early cannot claim a graceful complete stream. `owner.abort_read()`
interrupts a stalled reader; callers must bound control, drain and restoration.

## Failure diagnostics

The companion is based on PPU `e0a4072`, which includes bounded, session-bound
`SCANDIAG` snapshots. On a terminal device error or failed stream, the v5 session
captures `failure_diagnostics` before closing its owning connection. Unsupported
commands or failed diagnostic reads record `unavailable_error`; they never
replace the original acquisition error or invent restoration. Successful streams
do not request failure diagnostics. Independent controls rejected by the device
raise `ContinuousControlError`, an `AdaptiveScanTransportError` subclass with a
positive `errno` for callers handling ENODATA races.

## Qualification and packaging

Existing Hatch discovery includes both modules. No console entry point or
dependency is added. This API companion is separate from Leo recording CLI and
offline GLRT. A continuous-only PPU pin does not supply paused standalone power
APIs; applications using those APIs must retain their full SDK pin.

Run the owned and finite compatibility tests, then repository CI:

```sh
uv sync --python 3.11 --extra dev --locked
uv run pytest tests/test_continuous_scan.py tests/test_continuous_scan_radio.py
uv run pytest -q
uv run ruff check src tests
uv run mypy src/pluto_plus
uv build
```

Inspect the wheel and sdist, test an installed wheel outside the checkout, and
retain artifact hashes. Offline tests do not establish hardware timing, RF
performance or firmware restoration. Preserve exact per-device hardware reports
with the firmware release. Publication and persistent-update policies remain
in [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md).
