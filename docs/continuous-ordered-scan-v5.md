# Continuous ordered scan v5 host companion

`pluto_plus.continuous_scan` and `pluto_plus.continuous_scan_radio` add a
separate host API for continuous ordered IQ firmware. Adaptive scan v1–4
retain their accepted versions and finite duration meanings. This companion
contains no FPGA power worker, PWR1 MMIO helper, power protocol or detector.
It requires no new FPGA power personality.

## Firmware compatibility

Use the continuous-only device iiOD/libiio pair supplied by firmware
`v0.62-plutoplus-spf-continuous-fast-scan`, libiio source commit
`e2ea69c284f0f1c64efb05c0251bca2ee59932b1`. Every COMPLETE window begins at least
the configured transition budget after both its selection counter and the
actual Fast Lock recall end. The host checks:

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

The qualified host uses metadata ABI3 and the existing v058 native runtime,
source `7639fc9b6c01336e1451f4f58ccf66e30a22388d`, selected by the unchanged
`--metadata-abi 3 --scanner-glrt` installer options. Its source reference is
`adaptive-multirate-agc-v058-source/libiio-v1`. The v5 Python client sends commands
directly over the selected iiOD TCP connection; public radio preparation uses
that installed host runtime. It does not require a new host native library
merely to send v5 commands. Other native-runtime versions are not qualified by
this pairing.

Keep the host and device artifacts separate in deployment provenance. The
tested local host build and exact v062 device pair have these SHA-256 hashes:

| Artifact | SHA-256 |
|---|---|
| Host native libiio | `4d84fbaecce13ee109029f08f78be0ecbfc9eefa9a6f491ccdca943e8e1809a8` |
| Host Python iio binding | `943995d22acef36a57362e0f8871ef0578d11f80ebf45114c86246d76c5a4be5` |
| Device iiOD | `f8555bf2e646b87441b279005ea508689d79b218565a1423d42d718da02198dc` |
| Device libiio | `00a22df5f484055e2ab4db1d18db6f18fb0c44d8eca0d35d85de2cfe4db2bfe2` |

The exact-image LAN qualification retained 601 receive windows across two
segments and 112 fixture windows. Independent saved-IQ validation checked all
713 windows, their ordered counters and 20 ms post-recall guards, integer powers,
payload hashes and terminal accounting. Both sessions restored RX settings;
the fixture also restored TX. This is evidence for the recorded configuration
and device, not every radio, native build or directed transition. The saved
context advertises metadata ABI3; a source-component label containing “v6” is
not the negotiated capture ABI.

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
