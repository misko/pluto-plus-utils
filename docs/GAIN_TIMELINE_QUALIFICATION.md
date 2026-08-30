# Authoritative gain-timeline qualification

The ABI-4 release gate is owned by `pluto-plus-utils`; it does not depend on a
checkout-local helper script. The campaign loads one immutable candidate RAM
operation plan, boots that candidate on one exact USB topology, exercises the
USB and physical `192.168.1.*` IIO paths, and resets into the pre-campaign QSPI
runtime in a `finally` cleanup path. A passing report proves that the persistent
`qspi-linux` identity did not change.

The general matrix has 60 cases per radio:

- USB and physical IP;
- HOLD and AUTO tandem modes;
- ordinary IIO with single RX0 and dual RX;
- 200 MB DDR ring with single RX0 only (firmware does not admit a dual-RX ring);
- two 200-frame and two 600-frame regressions, followed by one 5,000-frame soak;
- 20 MS/s, 20 MHz bandwidth, 262,144 samples per channel, four kernel buffers.

Two named historical regressions are added explicitly, without creating a
generic cross-product:

- issue #49: 64 independent direct-USB ABI-4 open/capture/close lifecycles,
  each dual RX in HOLD at 1 MS/s, 100,000 samples per channel, 100 frames, and
  eight kernel buffers; and
- issue #54: at each of 2.5, 3, and 5 MS/s over the physical `192.168.1.*`
  endpoint, 20 independent dual-RX HOLD sessions of six 4,194,304-sample
  frames, followed by one six-frame descending ladder through 4,194,304,
  2,097,152, 1,048,576, and 524,288 samples per channel with four kernel
  buffers.

Together these are 187 independently receipted capture sessions per radio: 60
general cases, 64 issue-#49 sessions, and 63 issue-#54 sessions. Each ladder is
one lifecycle with a separate open/close capture at every rung.

Every case must return all frames with no counter gap or overflow, a complete
authoritative V7 gain timeline for every frame, exact settings restoration, and,
for ring cases, clean status V2, bounded first-frame latency, exact FIFO
positions, and its observed initial contiguous span. The first
failure stops further capture cases so cleanup can run immediately.

Candidate admission also proves the compatibility-preserving negotiation:
legacy scalars remain `iio,buffer-metadata=3` and
`iio,buffer-metadata-status=1`, while the canonical explicit sets contain ABI 4
and status V2. The host selects 4/2 from those sets; it never interprets either
legacy scalar as the v8 wire version.

Hardware identity remains exact rather than interchangeable. Candidate plans,
operation plans, and receipts retain one raw `hw_model`, chosen from the two
supported Rev.C identities: `Z7010-AD9361` or the native
`Z7010-AD9363A`. An AD9361 plan cannot accept an AD9363A observation (or the
reverse). The native AD9363A identity is admitted only with a typed, read-only
setup attestation proving that `attr_name` and `attr_val` are absent,
`compatible=ad9361`, `mode=2r2t`, the live PHY is a supported AD9361/AD9363A
compatible, the RX scan layout is exactly `voltage0` through `voltage3`, and the
candidate exposes the tandem device. Serial, USB topology, QSPI identity, and
the safe-state checks remain independent mandatory gates.

Create one private plan per radio without touching hardware:

```console
uv run pluto firmware candidate-ram qualification-plan \
  --operation-plan /private/rc/serial/operation.json \
  --physical-ip 192.168.1.20 \
  --report /private/rc/serial/gain-timeline-report.json \
  --output /private/rc/serial/gain-timeline-plan.json
```

The plan prints its exact confirmation phrase. Execute it only from the clean
Utils commit named by the candidate plan:

```console
uv run pluto firmware candidate-ram qualification-execute \
  --plan /private/rc/serial/gain-timeline-plan.json \
  --ssh-password-file /private/radio-password \
  --confirm 'QUALIFY GAIN TIMELINE EXACT_SERIAL CAMPAIGN_ID' \
  --tool-repository /path/to/pluto-plus-utils \
  --state-root /private/pluto-state
```

The process holds the shared per-radio lock for boot, capture, and restoration.
Physical-IP phases additionally hold one host-wide lock for
`192.168.1.0/24`, while USB phases for different radios may proceed in parallel.
Candidate boot and persistent reset briefly take the existing daemon/route
maintenance locks. All radios in one physical-LAN campaign must therefore run
on the same self-hosted runner host; the host-wide lock is an OS lock, not a
distributed lock.

The manual `Gain timeline qualification` Actions workflow runs the offline
contract gate first and then a non-fail-fast per-radio matrix. Its
`campaigns_json` input is an array such as:

```json
[
  {
    "serial": "EXACT_SERIAL",
    "plan": "/private/rc/serial/gain-timeline-plan.json",
    "confirmation": "QUALIFY GAIN TIMELINE EXACT_SERIAL CAMPAIGN_ID"
  }
]
```

Private plans, password files, and reports remain on the self-hosted runner.
An interrupt is not converted into a test failure: it propagates after the
`finally` restore attempt. A failed restore makes the campaign outcome
`unknown`, never `failed` or `pass`, and requires operator reconciliation.
