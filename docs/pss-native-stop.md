# Native PSS map-boundary stop operations

This experimental API admits exactly shared-XFFT **15 MS/s PSMA ABI 1.6**:
capabilities `0x33f`, 20,000 bins, 64 frames, 200 chunks/map, DDC configuration
`0x000f0202` and zero DDC delay. Existing defaults and ABI 1.5 opt-in are unchanged.
This is host software support, not qualification of an FPGA image or radio.

Select both `experimental_shared_xfft=True` and
`experimental_boundary_stop=True` when connecting `PssIioClient`, with the
exact reserved radio serial. Use an externally attested `ObservationIdentity`
whose profile is `ProcessingProfile.PAIRED_15_SHARED_XFFT_512_447_STOP_V1`.
Boot, visit, RF configuration and processing fingerprint remain the owner's
responsibility; cached IIO context metadata does not prove a fresh hardware epoch.

On an already-owned, opened map session:

```python
request = client.request_map_stop(
    observation, ticket=next_ticket, timeout_ms=1000, budget_ms=5000,
)
status = client.read_map_stop(
    observation, expected_ticket=next_ticket, timeout_ms=1000, budget_ms=5000,
)
```

These calls do not open a buffer, flush acquisition, poll until terminal,
drain maps, cancel native I/O or close the context. Run them **between** bounded
map refills; concurrent operations on the same client are rejected. Each call
retains separately observed identity, exact contract attributes, raw PSST text,
attempted/returned write state and errors. Contract attributes are checked
before and after the stop observation. The receipt retains configured timeout,
total budget and observed elapsed milliseconds. Finite per-operation timeouts and a
total budget do not guarantee that an unresponsive native call returns at an
exact wall-clock deadline; a late return must not qualify as a complete operation.

`PssMapStopOperation.complete` describes completion of these I/O observations,
not success of the stop itself. A complete read can legitimately report
pending, failed or historical state. Write acknowledgment and observed ticket
acceptance are distinct from a terminal boundary. A write error can leave
hardware acceptance unknown; retain the error receipt and resolve it with a
separate read, not an automatic retry or a fabricated zero ticket.

After a matching terminal is observed, the existing pure
`PssMapStopReceipt.require_boundary_complete(expected_ticket=...)` checks its
structural meaning. It still does not prove RF health, kernel delivery, durable
host storage or detection. Retain fresh acquisition health and every raw map
chunk through the terminal generation. Empty hardware ready banks alone are
not evidence of host delivery. See [the receipt contract](pss-stop-receipt.md).

## Recorder integration requirements

- For a finite stop/drain workflow, open maps with `refill_chunks=200` and
  `batch_mode=True`. The legacy 400-chunk default can wait for a nonexistent
  second map when the terminal map count is odd.
- `open_maps()` currently flushes acquisition. Open it **before pilot ARM**;
  never invoke it to restart coarse processing during an active pilot capture.
- Request tickets are explicit nonzero u32 values: accepted-ticket replay is
  idempotent, otherwise the next ticket is required. Never wrap after `0xffffffff`.
  Replaying an old accepted ticket cannot stop a newly rearmed acquisition.
- Bind maps, pilot IQ and fine results to the same observation, while checking
  their complete source-support intervals independently. Decimated pilot centers
  do not constitute a recording of every full-rate sample.
- Retain failures and partial data. Stop/join bounded readers before the existing
  graceful teardown; do not disable the map buffer merely because a stop request
  was acknowledged.

The integrated terminal-generation drain ledger, paired recorder, blind GLRT
comparison, network/radio deployment, and 30/60 MS/s stop profiles are separate
milestones. This increment does not implement or qualify them.
