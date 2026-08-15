# Hardware acceptance gates

No command in this document should be run against an unspecified radio. Record
the stable serial, USB sysfs path, current firmware, host, operator, and artifact
digests before beginning.

| Gate | Scope | Pass evidence | Mutation |
|---|---|---|---:|
| H1 | Discover one named serial twice | Same serial, URI, sysfs path, firmware | No |
| H2 | Settings/read-back matrix | Requested and actual values within device tolerance | Yes, reversible |
| H3 | Dual-RX capture | Paired shape, channel order, digest-valid artifact | No |
| H4 | Tune/scan restoration | Preview retunes; scan restores exact prior settings | Yes, reversible |
| H5 | Disconnect/reconnect | Bounded failure, no deadlock, serial re-attested | No |
| H6 | Two-radio isolation | Activity on serial A never changes serial B | Yes, reversible |
| H7 | Volatile firmware canary | Exact image/serial/path, RAM boot, expected version, cold rollback | Yes, volatile |
| H8 | Persistent firmware canary | Qualified H7 image, `pluto.frm` only, receipt, expected version | Yes, persistent |
| H9 | Soak | 8–24 h capture/preview, bounded memory/queues, no corrupt artifacts | No |

## Offline and read-only commands

```bash
uv run pytest -q
PLUTO_HARDWARE_SERIALS=SERIAL_A uv run pytest -q -m hardware
PLUTO_HARDWARE_SERIALS=SERIAL_A,SERIAL_B uv run pytest -q -m hardware
```

The current marked tests are read-only discovery/status checks. Capture, direct
transport, RAM firmware, and persistent firmware gates require site-specific
fixtures and remain explicit pending evidence. Never promote a persistent image
that has not passed the volatile canary on the same hardware revision.

For direct transport qualification, start only the daemon composition matching
the named serial:

```bash
uv run plutod --state-root ./acceptance-state --direct-usb SERIAL_A
uv run plutod --state-root ./acceptance-state --direct-ip RADIO_HOST,SERIAL_A
```

Run these alternatives separately. Record sustained sample rate, dropped-frame
metadata, bounded timeout behavior, USB/IP disconnect recovery, and the exact IIO
serial observed before and after each transport test.
