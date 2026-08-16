# Pluto+ Utils

Standalone control, capture, analysis, scanning, firmware, and web tooling for
one or more Pluto+ radios. `plutod` is the sole hardware owner; both the `pluto`
CLI and embedded browser UI use its versioned API.

## Quick start

```bash
uv sync --all-extras
uv run pytest
uv run pluto serve --fake-radio fake-001
```

Open <http://127.0.0.1:8765>, or use another terminal:

```bash
uv run pluto radio list
uv run pluto radio status fake-001
uv run pluto doctor
uv run pluto doctor fake-001
uv run pluto stream start fake-001
uv run pluto capture start fake-001 --duration 2
uv run pluto scan start fake-001 --start 900000000 --stop 930000000 --step 1000000
uv run pluto artifact list
uv run pluto analyze ARTIFACT_ID --analyzer spectrum --parameters '{"fft_size":4096}'
```

Use `--hardware` to discover serial-pinned USB IIO radios. Native dependencies
live in the `hardware` extra and are imported only by the daemon:

```bash
uv run pluto serve --hardware --state-root /var/lib/pluto-plus
```

Standard network/libiio radios are explicit and may optionally be pinned to a
known serial:

```bash
uv run plutod --iio-ip 192.168.1.15 --iio-ip 192.168.1.20,SERIAL
```

For DHCP-managed radio LANs, use bounded read-only discovery instead of listing
device addresses. Every serial-attested Pluto appears in the Web inventory, but
only explicitly promoted serials are opened for tuning or capture:

```bash
uv run plutod \
  --discover-iio-network 192.168.1.0/24 \
  --manage-discovered-iio EXACT_DEVELOPMENT_SERIAL
```

Discovery probes the standard libiio TCP port, then verifies the reported model,
serial, firmware, AD936x PHY, and paired-RX buffer topology. CIDRs are limited to
4,096 unique hosts and duplicate serials fail closed. Inventory-only radios are
labelled `discovered` in the Web selector and cannot be tuned, recovered, or
streamed until their serial is explicitly promoted at daemon startup.

Loopback is the safe default. Setup and firmware mutations have a separately configured
bearer-token and strict browser-Origin boundary, but ordinary tune/stream/capture routes
are intentionally not a general remote-authentication system. For a local multi-user
deployment, bind a Unix socket and point clients at it:

```bash
uv run plutod --hardware --uds /run/pluto-plus/plutod.sock
uv run pluto --endpoint unix:///run/pluto-plus/plutod.sock radio list
```

## Architecture and data

- One controller owns each radio and serializes configuration, paired RX refill,
  stream, scan, and firmware transitions.
- Settings updates use optimistic revisions and hardware read-back verification.
- WebSocket presentation queues are bounded and discard stale frames rather than
  blocking acquisition.
- Persistent captures are bounded atomic SigMF-like `ci16_le` artifacts. Their
  SHA-256 digest is verified before analysis.
- Preview streams can tune live. Persistent captures lock frequency, sample
  rate, bandwidth, and channel axes so an analysis never silently combines
  incompatible epochs.
- Spectrum, carrier, occupancy, CI16 quality, and dual-receiver
  delay/coherence/phase analyzers operate only on immutable artifacts.

State is stored below `--state-root`: SQLite catalog, captures, scan results,
analysis documents, firmware staging, and firmware receipts.

### Browser diagnostics

The embedded UI writes structured `[pluto+]` events to the browser developer
console for initialization, API status and latency, WebSocket lifecycle and
reconnects, first-frame payload size, canvas resizes, invalid frames, long tasks,
and event-loop stalls. During a preview it emits a bounded waterfall summary every
five seconds or 50 rendered frames with payload KiB/s, render FPS, coalesced-frame
count, and sequence progress. Run `plutoDiagnostics()` in the console for the
current cumulative snapshot. Request bodies, authorization headers, and setup or
firmware tokens are never logged.

The doctor compares each radio with an explicit, profile-aware canonical policy.
It reports active firmware, live AD9361/dual-RX facts, USB correlation, persistent
setup provenance, and guarded remediation. Read
[`docs/FLASHING_AND_DOCTOR.md`](docs/FLASHING_AND_DOCTOR.md) before any Pluto+
setup or firmware operation.

Canonical AD9361/2R2T setup is a distinct inspect → plan → confirm → execute workflow:

```bash
uv run pluto --admin-token-file /private/admin.token setup status
uv run pluto --admin-token-file /private/admin.token setup plan RADIO_ID
uv run pluto --admin-token-file /private/admin.token setup execute PLAN_ID --token TOKEN
uv run pluto --admin-token-file /private/admin.token setup receipt-list
```

The daemon enables this only with `--enable-canonical-setup` plus one exact serial,
USB sysfs path, USB network interface/address, private password file, pinned host-key
file, admin token file, and allowed browser Origin. The Web Doctor panel exposes the
same guarded flow and never renders or stores the one-time token. Read-only radio and
doctor views may remain LAN-visible, but privileged Web/API requests are accepted only
over HTTPS, a Unix socket, or loopback (for example through an SSH tunnel); the browser
will not send the bearer token over non-loopback plaintext HTTP.

If execution becomes uncertain after mutation or reboot, the receipt records the last
completed phase and durable backup reference. Do not replay the consumed plan. Re-attest
and, if necessary, explicitly re-pin the selected radio's SSH host key out of band, then
use the receipt's read-only reconciliation action.

## Guarded firmware workflow

Firmware is fail-closed unless the service is constructed with an explicit
privileged executor. The normal workflow is inspect → upload → plan → verify the
serial/path/hash/mode/expected version → execute the short-lived one-time token.
The CLI surface is:

```bash
uv run pluto firmware status
uv run pluto firmware inspect RADIO_ID
uv run pluto firmware upload candidate.dfu
uv run pluto firmware plan RADIO_ID IMAGE_ID --mode volatile_dfu --expected-version v0.39
uv run pluto firmware execute PLAN_ID --token TOKEN
uv run pluto firmware receipt-list
```

The domain implementation validates Pluto DFU/FIT/FRM structure and checksums,
generates only firmware-safe `pluto.frm`, binds plans to serial/sysfs path/current
firmware/image digest, and records every authorized attempt. Persistent updates
refuse archives and `boot.frm`. The concrete mass-storage updater selects exactly
one injected `ID_SERIAL_SHORT` match and never guesses via `/dev/sd*` globs.

The default daemon deliberately reports firmware unavailable: installing the
site-specific privileged helper, exact-radio DFU transition, and block-device
enumerator is a hardware deployment checkpoint, not an offline-safe default.
Once that separately installed helper is listening on a protected Unix socket,
compose the client boundary explicitly with
`plutod --firmware-helper-socket /run/pluto-plus/firmware-helper.sock ...`.

### Experimental network firmware transport

An IP-attached, managed IIO radio can be explicitly enrolled for a canonical,
persistent `pluto.frm` update. Network discovery alone never grants this ability.
Enrollment is a private mode-0600 JSON file:

```json
{
  "serial": "EXACT_HARDWARE_SERIAL",
  "host": "192.168.1.165",
  "username": "root",
  "known_hosts_file": "/absolute/private/radio.known_hosts",
  "private_key_file": "/absolute/private/radio_ed25519"
}
```

The known-host key must be verified out of band; the daemon never performs
trust-on-first-use. Add the enrollment to a daemon that already manages the same
serial and IP with `--ssh-firmware-enrollment /absolute/private/enrollment.json`.
The API remains unavailable for mutation over non-loopback plaintext HTTP.

```bash
uv run pluto --admin-token-file /private/admin.token firmware upload RELEASE.dfu
uv run pluto --admin-token-file /private/admin.token firmware plan EXACT_HARDWARE_SERIAL IMAGE_ID \
  --mode persistent_qspi --transport ssh \
  --expected-version v0.38-plutoplus-spf-libiio-metadata-v5
uv run pluto --admin-token-file /private/admin.token firmware execute PLAN_ID --token TOKEN \
  --operator-confirmation 'FLASH EXACT_HARDWARE_SERIAL'
uv run pluto --admin-token-file /private/admin.token firmware reconcile RECEIPT_ID
```

The SSH transport accepts only the hardware-qualified canonical FIT, invokes only
the fixed on-radio FRM updater, verifies the exact `mtd3` FIT body before reset,
and records durable phases. A disconnect after updater dispatch is an unknown
outcome and must be reconciled, never replayed. A rebooted radio that presents a
new SSH host key is locked out until that key is verified and re-enrolled out of
band. See [ADR 0004](docs/adr/0004-ssh-staged-firmware.md).

## Direct transport status

`pluto_plus.direct_radio` contains USB v3 and direct-IP v1 wire parsers, bounded
I/O, CRC/order validation, and dual-RX CI16 conversion. Direct-IP has a finite
UDP adapter selected with `--direct-ip HOST,SERIAL`; direct USB has a lazily
loaded libusb adapter selected with `--direct-usb SERIAL`. Both pair capture with
serial-attested IIO control and fail closed on identity mismatch. Protocol,
real-loopback IP, and fake-backend USB tests pass without an SPF runtime
dependency. Physical throughput and reconnect behavior remain behind the
attached-radio acceptance gate; see
`src/pluto_plus/direct_radio/README.md`.

## Verification

```bash
uv run pytest -q
uv run ruff check src tests
uv run mypy src/pluto_plus
uv build
```

The default lane never mutates hardware. Set `PLUTO_HARDWARE_SERIALS` only for
the marked read-only/capture acceptance tests. RAM firmware and persistent QSPI
qualification require explicit, separately reviewed commands; see
`docs/HARDWARE_ACCEPTANCE.md` and `docs/IMPLEMENTATION_PLAN.md`.
