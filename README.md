# Pluto+ Utils

Standalone discovery plus coordinated control, capture, analysis, scanning,
firmware, and web tooling for one or more Pluto+ radios. `pluto radio inventory`
runs directly on the host; stateful control commands and the embedded browser UI
use `plutod` as the sole hardware owner.

## Quick start

```bash
uv sync --all-extras
uv run pytest
uv run pluto serve --fake-radio fake-001
```

Open <http://127.0.0.1:8765>, or use another terminal:

```bash
uv run pluto radio list
uv run pluto radio inventory
uv run pluto radio status fake-001
uv run pluto doctor
uv run pluto doctor fake-001
uv run pluto stream start fake-001
uv run pluto capture start fake-001 --duration 2
uv run pluto scan start fake-001 --start 900000000 --stop 930000000 --step 1000000
uv run pluto artifact list
uv run pluto analyze ARTIFACT_ID --analyzer spectrum --parameters '{"fft_size":4096}'
```

Use `--hardware` to discover serial-pinned USB IIO radios. The `hardware` extra
installs the Python packages, but it cannot install the native libiio shared
library. Check both layers and the required USB backend before opening a radio:

```bash
uv sync --extra hardware
uv run pluto environment
uv run pluto environment --format json
uv run pluto serve --hardware --state-root /var/lib/pluto-plus
```

The supported native host library is the SPF libiio 0.25 line at immutable tag
`spf-frame-metadata-source/v0.25-final-v3` (commit
`c26258bfa33098c2b215e19cf85d448e89499b1a`), built with
`WITH_USB_BACKEND=ON`. On Debian 12 `amd64`/`arm64`, prefer one matching
`libiio-artifacts-v0.25-spfmeta3.*` release bundle from
[`misko/spf`](https://github.com/misko/spf/releases) and its checksum-verifying
`install_spf_libiio_artifacts.sh`. The supported source-build fallback is
[`install_spf_libiio.sh`](https://github.com/misko/spf/blob/main/install_spf_libiio.sh)
with `--series 0.25` and
`--python /path/to/pluto-plus-utils/.venv/bin/python`. Install the matching native
package and generated `pylibiio` wheel into this environment together; an
unmodified PyPI `pylibiio` installation does not provide native libiio.

For a rootless, checkout-local install on Linux, use the repository installer:

```bash
scripts/install_native_libiio.sh
uv run pluto environment
```

It verifies the immutable source commit, builds the USB backend, installs the
matched native library and patched binding into `.venv`, and performs the same
preflight. Pluto+ Utils automatically preloads `.venv/lib/libiio.so.0`; no
`LD_LIBRARY_PATH`, `ldconfig`, or system-wide installation is required.

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

### Full radio inventory table

`radio inventory` is daemon-independent by default and reads the local USB/sysfs
topology without opening a radio. Network discovery is explicit, bounded, and
read-only:

```bash
uv run pluto radio inventory
uv run pluto radio inventory --network
uv run pluto radio inventory --network-cidr 192.168.1.0/24
uv run pluto radio inventory --format json
uv run pluto radio inventory --daemon
```

The default table includes the complete serial, classification, managed state,
radio IP/IIO URI, firmware, USB bus/device and sysfs path, local `/dev/ttyACM*`
terminal, USB-network interface and host IP, mass-storage node, model, and any
identity warning. It also reports negotiated speed, USB specification, advertised
MaxPower, runtime power state, direct-versus-intermediate hub topology, the nearest
xHCI PCI controller, and bounded port-scoped kernel errors/disconnects. MaxPower is
a descriptor budget—not measured voltage, current, or power margin. Unique serials
are the only correlation key. Blank or duplicate
USB serials remain separate and are marked ambiguous rather than guessed.

USB topology is read fresh on every command. `--network` scans private, shared, and
link-local IPv4 networks directly attached to the host, clipping every automatic
range to at most the host's `/24`; `--network-cidr` selects repeatable exact ranges.
Automatic LAN discovery excludes USB-gadget interfaces because multiple attached
Plutos commonly share `192.168.2.1`; those devices are already listed from sysfs.
The aggregate discovery safety limit is 4,096 hosts. Network candidates must pass
serial, model, firmware, PHY, and paired-RX IIOD metadata attestation. Use `--daemon`
when you specifically want managed/discovered daemon state correlated into the
table. Standalone discovery never tunes, captures, or writes radio state and does
not require native libiio.

### Standalone USB/IP speed ladder

`radio ladder` opens one exact radio directly and does not require `plutod`. It
uses ordinary standard-libiio paired-RX buffers, never enables TX, and restores
the original RX settings before returning. USB targets are serial numbers; IP
targets are literal IPv4 addresses, with an exact expected serial strongly
recommended:

```bash
uv run pluto radio ladder 104000b29905000e17000800065934759d --transport usb
uv run pluto radio ladder 192.168.1.15 --transport ip \
  --expect-serial 104000b29905000e17000800065934759d
uv run pluto radio ladder 192.168.1.15 --transport ip \
  --rates 1M,2M,3M,5M --frames 12 --samples 262144 \
  --kernel-buffers 8 --format json
```

The ladder runs the same passive environment preflight before opening its exact
target. Missing Python hardware packages, missing native libiio, an incompatible
native/Python ABI, and a missing USB backend have distinct JSON error codes and
include the underlying import error plus remediation where applicable.

The default ladder is `1M,1.5M,2M,2.5M,3M,5M,10M,20M,30M`. The table reports
offered wire payload, achieved MB/s and MB/min, effective sample rate, delivery
fraction, and per-frame latency. A `kept pace` result means observed host delivery
was at least 90% of the configured sample rate. It is deliberately not described
as gapless: ordinary libiio buffers lack the FPGA sequence metadata needed to
prove continuity. Stop any daemon or other process that owns the selected radio
before running a direct ladder. The ladder explicitly configures 8 RX kernel
buffers by default; use `--kernel-buffers` to compare another bounded count.

### Local USB Fast Lock probe

`radio fastlock-probe` compares ordinary AD9361 RX-LO writes with volatile Fast
Lock recalls on one exact locally attached USB serial. It never accepts an IP
target, arms no RX or TX buffer, verifies TX mute, requires a visibly advancing
FPGA low-32 sample counter, and restores the exact original RX settings. The dry
run resolves the current USB bus/device/interface and prints the serial-specific
confirmation phrase:

```bash
uv run pluto radio fastlock-probe EXACT_SERIAL \
  --lower-hz 959687500 --upper-hz 1190312500 --hops 32
uv run pluto radio fastlock-probe EXACT_SERIAL \
  --lower-hz 959687500 --upper-hz 1190312500 --hops 32 \
  --report /private/fastlock.json --execute \
  --confirm 'FASTLOCK USB EXACT_SERIAL'
```

The measured latency is the host-observed USB IIO attribute-write time, not the
AD9361's internal RF-lock interval. Counter brackets do not locate the exact IQ
sample where lock occurred. During Fast Lock, the ordinary LO-frequency attribute
may remain cached at the last conventional tune; the probe therefore validates the
active profile and the stored sixteen-byte profile readback instead. Metadata
buffers are intentionally excluded because
the tandem owner makes concurrent LO/Fast-Lock writes fail with `EBUSY`.
The selected profile slots are volatile but remain populated after the probe;
use the default high slots only on an otherwise idle radio.

The exact confirmation phrase is the operator's assertion that the selected
radio is otherwise idle. The probe does not acquire a cross-transport ownership
lock or change host network state. It still attests serial and sysfs path before
any buffer, TX, or RF mutation and requires the firmware tandem owner to be idle.
Ordinary and Fast Lock measurements use balanced, interleaved bufferless O-F-F-O
cycles after one unreported warmup cycle.

### Metadata lifecycle soak

`radio soak-metadata` reproduces the bounded context/retune/buffer lifecycle
matrix used by the firmware release gate. It is deliberately separate from the
ordinary-buffer speed ladder: each absolute 30.769230769-second slot opens one
network context, alternates the order of eight LO retunes, and creates fresh
ABI-2 tandem-HOLD metadata buffers for the 1.25/2.5/5 MS/s by 40/80/160 ms
matrix. It refuses catch-up bursts and runs each live slot in a killable child
with a 30-second wall-clock bound.

The command is a dry run unless `--execute` and its exact confirmation phrase
are supplied. Execution also requires a serial-specific pinned SSH host-key file
so it can prove unchanged Linux boot ID, iiOD PID/start time/generation, zero
buffer ownership, zero tandem fault/overflow, and TX1/TX2 `-80 dB` after every
slot. It restores RX settings and writes an atomic mode-0600 JSON report on both
pass and failure:

```bash
uv run pluto radio soak-metadata 192.168.1.15 \
  --expect-serial 104000b29905000e17000800065934759d --slots 9
uv run pluto radio soak-metadata 192.168.1.15 \
  --expect-serial 104000b29905000e17000800065934759d --slots 9 \
  --ssh-known-hosts-file /private/radio.known_hosts \
  --ssh-password-file /private/radio.password --report /private/soak.json \
  --execute --confirm 'SOAK METADATA 104000b29905000e17000800065934759d 9'
```

The nine-slot matrix is the practical release regression. The full `--slots
936` campaign remains the long-soak gate and takes eight hours at the fixed
period. Stop any competing owner before execution.

`pluto doctor` is also standalone by default. It reads fresh IIOD facts through
each exact USB-gadget network interface and reports identity, Rev.C model,
canonical v5 firmware, AD9361 PHY, paired-RX devices, metadata, and facts that
remain unprovable without the authenticated setup inspector:

```bash
uv run pluto doctor
uv run pluto doctor --usb-sysfs-path /sys/bus/usb/devices/3-11 --format json
uv run pluto doctor MANAGED_RADIO_ID  # explicitly uses plutod
uv run pluto doctor --daemon          # all daemon-managed radios
```

The passive sweep reports `transport.rx_data_plane` as `unknown`, because IIOD
metadata alone cannot prove that a buffer refill completes. When the selected radio
is quiescent, request one bounded 65,536-sample-per-channel refill on an exact USB
target:

```bash
uv run pluto doctor --usb-sysfs-path /sys/bus/usb/devices/3-11 \
  --probe-data-plane --format json
```

If that probe reports an `ETIMEDOUT` while IIOD metadata remains responsive, use the
standalone recovery lane. It derives the USB topology and interface from the serial,
does not require canonical AD9361/2R2T setup, and is a dry run until explicitly
confirmed:

```bash
uv run pluto radio recover SERIAL --data-plane \
  --ssh-known-hosts-file /private/SERIAL.known_hosts
uv run pluto radio recover SERIAL --data-plane \
  --ssh-known-hosts-file /private/SERIAL.known_hosts \
  --ssh-password-file /private/SERIAL.password \
  --execute --confirm 'RESTART IIOD SERIAL'
```

Execution is allowed only when the pre-probe failed as a receive timeout. The fixed
SSH script re-attests the remote gadget serial, records the old and replacement IIOD
PID/start epoch plus CMA and active-buffer evidence, and the command retries a fresh
bounded refill before issuing a mode-0600 receipt. A healthy, wrong-identity, or
host-environment failure never triggers a restart. LAN recovery uses `--ssh-host` and
the independently pinned key for that exact endpoint.

To prevent the known trigger, every `IioRadioDevice` ordinary and metadata capture
rejects a single RX allocation above 32 MiB: half of the supported firmware's 64 MiB
CMA pool. Use repeated/streaming buffers for longer captures. This avoids relying on a
nearly pristine contiguous CMA region even when `CmaFree` is high.

### Persistent setup inspection and repair

Without credentials doctor cannot reach the persistent U-Boot environment and
reports `setup.uboot_ad9361_2r2t` as `unknown`. Give it an enrolled known_hosts
file for one exact radio and it reads the real tuple instead — and repairs a
non-canonical one by default:

```bash
uv run pluto doctor \
  --usb-sysfs-path /sys/bus/usb/devices/3-11 \
  --setup-known-hosts-file ~/.local/state/pluto-plus-utils/ssh/SERIAL.known_hosts \
  --setup-password-file ~/.config/pluto-plus/radio.pw

uv run pluto doctor ... --no-fix   # read the tuple, change nothing
```

Repair is not a new mutation path: it drives the same guarded setup transaction
as `pluto setup plan` / `pluto setup execute`, so every run still backs up the
complete environment, applies the fail-closed TX mute, binds the environment
digest, reboots, re-attests the exact serial and path, and writes a receipt.
A radio that is already canonical is never written to.

Two boundaries keep the default-on repair bounded. It needs
`--setup-known-hosts-file`, so a doctor run without credentials cannot mutate
anything; and it needs `--usb-sysfs-path`, because a pinned host key and the
private `192.168.2.1` endpoint each address exactly one radio. The no-argument
sweep across every attached radio therefore stays read-only.

Only the `attr_name`/`attr_val`/`compatible`/`mode` tuple is repaired. Firmware
version mismatches are reported, never auto-flashed.

### Stale firmware and host libiio

`firmware.release_currency` compares the radio against `UPGRADE_TARGET_PROFILE`,
the newest **full** hardware-qualified release. Release candidates, development
builds, and RAM-only promotion candidates are deliberately excluded, and the
comparison uses an explicit `release_rank` rather than list position, so a radio
already on something newer is never offered a downgrade.

The report also carries `host_libiio`, the host-local libiio preflight that
`pluto environment` runs. It gates every radio, so a broken host is reported once
rather than per radio.

When either has a known fix, doctor offers it after an explicit `y`:

```bash
uv run pluto doctor          # prompts per finding, default no
uv run pluto doctor --yes    # show every fix without prompting
```

Prompting is suppressed for `--format json` and when stdin is not a TTY, so
scripts and CI are unaffected; a non-interactive run prints how many findings
have a fix and nothing else.

The offer prints the exact command rather than executing it. For libiio that is
deliberate. For firmware it is also a limitation: nothing in this project
downloads release assets, so doctor has no image to flash and cannot complete an
upgrade on its own.

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
and use the receipt's read-only reconciliation action. Firmware which regenerates its
SSH key on reboot is handled automatically only for the exact USB endpoint: setup first
proves that the selected serial/path disappeared and returned, rechecks the unambiguous
USB route, attests the same remote gadget serial, atomically archives the prior key, and
records both key fingerprints/digests in the receipt. LAN-routed replacement keys still
require independent out-of-band verification and are never accepted from IP identity.

## Guarded config.txt and static IP workflow

On Pluto firmware, `/opt/config.txt` is generated at boot from persistent U-Boot
environment values; editing that file directly is not a durable configuration API.
Pluto+ Utils therefore exposes a password-redacted read view and structured changes
for only the documented Ethernet and USB-gadget network variables. It does not expose
WLAN passwords, `[ACTIONS]`, arbitrary environment keys, remote paths, or shell commands.

The feature reuses an exact-radio pinned-SSH enrollment described below. Reads and
mutations require the admin token and a protected transport. Example Ethernet workflow:

```bash
uv run pluto --admin-token-file /private/admin.token config status
uv run pluto --admin-token-file /private/admin.token config show EXACT_HARDWARE_SERIAL
uv run pluto --admin-token-file /private/admin.token config plan EXACT_HARDWARE_SERIAL \
  --interface ethernet --mode static --address 192.168.1.165 \
  --netmask 255.255.255.0
uv run pluto --admin-token-file /private/admin.token config execute PLAN_ID \
  --token ONE_TIME_TOKEN \
  --operator-confirmation 'SET STATIC IP EXACT_HARDWARE_SERIAL 192.168.1.165'
uv run pluto --admin-token-file /private/admin.token config receipt-list
```

Use `--mode dhcp` with `--interface ethernet` to remove the persistent static
Ethernet address. USB gadget changes use `--interface usb_gadget --mode static`
and additionally require `--host-address`. Every plan is bound to the selected
serial, enrolled endpoint and host key, fresh canonical-network-value digest, exact
change set, expiry, and one-time token. Execution writes a private complete
environment backup, performs one batch update, and verifies persistent read-back.

Saving intentionally does **not** restart the radio. Before restarting after an
Ethernet address change, update the daemon's `--iio-ip` target and the pinned-SSH
enrollment to the new endpoint. The Web Network panel implements the same workflow
and reuses the in-memory admin-token input. See [ADR 0005](docs/adr/0005-structured-network-config.md).

## Guarded firmware workflow

### Local release-candidate RAM lifecycle

`firmware candidate-ram` is the native owner-operated path for loading a
release candidate into volatile RAM. It is separate from the legacy static
profiles below: the firmware repository emits a canonical candidate plan, this
utility owns every live device operation, and the firmware repository consumes
the resulting semantic receipt.

Capture the current USB topology and create one per-radio plan without opening
IIO, SSH, DFU, or changing a radio:

```bash
install -d -m 0700 /private/rc14
uv run pluto firmware candidate-ram inventory \
  --output /private/rc14/usb-inventory.json
uv run pluto firmware candidate-ram plan \
  --candidate-plan /private/rc14/candidate-plan.json \
  --usb-inventory /private/rc14/usb-inventory.json \
  --serial EXACT_SERIAL \
  --expected-current-firmware EXACT_CURRENT_VERSION \
  --receipt /private/rc14/hardware/deploy/EXACT_SERIAL/ram-receipt.json \
  --output /private/rc14/EXACT_SERIAL-operation-plan.json
```

After reviewing the plan, execute from a fully clean `pluto-plus-utils`
checkout at the exact repository/version/commit named by the candidate plan.
The exact confirmation phrase is printed by `plan`:

```bash
uv run pluto firmware candidate-ram execute \
  --operation-plan /private/rc14/EXACT_SERIAL-operation-plan.json \
  --ssh-password-file /private/credentials/EXACT_SERIAL.password \
  --tool-repository "$PWD" \
  --confirm 'RAM BOOT RELEASE CANDIDATE EXACT_SERIAL'

uv run pluto firmware candidate-ram receipt-verify \
  /private/rc14/hardware/deploy/EXACT_SERIAL/ram-receipt.json
```

RAM Dropbear keys are intentionally ephemeral. Candidate SSH therefore uses
password authentication through the exact USB interface and owned `/32` route,
with both known-host databases set to `/dev/null`; no host key is retained or
used as an authorization gate. The utility still binds the exact serial,
direct USB topology, candidate DFU/FIT bytes, pre/post boot IDs, unchanged
`qspi-linux` digest, and complete muted DDS/DAC/tandem safe state. Its only DFU
sequence uses paired `0456:b673,0456:b674`, the selected physical port, and the
`firmware.dfu` alternate followed by detach. `-R`, `-S`, arbitrary MTD paths,
and persistent targets are outside this command.

The full ownership and migration decision is recorded in
[`docs/adr/0006-release-candidate-device-lifecycle.md`](docs/adr/0006-release-candidate-device-lifecycle.md).

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

### Blank-serial USB bootstrap

For a normal serial-attested local USB radio, `firmware flash` provides a
standalone preview/execute flow and requires the exact `FLASH <serial>` phrase:

```bash
uv run pluto firmware flash /absolute/path/to/qualified-pluto.dfu \
  --usb-sysfs-path /sys/bus/usb/devices/3-8
uv run pluto firmware flash /absolute/path/to/qualified-pluto.dfu \
  --usb-sysfs-path /sys/bus/usb/devices/3-8 \
  --execute --confirm 'FLASH EXACT_SERIAL'
```

`firmware force-flash` (aliases `bootstrap-usb` and `force-flash-usb`) is an exceptional,
daemon-independent recovery command for a directly attached Pluto whose USB and
IIOD serials are both blank. It is not a generic validation bypass: it accepts
only the exact hardware-qualified canonical DFU digest, requires one explicit
direct USB sysfs port, verifies the live Rev.C model and USB network/storage
topology, and refuses a radio that already has a stable serial.

Run it once without `--execute` to get a read-only plan:

```bash
uv run pluto firmware force-flash /absolute/path/to/qualified-pluto.dfu \
  --usb-sysfs-path /sys/bus/usb/devices/3-11
```

Review every path, hash, and the generated confirmation phrase. Execute that
same target only by adding both flags printed by the preview:

```bash
uv run pluto firmware force-flash /absolute/path/to/qualified-pluto.dfu \
  --usb-sysfs-path /sys/bus/usb/devices/3-11 \
  --execute --confirm 'BOOTSTRAP 3-11'
```

Execution re-runs all preconditions, converts the DFU deterministically, mounts
the correlated updater partition through UDisks, writes only `pluto.frm`, syncs,
unmounts, ejects, and then requires the same physical port to return with
matching USB/IIOD identity plus the expected firmware and metadata. A force-flashed
unit whose hardware cannot derive a serial may remain consistently blank; the
firmware result can still be verified, but `doctor` keeps identity failed. Do not
unplug the radio during the update. A failure after `pluto.frm` is written is recorded as
`outcome: unknown`; do not retry it until the radio and durable receipt have
been reconciled.

For an uncertain serial-attested standalone SSH flash, reconcile the durable
receipt without replaying the update:

```bash
uv run pluto firmware reconcile-local RECEIPT_ID \
  --usb-sysfs-path /sys/bus/usb/devices/3-8 \
  --profile EXACT_PERSISTENT_PROFILE \
  --ssh-known-hosts-file /private/radio.known_hosts \
  --ssh-host 192.168.1.14
```

This command is hardware-read-only. It validates the receipt and immutable
profile, re-attests USB and IIOD identity, reads the complete TX/DDS safe state,
and hashes exactly the receipt-recorded FIT length from `mtd3`. It never stages
an image, invokes the updater, changes RF state, or reboots. A mismatch leaves
the attempt unresolved and must not be treated as permission to retry.

If the host UDisks service is unavailable, the same local command can use the
radio's fixed updater over SSH while remaining bound to the selected USB network
interface. The radio host key must already be pinned in a private `known_hosts`
file; there is no trust-on-first-use during execution. Omit the password-file
option to receive a hidden prompt:

```bash
uv run pluto firmware force-flash /absolute/path/to/qualified-pluto.dfu \
  --usb-sysfs-path /sys/bus/usb/devices/3-11 \
  --transport ssh --ssh-known-hosts-file /private/radio.known_hosts \
  --execute --confirm 'BOOTSTRAP 3-11'
```

This path verifies the staged FRM hash, requires an unambiguous updater `Done`,
independently hashes the exact FIT bytes in `mtd3`, removes the stage, reboots,
and retries post-return IIOD attestation while services start. It never exposes
an arbitrary remote command or updater path.

### Explicit LAN TOFU enrollment

When the exact radio cannot be physically USB-attached, an operator may
explicitly enroll its LAN SSH key using the factory-default password. First run
the read-only plan:

```bash
uv run pluto firmware enroll-lan-ssh EXACT_SERIAL \
  --host 192.168.1.20 \
  --profile libiio-metadata-v5 \
  --known-hosts-file /private/EXACT_SERIAL.lan-20.known_hosts
```

The plan reads only that host's bounded IIOD context and requires the exact
serial, immutable firmware profile, AD9361/paired-RX scan layout, metadata ABI,
and profile-specific tandem capability. Review it, then repeat with both explicit
guards:

```bash
uv run pluto firmware enroll-lan-ssh EXACT_SERIAL \
  --host 192.168.1.20 \
  --profile libiio-metadata-v5 \
  --known-hosts-file /private/EXACT_SERIAL.lan-20.known_hosts \
  --execute --use-default-password \
  --confirm 'TRUST LAN SSH EXACT_SERIAL 192.168.1.20'
```

This is deliberately **LAN trust on first use**, not a USB physical-path trust
anchor. A network attacker capable of consistently impersonating both IIOD and
SSH may defeat it, so prefer `firmware enroll-usb-ssh` whenever physical USB is
available. Enrollment accepts the first key only into a new mode-0600 temporary
file, disables user and global SSH trust, reconnects with strict checking to run
only the fixed gadget-serial read, and publishes atomically without overwriting.
It never writes `~/.ssh/known_hosts` or a global known-hosts file. Key rotation
requires a separately reviewed new destination path.

### Experimental pinned-SSH radio administration

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
serial and IP with `--ssh-radio-admin-enrollment /absolute/private/enrollment.json`
(the existing `--ssh-firmware-enrollment` name remains an alias). This enables the
structured network-config surface and the canonical SSH firmware transport for that
exact managed serial. The API remains unavailable for privileged operations over
non-loopback plaintext HTTP.

```bash
uv run pluto --admin-token-file /private/admin.token firmware upload RELEASE.dfu
uv run pluto --admin-token-file /private/admin.token firmware plan EXACT_HARDWARE_SERIAL IMAGE_ID \
  --mode persistent_qspi --transport ssh \
  --expected-version v0.39-plutoplus-spf-libiio-metadata-v6
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

### Serial-scoped local USB reboot

Use a guarded reboot when qualification needs a fresh boot epoch without another
QSPI write. The standalone command requires one exact local USB serial, sysfs
topology, USB network interface, and previously enrolled private `known_hosts`
file. Its default is a read-only plan:

```bash
uv run pluto radio reboot-local EXACT_SERIAL \
  --usb-sysfs-path /sys/bus/usb/devices/3-8 \
  --ssh-known-hosts-file /private/EXACT_SERIAL.known_hosts
```

Review the plan, then repeat with `--execute --confirm 'REBOOT EXACT_SERIAL'`.
Use `--ssh-password-file /private/radio.password` or enter the password at the
hidden prompt. Before dispatch, the command re-attests the local topology and
remote serial and mutes TX1/TX2 to -80 dB with DDS and TX buffers disabled. It
accepts return only after the same USB topology disappears and reappears with a
new boot identity and unchanged serial, firmware, and capabilities, then repeats
the TX mute/readback. Every dispatched attempt gets an atomic mode-0600 receipt
under `~/.local/state/pluto-plus-utils/reboot-receipts`. USB route ambiguity is a
hard refusal; the command never falls back to network discovery or another radio.
For a unique LAN endpoint, pass `--ssh-host 192.168.1.X`; the command retains the
exact USB serial/path checks but deliberately uses the normal LAN route without
binding the shared USB-gadget subnet. If firmware rotates its SSH key on reboot,
the new key is never trusted: return is independently attested and TX-muted through
the already selected USB-IIOD interface.

When several local Pluto gadget interfaces all claim `192.168.2.10/24` and the
radio endpoint `192.168.2.1`, add `--isolate-usb-route` to the dry run. The plan
records the selected interface, peer Pluto interfaces, overlapping host routes,
and the separate confirmation phrase `ISOLATE USB SSH <interface>`. Repeat the
enrollment or reboot with both its normal confirmation and
`--isolation-confirm 'ISOLATE USB SSH <interface>'`. Execution requires `ip`,
`networkctl`, and non-interactive sudo. It writes an atomic mode-0600 receipt
under `~/.local/state/pluto-plus-utils/host-isolation-receipts`, temporarily
removes only the recorded competing routes and peer Pluto links, attests the
selected route, runs the bounded operation, and restores the host network in a
`finally` block. Uncertain restoration always overrides operation success.

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
