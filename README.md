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

### Measuring reference error against a seeded frequency hop

> **⚠️ Closed, conducted paths only.** The example below uses 11 GHz, which is
> satellite downlink spectrum. These are theoretical bench procedures and must
> **never be performed over open air** -- terrestrial transmission there is
> prohibited in essentially every jurisdiction and interferes with satellite
> reception well beyond your own site. This host only *listens*, but whoever
> operates the transmitter must keep it conducted: coax, attenuation, shielding,
> and no antenna on either end.

A transmitter that this host does not control can hop among a set of frequencies
in an order derived entirely from a seed both ends already know. The receiver
regenerates the identical schedule, so it never infers which point it is
hearing: the only unknown is the epoch, and that is one bounded search. After
alignment, every frame's frequency point is known and each point's frequency
error follows directly.

This supersedes duration coding, where a point announced itself by how long its
burst lasted. On this bench, over the same hardware and equal capture time, the
duration-coded ladder never identified more than **1 burst in 95**, while the
seeded hop identified **100% of points in every configuration tried**. Duration
estimation needs hysteresis, gap merging and a rounding tolerance, and it fails
outright once several points share the capture band, because the envelope never
returns to the floor between them.

**Transmit side.** Not this tool -- the hop comes from whatever generates it, and
whoever runs it is responsible for keeping it off the air. With an ADF5355
driven by [`adf5355_tester`](https://github.com/misko/adf5355_tester):

```bash
adf5355 hop --seed 0xC0FFEE --start-ghz 11.0 --stop-ghz 11.00171 \
            --points 20 --min-hop-ms 10 --cycles 300 --power 0 --enable-rf
```

**Receive side.** One capture is enough: the whole span must fit the receiver's
instantaneous bandwidth so a single tuning hears every point. Tune to the span
midpoint, minus the nominal LNB LO, minus the LO error already known -- here
11.000855 - 9.750 GHz = 1.250855 GHz, less the 94 kHz this LNB measures high, so
1.250761 GHz. Skipping that last term is not cosmetic: it slides the whole comb
94 kHz down the passband and leaves the lowest point about 960 kHz off centre, at
the edge of what 2.5 MS/s actually resolves. Pin the analog bandwidth too, so a
narrower setting left over from an earlier session cannot quietly filter the
outer points:

```bash
uv run pluto radio settings set RADIO \
  --frequency 1250761000 --sample-rate 2500000 --bandwidth 2500000
uv run pluto capture start RADIO --duration 8

uv run pluto calibrate seeded-hop ARTIFACT_ID \
  --seed 0xC0FFEE --rung-start-hz 11.0e9 --rung-stop-hz 11.00171e9 \
  --points 20 --hop-seconds 0.010 --lo-hz 9.75e9
```

Recommended defaults, all measured on 8 s captures at 2.5 MS/s: fixed 10 ms
dwell, 20 points, 1.71 MHz span (11.0 to 11.00171 GHz, 90 kHz spacing), seed
`0xC0FFEE`. Precision tracks dwell, because dwell is integration time -- 2 ms
gave 2946 Hz of scatter, 5 ms gave 1361 Hz, and 10 ms gave 730 Hz. Dwell jitter
changed nothing measurable, so a fixed dwell is preferred: it makes epoch
alignment a uniform grid search.

The decode reports its own confidence and never hides a weak result. `comb`
carries the bulk offset of the whole comb - the LNB local-oscillator error,
about -106 kHz at a 1.25 GHz IF on this bench - with a sharpness figure that ran
37x to 422x on real captures. `epoch` carries the alignment and how far it stood
above every other shift. A capture that decodes weakly comes back with
`confident: false` and named warnings, and points with too few strong frames
report a null measurement instead of a median of noise. The same analyzer is
reachable as `pluto analyze ARTIFACT_ID --analyzer seeded_hop`.

Use `--hardware` to discover serial-pinned USB IIO radios. The `hardware` extra
installs the Python packages, but it cannot install the native libiio shared
library. Check both layers and the required USB backend before opening a radio:

```bash
uv sync --extra hardware
uv run pluto environment
uv run pluto environment --format json
uv run pluto serve --hardware --state-root /var/lib/pluto-plus
```

The native host library is selected by the radio's declared metadata ABI and
must be installed with the Python binding from the same source commit. ABI 1
uses SPF libiio 0.25 tag `spf-frame-metadata-source/v0.25-final-v3` at
`c26258bfa33098c2b215e19cf85d448e89499b1a`. The current direct-async/RAM-extension
ABI-3 runtime requires libiio 0.25 commit
`5cb2389719d46d12463daa0371d1fda19eb25fa7` and tag
`iq-direct-async-v4-source/libiio-v1`. It keeps as many as 4,096 frames in one
finite session, exposes both overrun policies, recovers stale metadata, and
requires the kernel's allocated DMA count to exactly match the request. Full
persistent firmware release
[`v0.49-plutoplus-spf-iq-direct-async-v4`](https://github.com/misko/plutosdr-fw/releases/tag/v0.49-plutoplus-spf-iq-direct-async-v4)
contains the matched radio runtime and a 216 MiB CMA pool admitting the
qualified 50 × 1,000,000-sample queue as exactly 200,000,000 IQ bytes. The
installer fails closed on every older ABI-3 build. See
[`docs/METADATA_CAPTURE_RUNTIME.md`](docs/METADATA_CAPTURE_RUNTIME.md) for the
complete matrix and status.

Host libiio is built with `WITH_USB_BACKEND=ON`. On Debian 12 `amd64`/`arm64`,
prefer one matching
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
scripts/install_native_libiio.sh \
  --uv-bin /ABSOLUTE/PATH/TO/NON-SYMLINK/uv \
  --metadata-abi 3 \
  --python "$PWD/.venv/bin/python" \
  --prefix "$PWD/.venv"
uv run pluto environment
```

It verifies the immutable source commit, builds the USB backend, installs the
matched native library and patched binding into `.venv`, and performs the same
preflight. Pluto+ Utils automatically preloads `.venv/lib/libiio.so.0`; no
`LD_LIBRARY_PATH`, `ldconfig`, or system-wide installation is required. Use
`--metadata-abi 1` for the currently deployed production ABI-1 radios; ABI 3
is only for the exact source-qualified stack described above.

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

### Plan-gated RX environment survey

`environment-survey` is the standalone, exact-USB chamber survey path. Planning
uses only the passive sysfs inventory. Execution requires the plan's exact
serial/topology/bus/device identity, the same clean utility commit, a shared
per-serial OS lock, the printed plan SHA-256 and confirmation phrase, and a second
explicit `--ensure-mute` gate. The imported `pluto_plus` package must be the
tracked `src/pluto_plus` tree inside that exact clean checkout. It never uses SSH,
changes a host route, enters DFU,
reboots, reads or writes QSPI, or authorizes Pluto transmit.

Create a private result root and plan file, then execute the printed command:

```bash
install -d -m 0700 /private/pluto-surveys /private/pluto-survey-plans
uv run pluto environment-survey plan \
  --serial EXACT_SERIAL \
  --usb-path /sys/bus/usb/devices/3-7 \
  --emitter-inventory /private/chamber/emitter-inventory.json \
  --emitter-inventory-sha256 EXACT_SHA256 \
  --result-root /private/pluto-surveys \
  --output /private/pluto-survey-plans/radio-plan.json \
  --ensure-mute

uv run pluto environment-survey execute \
  --plan /private/pluto-survey-plans/radio-plan.json \
  --expected-plan-sha256 EXACT_PLAN_SHA256 \
  --ensure-mute \
  --confirm 'EXECUTE RX ENVIRONMENT SURVEY EXACT_SERIAL PLAN_ID'

uv run pluto environment-survey receipt-verify \
  /private/pluto-surveys/PLAN_ID/receipt.json
```

Before any pyadi adapter is opened, execution requires both TX gains, TX
buffer/data/scan state, all eight DDS raw and scale attributes, all four FPGA
DAC selectors, and tandem state/FIFO/fault/overflow through the exact raw USB-IIO
context. The explicitly authorized mute sets gains to `-80 dB`, clears exposed
TX buffer and scan selection, zeros every DDS source, selects FPGA ZERO on all
four DAC lanes, and must read back completely safe. The same full predicate is
required again after exact RX-setting restoration. Cleanup preserves an original
RX0-only, RX1-only, or paired channel layout; it requires exact readback of every
settable field (including each originally manual gain), while retaining but not
equality-gating the dynamic gain reported by an original AGC mode.

The acquisition is not CLI-tunable: it captures a 2.445 GHz pre-anchor, sweeps
all 91 integer-MHz centers from 2.400 through 2.490 GHz, captures TX-muted
authorizing baselines at 1.05/1.55/2.05/5.8 GHz, then captures a 2.445 GHz
post-anchor. Every center uses 2.5 MS/s, 1.5 MHz RF bandwidth, manual gain 40,
and 32 dual-RX windows of 65,536 samples. Both anchors and all four authorizing
baselines must remain unclipped. Analysis uses a
periodic Hann (`4096`, hop `2048`), full density-normalized PSD/STFT in
`dBFS/Hz`, percentiles over linear integrated power before dB conversion,
burst occupancy, and AD9361 12-bit clipping.
Every 32-window block retains exact paired-RX settings plus the required shared
AD9361 temperature immediately after tuning and after its last window. The
settings evidence enumerates every raw RX channel exposing the shared PHY sample
rate and bandwidth attributes; all values must match the pyadi scalar. No
per-window attribute reads disturb the cadence.

A required private, SHA-pinned worst-normal inventory binds every 2.4 and 5 GHz
emitter; selection excludes the expanded union of its non-touching 2.4 GHz
occupied spans. A control must also be unclipped. Run the exact full survey in
canonical order on all four reserved radios, using an independent serial-scoped
result root and 5 GiB gate each. `fleet-select` consumes each matching PASS
manifest and receipt, re-verifies all evidence, and ranks by worst p99 across
all four radios/eight RX paths, then worst occupancy, then frequency. Execution
requires at least `5,368,709,120` free bytes; per-radio raw plus spectral payload
is `4,882,169,856` bytes with an exact 64 MiB failure reserve and a retained
400 MiB manifest allowance at every per-center free-space check. See
[the evidence contract](docs/environment-survey.md) for inventory schema,
formulas, layouts, fleet commands, drift thresholds, and failure behavior.

### Standalone USB/IP speed ladder

`radio ladder` opens one exact radio directly and does not require `plutod`. It
uses ordinary standard-libiio RX0-only, RX1-only, or dual-RX buffers, never
enables TX, and restores the original RX settings before returning. USB targets
are serial numbers; IP targets are literal IPv4 addresses and require an exact
expected serial:

```bash
uv run pluto radio ladder 104000b29905000e17000800065934759d --transport usb
uv run pluto radio ladder 192.168.1.15 --transport ip \
  --expect-serial 104000b29905000e17000800065934759d
uv run pluto radio ladder 192.168.1.15 --transport ip \
  --expect-serial 104000b29905000e17000800065934759d \
  --channels rx0 --rates 1M,2M,3M,5M --frames 12 --samples 262144 \
  --kernel-buffers 8 --format json
```

When several USB-attached Plutos share `192.168.2.1`, bind the IP ladder to one
serial and sysfs path with the receipt-backed isolation gate. `--report` writes
an absent-only canonical JSON evidence file beneath an existing owned mode-0700
directory:

```bash
uv run pluto radio ladder 192.168.2.1 --transport ip \
  --expect-serial EXACT_SERIAL --usb-sysfs-path /sys/bus/usb/devices/EXACT_PORT \
  --isolate-usb-route --isolation-confirm 'ISOLATE USB SSH EXACT_INTERFACE' \
  --channels dual --rates 1M,2.5M,5M,7.5M,10M,12.5M,15M \
  --frames 12 --samples 262144 --kernel-buffers 8 --format json \
  --report /ABSOLUTE/PRIVATE/PATH/ip-dual.json
```

Use `--duration-seconds` when every rate rung should cover the same nominal
sample time. It is mutually exclusive with `--frames`; the ladder rounds each
rung up to a complete refill and records both the resulting frame count and
`nominal_capture_seconds`:

```bash
uv run pluto radio ladder 192.168.1.20 --transport ip \
  --expect-serial EXACT_SERIAL --channels rx0 \
  --rates 5M,10M,15M,20M,25M,30M --samples 1000000 \
  --duration-seconds 20 --kernel-buffers 4 --format json \
  --report /ABSOLUTE/PRIVATE/PATH/ip-rx0-20s.json
```

The duration is source sample-time coverage, not a wall-clock deadline. A
link-limited rung takes longer to transfer. Duration mode remains bounded to 60
seconds and 4,096 timed refills per rung; increase `--samples` if the requested
rate/duration pair would exceed that refill bound.

`--iq-decoder raw-complex64` opts into the vectorized Pluto RX decoder. The
default `pyadi` decoder remains the control. The opt-in path accepts only the
canonical RX0, RX1, or dual `cf-ad9361-lpc` scan: exact scan indexes, no padding,
and fully defined signed little-endian 16-bit I/Q storage are revalidated before
every refill. A changed or unsupported layout fails instead of silently falling
back. The report records the selected decoder so their results cannot be mixed.

`kept_pace` compares delivered sample periods with the configured rate. The
ordinary-buffer ladder measures host transport performance; it does not claim a
gapless FPGA timeline. Use `radio metadata-ladder` for counter-proven continuity.

### Direct-async rate/duration ladder

The ABI-3 direct firmware has a dedicated one-command matrix. Its defaults are
the release qualification request: single RX0 at 5, 10, 15, and 25 MS/s for
nominal source durations of 3 and 10 seconds, using 1,000,000-sample frames and
50 exactly allocated DMA buffers. This is the v0.49 preferred profile: exactly
200,000,000 IQ payload bytes, RAM ring disabled, and drop-backlog enabled:

```bash
uv run pluto radio direct-async-ladder 192.168.1.15 \
  --transport ip --expect-serial EXACT_SERIAL \
  --format json --report /ABSOLUTE/PRIVATE/PATH/direct-matrix.json
```

The rates, durations, samples, buffer count, ringless selection, and overrun
policy may all be omitted because those values are the command defaults. The
report must attest `kernel_buffers=50`, `allocated_kernel_buffers=50`,
`samples_per_frame=1000000`, and `ram_ring_slots=0`. For a qualification daemon
on a nondefault port, add `--ip-port PORT`. The matched radio and host libiio
must be ABI 3 commit `5cb2389`; released iiOD runs with
`--rw-cpu-affinity 1`.

Use `--samples 1048576 --kernel-buffers 15` only as an explicit legacy or
comparison profile. PPU does not silently shrink the new default on an older
radio: exact admission fails closed so a report can never call a partial queue
an exact 200 MB queue.

Set `--ram-ring-slots 13 --kernel-buffers 10` to run the same matrix with RAM
extending the direct DMA FIFO. Zero slots is the default ringless mode. The
report distinguishes achieved wire-format MB/s, counter-proven gaps inside
each direct session, DMA-overflow flags, RAM spill/drain/drop/high-water counts,
and samples skipped between sessions if a future request exceeds one session.

The default `--drop-backlog-on-overrun` policy keeps the frame already entering
TCP, immediately retires every older queued-but-unsent frame after a source
overrun, and refills the same queue until the exact host frame target is met.
This minimizes stale-data latency and the number of separate discontinuities;
it does not promise fewer missing samples when the source continuously outruns
the link. Use `--preserve-backlog-on-overrun` when retaining every already
queued frame is more important than returning quickly to current RF time.

When several locally attached Pluto gadgets share `192.168.2.1`, keep IP/TCP
transport and bind the full matrix to one exact serial and physical USB path:

```bash
uv run pluto radio direct-async-ladder 192.168.2.1 \
  --transport ip --expect-serial EXACT_SERIAL \
  --usb-sysfs-path /sys/bus/usb/devices/EXACT_PATH \
  --isolate-usb-route \
  --isolation-confirm 'ISOLATE USB SSH EXACT_INTERFACE'
```

The utility temporarily removes only the competing Pluto routes/interfaces,
runs the entire matrix as one bounded action, restores the host network in a
`finally` path, and writes a durable isolation receipt. This tests the same TCP
path as a physical-IP run; selecting `--transport usb` is a different transport
and does not substitute for the release TCP measurement.

One direct wire request accepts at most 4,096 frames. The ladder also bounds a
cell to 4,096 frames, so every supported rate/duration cell is one finite DMA
producer/consumer session with no periodic re-arm. The throughput timer covers
the `read_block()` loop and the report records `capture_segments=1` and zero
inter-segment loss. Every matrix run snapshots and exactly restores the
original RX settings, and a capture failure makes the command exit nonzero
after preserving the other completed cells in its report. Counter-observed
gaps remain measured results rather than command failures: this lets a speed
matrix report the link-limited 25 MS/s cells without pretending they kept pace
with the source.

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

### DDR abrupt-disconnect recovery

`radio qualify-ddr-recovery` exercises the shutdown/reopen boundary that a
normal throughput ladder cannot cover. Each cycle alternates RX0 and RX1,
admits the exact 200 MB burst geometry at 25 MS/s, terminates that client while
its refill is active, and immediately opens a fresh DDR capture. It then proves
an ordinary low-rate metadata capture, exact RX-setting restoration, unchanged
Linux boot and iiOD process identity, zero leaked buffers, and TX-safe state.

The command is a dry run unless its exact confirmation phrase is supplied. A
pinned LAN SSH key and private password file are required for execution so that
data-plane recovery cannot be mistaken for a radio or iiOD restart:

```bash
uv run pluto radio qualify-ddr-recovery 192.168.1.15 \
  --expect-serial 104000b29905000e17000800065934759d --cycles 20
uv run pluto radio qualify-ddr-recovery 192.168.1.15 \
  --expect-serial 104000b29905000e17000800065934759d --cycles 20 \
  --profile ddr-burst-v1-release-ram \
  --ssh-known-hosts-file /private/radio.known_hosts \
  --ssh-password-file /private/radio.password --report /private/recovery.json \
  --execute \
  --confirm 'QUALIFY DDR RECOVERY 104000b29905000e17000800065934759d 20'
```

The report is created atomically with mode 0600 on pass or failure. A failed
immediate reopen is a firmware release failure; reboot the RAM candidate rather
than attempting to continue a wedged campaign.

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

For read-only bottleneck work on a unique physical-LAN endpoint, `data-plane-status`
attests the exact gadget serial over pinned SSH and reports iiOD process generation,
per-thread `/proc` CPU counters and CPU masks, RX-buffer/CMA state, DMA devices,
interrupts, and bounded kernel evidence. `--sample-seconds` takes two snapshots and
computes CPU percentages only for threads whose TID and start epoch both remain stable;
thread churn and an iiOD generation change are reported or rejected rather than folded
into misleading utilization:

```bash
uv run pluto radio data-plane-status EXACT_SERIAL \
  --ssh-host 192.168.1.17 \
  --ssh-known-hosts-file /private/EXACT_SERIAL.known_hosts \
  --ssh-password-file /private/EXACT_SERIAL.password \
  --sample-seconds 5
```

This command does not arm a buffer or change radio state. Add `--probe` only when one
bounded two-receiver LAN refill is also intended.

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

There are two firmware-qualified tuple profiles. Doctor does not infer success from
either tuple or from an `AD9361`/`AD9363A` label: after every guarded reboot it requires
four RX scan channels, TX-safe probe conditions, exact 5.8 GHz RX-LO readback, and exact
restoration of the previous LO. An already bounded 2R2T radio is never rewritten when
that functional probe is unavailable (for example, while its RX buffer is active).

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
- Spectrum, carrier, occupancy, CI16 quality, dual-receiver
  delay/coherence/phase, and seeded frequency-hop reference-error analyzers
  operate only on immutable artifacts.

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

Guarded AD936x setup is a distinct inspect → plan → confirm → execute workflow.
Omitting `--target` preserves the hardware-qualified `ad9361-2r2t` default; two
explicit single-stream development targets keep driver personality independent
from channel mode:

```bash
uv run pluto --admin-token-file /private/admin.token setup status
uv run pluto --admin-token-file /private/admin.token setup plan RADIO_ID
uv run pluto --admin-token-file /private/admin.token setup plan RADIO_ID --target ad9361-1r1t
uv run pluto --admin-token-file /private/admin.token setup plan RADIO_ID --target ad9363a-1r1t
uv run pluto --admin-token-file /private/admin.token setup execute PLAN_ID --token TOKEN
uv run pluto --admin-token-file /private/admin.token setup receipt-list
```

The daemon enables this only with `--enable-canonical-setup` plus one exact serial,
USB sysfs path, USB network interface/address, private password file, pinned host-key
file, admin token file, and allowed browser Origin. It derives firmware authority from
the managed radio's exact active version and the persistent setup allowlist; selecting
an RF target never selects or authorizes firmware. A single-stream daemon must also use
`--setup-target ad9361-1r1t` or `--setup-target ad9363a-1r1t`; this explicit runtime
binding survives restarts through service configuration and must match `setup plan
--target`. Omitting both flags retains the legacy 2R2T path unchanged. The Web Doctor
panel exposes the default guarded repair flow and never renders or stores the one-time token. Read-only radio and
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

An attached radio does not need a LAN address or a running daemon to enter this
workflow. `config bootstrap-ethernet` reaches only the fixed USB-gadget endpoint,
requires an exact local serial/sysfs path/host interface and pinned host key, and
then reuses the same structured planner and fixed remote operations:

```bash
uv run pluto config bootstrap-ethernet EXACT_HARDWARE_SERIAL \
  --usb-sysfs-path /sys/bus/usb/devices/3-8 \
  --ssh-known-hosts-file /private/EXACT_HARDWARE_SERIAL.known_hosts \
  --ssh-password-file /private/radio.password \
  --address 192.168.1.186 --netmask 255.255.255.0
```

The default is an inspection-only plan: it exposes the password-redacted current
configuration and confirmation phrase, but never the internal one-time token. Repeat
with `--execute --confirm 'SET STATIC IP EXACT_HARDWARE_SERIAL 192.168.1.186'`
to persist the plan. When local Pluto gadgets have overlapping `192.168.2.1` routes,
also pass `--isolate-usb-route` and the generated
`--isolation-confirm 'ISOLATE USB SSH <interface>'` phrase to both invocations.
The reversible host isolation and persistent radio mutation receive separate private
receipts. The command writes no firmware partition and never restarts the radio;
activate the new address later with the separate guarded `radio reboot-local` flow.
Use `--mode dhcp` without `--address` or `--netmask` to remove a static Ethernet
address.

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

ABI-4 authoritative gain-timeline candidates use the first-class
`candidate-ram qualification-plan` and `qualification-execute` campaign. It
owns the fixed USB/physical-IP, HOLD/AUTO, ordinary/single+dual, and
200-MB-ring/single matrix, including repeated 200/600-frame regressions and a
5,000-frame soak. It always attempts to reset the RAM candidate into the
unchanged persistent QSPI runtime. See
[`docs/GAIN_TIMELINE_QUALIFICATION.md`](docs/GAIN_TIMELINE_QUALIFICATION.md).

### Immutable approved-v7 comparator RAM lifecycle

`firmware comparator-ram` is a separate, native evidence boundary for the
RC21 same-board approved-v7 comparator. It does not relabel a release-candidate
plan or receipt. The plan hard-binds the retained v7 bundle, DFU and extracted
FIT bytes, profile/tag/source commit, historical qualification harness, exact
pilot USB inventory target and current runtime, and the clean current utility
tree plus its comparator execution wrapper.

Create the plan from retained files only. The strict USB inventory can be the
private output of `firmware candidate-ram inventory`:

```bash
uv run pluto firmware comparator-ram plan \
  --retained-bundle /private/v7/plutoplus-spf-tandem-agc-v2-e0049c2d0077.tar.gz \
  --dfu /private/v7/plutoplus-spf-tandem-agc-v2-e0049c2d0077-pluto.dfu \
  --usb-inventory /private/rc21/usb-inventory.json \
  --serial EXACT_SERIAL \
  --expected-current-firmware EXACT_CURRENT_VERSION \
  --expected-current-hardware-model 'EXACT MODEL' \
  --expected-current-metadata-abi frame-metadata-v5 \
  --expected-current-capability tandem-agc \
  --receipt /private/rc21/EXACT_SERIAL/comparator-ram-receipt.json \
  --output /private/rc21/EXACT_SERIAL-comparator-ram-plan.json
```

Review the complete plan and its printed SHA-256 before executing its bounded
approval window:

```bash
uv run pluto firmware comparator-ram execute \
  --plan /private/rc21/EXACT_SERIAL-comparator-ram-plan.json \
  --expected-plan-sha256 EXACT_PLAN_SHA256 \
  --ssh-password-file /private/credentials/EXACT_SERIAL.password \
  --confirm 'COMPARATOR RAM BOOT EXACT_SERIAL'

uv run pluto firmware comparator-ram receipt-verify \
  /private/rc21/EXACT_SERIAL/comparator-ram-receipt.json
```

The executor shares the normal per-radio lock, owns and removes one exact
`/32` USB-gadget route, re-attests the serial/topology/interface and current
runtime, copies the reverified DFU into a sealed descriptor, and accepts only
the paired `0456:b673,0456:b674` selector on `firmware.dfu` followed by detach.
A PASS receipt requires a changed boot ID, exact approved-v7 runtime, unchanged
`qspi-linux` size/hash, released route, and complete TX/DDS/DAC/tandem safe
state. `-R`, `-S`, serial-only selectors, arbitrary alternates, QSPI writes,
and every persistent target are outside this command.

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
  --usb-sysfs-path /sys/bus/usb/devices/3-8 \
  --profile ddr-ring-v1-release-persistent-promotion
uv run pluto firmware flash /absolute/path/to/qualified-pluto.dfu \
  --usb-sysfs-path /sys/bus/usb/devices/3-8 \
  --profile ddr-ring-v1-release-persistent-promotion \
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
outside the guarded firmware workflow requires a separately reviewed new destination
path.

### Guarded persistent flash over LAN

For a network-only radio whose key was enrolled as above, `firmware flash-lan`
provides a standalone, receipt-bound persistent update. It accepts only a literal
private IPv4 address, one exact serial, and an immutable hardware-qualified
persistent profile. The current full direct-async/RAM-extension release uses
profile `iq-direct-async-v3-release-persistent-promotion` and exact firmware
release `v0.48-plutoplus-spf-iq-direct-async-v3`.

Create a read-only plan first:

```bash
uv run pluto firmware flash-lan /absolute/path/to/qualified-pluto.dfu \
  --serial EXACT_SERIAL \
  --host 192.168.1.20 \
  --profile iq-direct-async-v3-release-persistent-promotion \
  --ssh-known-hosts-file /private/EXACT_SERIAL.lan-20.known_hosts
```

Review the serial, current/target versions, DFU/FRM/FIT hashes, and confirmation
phrase. Then execute with the same inputs and a private password file (or omit that
option for a hidden prompt):

```bash
uv run pluto firmware flash-lan /absolute/path/to/qualified-pluto.dfu \
  --serial EXACT_SERIAL \
  --host 192.168.1.20 \
  --profile iq-direct-async-v3-release-persistent-promotion \
  --ssh-known-hosts-file /private/EXACT_SERIAL.lan-20.known_hosts \
  --ssh-password-file /private/radio.password \
  --receipt-directory /private/lan-flash-receipts \
  --return-timeout 420 \
  --execute --confirm 'FLASH LAN EXACT_SERIAL 192.168.1.20'
```

The pinned pre-reboot SSH key authorizes only the mutation. Before staging, the
command independently re-attests the radio serial, current firmware, updater, idle
buffers, muted TX gains, disabled TX scan elements, and zeroed DDS state. It hashes
the staged FRM and the exact FIT bytes read back from `mtd3` before reset.

Pluto's generated SSH host key is ephemeral and normally changes at reboot. The
command therefore does not wait for old-key SSH to recover. It first observes IIOD
disappear and return, then requires the exact serial, target firmware, metadata ABI,
paired-RX/tandem layout, direct-async and RAM-ring capabilities, and TX-safe readback.
Only after that independent attestation does it accept one replacement key, verify
the same serial through the new SSH session, archive the old known-hosts bytes, and
atomically replace the active mode-0600 file. Both key hashes and fingerprints are
stored in the durable receipt. A failure after updater dispatch is `unknown` and must
not be retried without read-only reconciliation.

A firmware-provisioned persistent host key would remove routine rotation, but it must
be generated per device and stored in protected persistent storage. Reusing one key
across images or radios would weaken identity. Until that is a separately qualified
firmware feature, post-return identity-first rotation is the supported solution.

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
