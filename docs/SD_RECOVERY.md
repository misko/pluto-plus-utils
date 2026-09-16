# Guided SD recovery

`pluto firmware recover` provides private diagnostic sessions and a qualified,
resumable repair engine for radios that cannot boot normally. It is separate from
`pluto radio recover --data-plane`, which restarts IIOD on a running radio.

**Current live support: one incident-scoped recipe, `plutoplus-incident-114`.**
It binds the exact radio's flash factory UID, retained original image, SD bootstrap
and rollback artifacts. Writes remain below physical 16 MiB. This is not a general
hardware qualification grant; other units and images are refused. RAM acceptance
and cold-boot evidence are collected during execution, not supplied as invented
prior successes. No `--force` or caller-supplied profile enables another target.

On Gauss, the private incident kit is provisioned under
`~/.local/share/pluto-plus-utils/recovery-kits/incident-114`. The existing session
`~/pluto-recovery-14` has a live-verified complete 32 MiB backup, including an SD
write/reload comparison, and a 73-sector repair plan. RAM boot, flash repair and
persistent cold-boot acceptance remain pending.

## One guided command

```console
pluto firmware recover guide --session /private/recovery-session
```

On a supported installation, this creates or reopens a session and walks through
SD preparation, UART acquisition, a complete backup, repair planning, SD payload
transfer, RAM acceptance, exact-plan confirmation, flash verification and QSPI
cold-boot acceptance. Run it on the Linux host connected to the UART; a Mac can
prepare the SD card using the exported files and portable verification scripts.
It acquires the UART before asking you to power on. Stop other serial terminals
before starting; PPU does not stop another program's capture process.

The first run asks for a shipped profile, an explicit stable adapter path and
missing artifact/provenance paths. These can also be supplied with `--profile`,
`--adapter`, `--assets`, `--boot`, `--fit`, `--provenance` and `--history`.
The session parent directory must already exist. The command does not select a
radio by old IP or choose a profile from the device's model name.

The guide prints SD bundle locations and manifest digests. It pauses for card
transfer, boot selection and power changes, and requires the exact displayed
`RECOVER SESSION_ID PLAN_SHA256` phrase before any flash erase. Answering a physical
action prompt does not replace the backend's identity, boot-source, reset-cause
or service checks. Completed recovery emits a sanitized receipt.

After a cancellation, EOF, UART error or process restart, rerun the **same
command with the same session**. A previously verified original backup is reused;
an interrupted write is reconciled against newly read physical bytes. Old RAM
acceptance is never reused across guide invocations: a successor plan requires a
new RAM test and exact confirmation. Verified flash proceeds to cold-boot checks
without reflashing. Reopening a completed session only exports its receipt.
Incomplete SD exports can be finished from the same verified source; changed or
unexpected files are refused. Two guide processes cannot operate one session.

### Resume the prepared `.14` recovery

On the Mac, add the exported repair files to the existing diagnostic SD card
(adjust the volume name if needed):

```sh
scp mouse9911@gauss:/home/mouse9911/pluto-recovery-20260913/ppu-repair14-sd.zip ~/Downloads/
unzip -o ~/Downloads/ppu-repair14-sd.zip -d /Volumes/PLUTOREC
python3 /Volumes/PLUTOREC/ppu-repair/verify-repair.py /Volumes/PLUTOREC/ppu-repair
```

The verifier must print manifest SHA-256
`240cb852de8cd18632a14240f583e01ee6d4d896e87a5a667fbe42580034751e`.
Preserve the existing boot files and backup. Eject the card and insert it with
radio power off. On Gauss run:

```sh
pluto firmware recover guide --session ~/pluto-recovery-14
```

At every boot question, PPU has already acquired and is listening to UART. Keep
the question open and begin with the radio fully powered off, even if it is
already sitting at `Pluto+>`. Perform the requested power cycle, wait 15 seconds,
and only then answer `y`. The verifier's argument must be the `ppu-repair` directory, not
the SD volume root. An interrupted session uses one SD boot to reread flash and
build a successor plan. In that same invocation, PPU reuses the identity-checked
SD console for its RAM test and explicitly says that no second power cycle is
needed.

The guide tests the rollback initramfs in RAM with
`rdinit=/bin/sh`, starts the required network/IIO services explicitly, and asks for
another SD boot to prove flash stayed unchanged. Only then does it request the
exact plan confirmation for persistent repair. Finally it asks for power off,
SD removal and normal QSPI boot and checks the actual reset/source registers.

This implementation consumes the [shared flash safety policy](FLASH_SAFETY.md).
The full design and acceptance matrix are in
[the #114 plan](ISSUE_114_SD_RECOVERY_PLAN.md). The motivating radio's physical
repair and cold-boot acceptance remain pending.

## Start a diagnostic session

```console
pluto firmware recover discover
pluto firmware recover profiles
pluto firmware recover start --session /private/recovery-session --adapter EXPLICIT_ADAPTER
pluto firmware recover import-evidence --session /private/recovery-session --file /private/dump.bin
pluto firmware recover status --session /private/recovery-session
pluto firmware recover export --session /private/recovery-session --output /private/receipt.json
```

Use an existing parent directory for the session. The session itself must not
already exist. It is created with mode `0700`; raw dumps, transcripts and contracts
use `0600`. A session never selects a radio by enumeration order, generic MAC,
model name or old IP address. Discovery reads host filesystem inventory without
opening a UART or contacting a network radio. No LEDs/USB observation diagnoses
the failed component by itself.

Imported files are always labelled **unverified evidence**. Their digest proves
file identity, not physical flash placement. Import does not advance the session
to `backup_verified`. Share the sanitized export, not raw session files.

## Profile-bound workflow

The shipped incident recipe is limited to its pinned unit and image. General
profiles require the complete hardware qualification described below. Start a
new session with its shipped `--profile`. The profile supplies wiring/boot instructions, artifacts, actual
erase geometry, safe RAM buffers, identity probes and reader/writer/boot evidence.
The initial serial transport supports Linux, 115200 baud, 8N1 and an explicitly
selected `/dev/serial/by-id/...` or `/dev/serial/by-path/...` endpoint. Profiles
must qualify that transport configuration; no universal UART voltage is assumed.

1. `prepare-sd --assets DIR --output DIR` builds a diagnostic bundle from exact
   qualified files. The firmware bootstrap must reliably stop at the console,
   including when the QSPI environment is stale or corrupt. An override file alone
   does not establish this property.
2. Copy the bundle to an explicitly selected prepared filesystem. `--media MOUNT`
   first reports a media identity; repeat with `--media-id DIGEST` to copy to that
   same empty mounted filesystem. PPU does not format disks. For a second computer,
   copy the bundle and run `python3 verify.py MOUNT`; compare the printed manifest
   SHA-256 with the PPU receipt, then safely eject. Unexpected startup files refuse
   verification rather than being deleted.
3. `capture` observes the bound target, reads the complete physical chip, checks
   boundary/repeated reads, saves and reloads the SD export, and publishes/reopens
   the immutable original host backup. Unqualified addressing, short reads, media
   errors or failed host storage prevent `backup_verified`.
4. `plan --boot BOOT --fit FIT --provenance JSON --history JSON` reconstructs the
   expected full image. `BOOT` is the reconstructed full boot partition matching
   the target's historical digest. Only sectors with justified changes are written.
   The older FIT is selected by exact trusted hash and configuration. Environment
   bytes come from the captured target; only `fit_size` and its CRC may change.
5. `stage-sd --output DIR` exports content-addressed full-sector payloads plus the
   rollback FIT. Run `verify-repair.py DIR`, compare the repair-manifest digest,
   and copy the directory to `ppu-repair` on the selected SD filesystem. This is
   a separate transfer after diagnostic media verification. Execution checks the
   exact file length and complete RAM bytes before any erase.
6. `ram-test` uses the qualified RAM recipe and verifies identity, image, required
   services, settings and RF inactivity. IIOD is started as a background service
   with its console streams redirected; PPU then requires both a live IIOD process
   and the expected read-only network context before accepting the RAM boot.
   Returning to SD must prove the complete pre-repair flash is unchanged. Normal
   boot helpers that call `saveenv` are not acceptable RAM recipes.
7. `execute --confirm 'RECOVER SESSION_ID PLAN_SHA256'` revalidates the exact plan,
   source files, target, writer and current bytes. It programs FIT, environment
   and justified boot sectors in that order. Complete sector preservation and
   final full-chip comparison are required. It never automatically reboots.
8. After `awaiting_cold_boot`, follow the profile's power-off/SD-removal/QSPI
   instructions and run `attest`. This requires machine-observed QSPI boot and
   power-on reset evidence, separately recorded operator actions, identity/image
   continuity, expected services/settings and RF inactivity. A RAM boot, warm
   reboot, console banner or reachable old IP cannot report `recovered`.

Commands take `--session` throughout. `status` always names the next action.
The UART backup path is deliberately bounded and may be slow for a complete
32 MiB image. A faster export transport needs its own qualified implementation.

## Historical evidence and artifact formats

The history document uses canonical JSON: sorted keys, compact separators, one
trailing newline. It contains `target_uid`, `boot_sha256` and
`source_receipt_sha256`. The provenance document contains `target_uid`,
`historical_boot_sha256`, `historical_record_sha256`, `boot_source_sha256` and
`rollback_sha256`, `boot_restore_start` and `boot_restore_size`. The explicit
restoration interval must reconstruct the historical full boot digest while
leaving the rest of the captured boot partition unchanged. The actual canonical history file is retained and verified,
not replaced by a bare claimed digest. Its source must be the target's retained
pre-failure receipt; another unit's matching model does not establish provenance.

Existing #113 backups are useful source evidence, but importing their files does
not impersonate a qualified full-chip recovery capture or establish missing UID
continuity. Firmware/profile onboarding must establish that correlation.

FIT support covers bounded version-17 FDTs with inline selected components,
explicit configuration, SHA-256/SHA-1 component integrity under an exact trusted
outer SHA-256. The incident legacy FIT additionally pins every selected component
with SHA-256, including components with legacy MD5 or no internal hash. Supported
compression is uncompressed data or gzip with exact expanded-size bounds.
External FIT data, unqualified compression/load addresses and unsupported
configuration features refuse validation. The initial environment codec supports
only the qualified 128 KiB, single-copy, little-endian CRC32 format. Redundant
environment copies need their own codec and power-loss qualification before use.

## Interruptions and return evidence

Every destructive dispatch has a durable prior intent. Lost UART responses,
timeouts and storage failures leave an interrupted state. The console refuses
another command after an uncertain response; no blind retry or reboot is sent.

`resume` reacquires the target and reads its actual flash. Only previously
dispatched sector footprints can explain changes from the attempt's baseline.
Unexpected changes elsewhere, hardware swaps, changed artifacts or changed
qualification reject reconciliation. A successor plan reconstructs partial
sectors from the original backup, links to the previous plan and requires a new
RAM test and deliberate execution. The original backup is never replaced.

Private receipts retain exact observations, artifacts, command evidence and
operator/runtime attestation. Public receipts contain states, event digests,
qualification/policy identities, planned intervals and artifact/before/after
digests. They omit raw flash/environment, credentials, private paths and device
identity. Recovery to older firmware retains conservative Linux update limits;
SD writer qualification does not qualify the returned Linux driver.

## JTAG handoff and hardware acceptance

If SD bootstrap cannot be established, retain the diagnostic session and hand
off its sanitized receipt plus privately transferred evidence to the firmware
maintainer. Identify the exact board revision before obtaining its JTAG wiring,
voltage and bootstrap recipe. PPU does not automate JTAG or supply guessed wiring.

Before promoting a general qualified profile, the firmware and PPU owners must record exact
board/SoC/DDR/flash identities, artifact and recipe digests, independent physical
read/write/bank-boundary qualification, console-only startup, no-write RAM boot,
controlled interrupted repairs and preserved bytes. Test local and second-host
SD transfer, two-radio isolation, and at least three actual QSPI cold boots with
identity/image/service/settings checks and RF inactive. Unknown combinations stay
blocked. The motivating unit's eventual repair result needs its own receipt.

## Incident reader and writer evidence

The reader checks JEDEC, factory UID, status registers and native four-byte SPI
reads independently of banked SF reads. Full RAM byte comparisons use a small
pinned SHA-256 helper whose source, linker script and reproducible binary ship
with PPU; it has no flash or peripheral access. Instruction/data caches are
disabled before upload and the uploaded bytes are read back before execution.
The initial development attempt exposed a cache-coherency fault and reset the
CPU; after correction, live vector and full-image comparisons passed. No flash
programming occurred during that validation.

The backend checks a pinned immutable relocated U-Boot code interval and SD file
hashes. Its reviewed SF writer performs write-enable before mutation and verifies
bank zero before each operation. These checks do not substitute for completed
hardware write or interruption qualification. Each actual write still requires
fresh target/plan checks, successful no-write RAM acceptance, durable intent,
sector readback and final full-chip comparison. The incident environment codec
preserves existing opaque padding byte-for-byte while adjusting only the
same-width `fit_size` value and CRC.
