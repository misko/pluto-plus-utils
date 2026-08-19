# Pluto+ doctor, AD9361/2R2T setup, and safe firmware updates

This guide is the Pluto+ Utils policy. It was independently derived from the local
`spf`, Rover 3.1, and `plutosdr-fw` safety contracts; it does not copy their scripts.
The three source trees contain stale and conflicting instructions, so do not combine
individual snippets from them.

## Selected profiles

Pluto+ firmware is profile-aware. A newer tag in a different profile is not an
automatic upgrade or downgrade decision.

| Consumer | Selected profile | Persistent release |
| --- | --- | --- |
| Pluto+ Utils standard libiio USB/IP | `libiio-continuous-metadata` | `v0.39-plutoplus-spf-libiio-metadata-v6` |
| Rover direct-USB V7 production | Rover YAML policy | currently RC16; do not use this as Pluto+ Utils' latest |

The Pluto+ Utils canonical release was published on 2026-08-17 and is the current
non-prerelease GitHub release as of this policy review:

- DFU: `plutoplus-spf-libiio-metadata-v6-e3700cc72681-pluto.dfu`
- SHA-256: `8ffbb0bf0912285636ddbcf0b00e12deaca0f55612faf7d29efa067b22e61352`
- expected `fw_version`: `v0.39-plutoplus-spf-libiio-metadata-v6`
- source commit: `e3700cc7268132eb6baa4bc88d8f3320dc7148b9`
- release: <https://github.com/misko/plutosdr-fw/releases/tag/v0.39-plutoplus-spf-libiio-metadata-v6>

The release manifest says the exact bytes were persistently tested on four radios and
survived QSPI reboot. The radio advertises `iio,buffer-metadata=1`; consuming the new
metadata records also requires one of the separately patched host libiio builds.
Ordinary IQ reads remain compatible.

## What `doctor` checks

Run all radios or one stable radio ID:

```console
pluto doctor
pluto doctor 104000b29905000e17000800065934759d
```

The web UI runs the same API at `GET /api/v1/radios/{radio_id}/doctor`. It checks
each fact independently:

- exact IIO hardware serial and a separately correlated `0456:b673` USB sysfs path;
- active `fw_version` against the selected firmware profile;
- live `ad9361-phy,model == ad9361`;
- RX scan elements `voltage0..voltage3`, proving both complex receive paths exist;
- `iio,buffer-metadata=1`;
- the complete persistent U-Boot tuple, when a trusted reader is configured;
- whether QSPI persistence has been proved by a full power cycle;
- whether the privileged, exact-radio firmware helper is available.

`unknown` is deliberate. Channel presence cannot prove the persistent U-Boot values,
and an active RAM-loaded image cannot prove QSPI contents. The daemon does not use
default SSH credentials and does not guess these facts.

## Radio `.15` on Gauss

The 2026-08-15 read-only inspection correlated `.15` as follows:

| Fact | Observation |
| --- | --- |
| Network endpoint | `192.168.1.15` |
| Hardware serial | `104000b29905000e17000800065934759d` |
| USB attachment | yes, Gauss sysfs device `3-8` (`0456:b673`) |
| Board report | `Analog Devices PlutoSDR Rev.C`; live PHY now `ad9361` |
| Active firmware | canonical metadata-v5 |
| Live PHY model | `ad9361` — canonical after guarded setup on 2026-08-15 |
| Metadata capability | present |
| Dual-RX scan layout | voltage0..3 present |
| Persistent U-Boot tuple | all four canonical values verified after reboot |
| QSPI image | exact metadata-v5 FIT body SHA-256 verified in `mtd3` |
| QSPI cold-boot provenance | still unknown until a full removal of power |

`.15` was not reflashed: its active and persistent firmware bytes already matched the
selected release. The authenticated Web setup flow backed up the environment, applied
the fail-closed TX mute, wrote only the three missing values, and rebooted. The exact
serial/path, live AD9361 PHY, voltage0..3 layout, metadata capability, and a paired
two-receiver Web preview now pass. A physical cold boot remains a separate checkpoint.

## Canonical AD9361/2R2T setup

Only use this profile for an exact serial-attested Pluto+ Rev.C. The persistent tuple is:

```text
attr_name=compatible
attr_val=ad9361
compatible=ad9361
mode=2r2t
```

A safe provisioner must perform this entire transaction:

1. Require an explicit dry run and exactly one selected USB serial/sysfs path.
2. Verify the live board is Pluto+ Rev.C and the network `hw_serial` equals the USB serial.
3. Require the approved active firmware and independently hash the approved FIT bytes in QSPI.
4. Back up `/opt/VERSIONS` and the complete output of `fw_printenv`.
5. Change only mismatching fields, preferably with one `fw_setenv -s` batch.
6. Sync and reboot; reacquire the same serial and physical path.
7. Reread all four values and require the live PHY to report `ad9361`.
8. Require scan elements 0–3 and take a paired two-receiver sample.
9. Keep DDS/TX buffers disabled and set/read back TX1 and TX2 attenuation to the safe minimum.

Pluto+ Utils implements this as a separate setup plan, not as a generic remote shell or
firmware upload. The daemon must be explicitly composed with one exact serial, sysfs path,
USB network interface, private USB address, private password file, and pinned SSH host-key
file. Plans bind the current environment digest and contain only mismatching values from
the immutable tuple. Browser setup and firmware POSTs additionally require an admin bearer
token and an exact allowed Origin; the token is held only in the password input.
Bearer credentials are never permitted on non-loopback plaintext HTTP: use HTTPS, a
Unix socket, or connect to the daemon's loopback listener through an SSH tunnel. The
LAN Web view remains useful for read-only status and doctor results, but its privileged
controls stay disabled on an insecure origin.

Guarded CLI primitives are:

```console
pluto --admin-token-file /private/admin.token setup status
pluto --admin-token-file /private/admin.token setup plan RADIO_ID
pluto --admin-token-file /private/admin.token setup execute PLAN_ID --token ONE_TIME_TOKEN
pluto --admin-token-file /private/admin.token setup receipt-list
```

The Web Doctor panel enables **Prepare setup repair** only for an eligible, noncanonical
selected radio. Inspect the immutable diff, enter the admin token, type
`PROVISION <serial>`, and execute once. A changed SSH host key is a hard verification
failure: physically re-attest the USB serial/path before reviewing and re-pinning it.
If an execution receipt reports an unknown outcome, do not retry provisioning. Preserve
the receipt and backup reference, restore pinned SSH trust only after that out-of-band
attestation, and run the dedicated read-only reconciliation action.

## Firmware update contract

Routine Pluto+ updates may write only the Linux FIT firmware partition, `mtd3`
(`qspi-linux`). The following are forbidden in the CLI, UI, and helper:

- a complete `*-fw-*.zip` bundle;
- `boot.frm`, `boot.dfu`, or `uboot-env.dfu`;
- arbitrary DFU alternate names;
- direct `/dev/mtdblock*` writes over SSH.

Those artifacts can overwrite `mtd0` (FSBL/U-Boot) or `mtd1` (environment), which is
the known Pluto+ brick path.

The staged flow is intentionally two-phase:

1. Download the exact release DFU and verify its SHA-256 before upload.
2. Run doctor and attach the selected serial over USB.
3. Fully power-cycle into the existing QSPI image so an old RAM image cannot fake the
   current version.
4. Create and execute a **volatile DFU** plan for `firmware.dfu`; smoke-test serial,
   firmware, AD9361, paired RX, tuning, metadata, and TX mute.
5. Create a new, separately confirmed **persistent QSPI** plan. Pluto+ Utils converts
   a valid DFU into firmware-only `pluto.frm` by removing the 16-byte DFU suffix and
   appending lowercase FIT MD5 plus newline. The mass-storage helper maps the block
   device by `ID_SERIAL_SHORT`, copies only `pluto.frm`, syncs, unmounts, asks
   UDisks to issue SCSI `LOEJ`, proves that the mass-storage LUN was removed while
   the composite USB device remained present, and then waits for the exact serial
   to re-enumerate. It never powers off the USB device or hub port.
6. Remove all power, reconnect the same radio, rerun doctor, and repeat the paired-RX
   and TX-safe-state checks. A soft reboot is not persistence proof.

Guarded CLI primitives are:

```console
pluto --admin-token-file /private/admin.token firmware upload ./IMAGE.dfu
pluto --admin-token-file /private/admin.token firmware plan RADIO_ID IMAGE_ID --mode volatile_dfu \
  --expected-version v0.39-plutoplus-spf-libiio-metadata-v6
pluto --admin-token-file /private/admin.token firmware execute PLAN_ID --token 'ONE_TIME_TOKEN'
```

For a hardware-unqualified candidate, use the standalone RAM-only gate. It
defaults to dry run, accepts only the exact immutable profile hash, selects one
stable serial and USB sysfs path, enters only the `firmware.dfu` alternate, and
never writes QSPI:

```bash
uv run pluto firmware ram-boot ./CANDIDATE.dfu \
  --usb-sysfs-path /sys/bus/usb/devices/5-2 \
  --profile libiio-metadata-v6-tandem-latch-clear-ram \
  --ssh-host 192.168.1.15 \
  --ssh-known-hosts-file /private/759d.known_hosts
```

Execution additionally requires `--execute --confirm 'RAM BOOT <serial>'`.
After loading, the command requires the exact serial/path to return with the
profile firmware, ABI, tandem capability, AD9361 PHY, and TX-safe readback.
Power cycling returns to the unchanged QSPI image. Persistent promotion always
requires a separate profile whose manifest is hardware-qualified.

The dry-run plan reports `raw_usb_write_access`. If it is false, install the
repository rule and reconnect the radios before execution:

```bash
sudo install -m 0644 packaging/udev/70-pluto-plus-utils.rules \
  /etc/udev/rules.d/70-pluto-plus-utils.rules
sudo udevadm control --reload-rules
```

Do not enter DFU until the runtime `/dev/bus/usb/...` node is writable; the
command repeats this check immediately before mutation.

For a serial-attested local USB radio, `firmware flash` is the standalone
canonical-image workflow. It binds the USB and IIOD serials, physical sysfs
path, updater partition, current firmware, and exact image hashes before asking
for `FLASH <serial>` confirmation.

For the narrower blank-serial recovery case, the standalone CLI has a
daemon-independent `firmware force-flash` command. It accepts only the
canonical qualified image hash and an exact direct USB sysfs path, defaults to
a read-only plan, and refuses serial-attested radios. It never accepts an
arbitrary target filename or validation override:

```bash
pluto firmware force-flash ./QUALIFIED.dfu \
  --usb-sysfs-path /sys/bus/usb/devices/3-11
pluto firmware force-flash ./QUALIFIED.dfu \
  --usb-sysfs-path /sys/bus/usb/devices/3-11 \
  --execute --confirm 'BOOTSTRAP 3-11' --return-timeout 420
```

The second command writes only `pluto.frm` to the serial-correlated updater
volume and records a durable local receipt. Once a stable serial exists, all
subsequent firmware operations must use the normal serial-attested plan/token
workflow. Never retry an `unknown` bootstrap receipt without read-only
reconciliation.

An uncertain serial-attested standalone SSH receipt is reconciled independently
of the daemon with `pluto firmware reconcile-local RECEIPT_ID`. Supply the exact
recorded `--usb-sysfs-path`, persistent `--profile`, pinned
`--ssh-known-hosts-file`, and endpoint. The command performs only readback: it
validates the durable receipt and qualified profile, correlates USB and IIOD
identity, verifies the active firmware and TX/DDS safe state, and hashes exactly
the recorded FIT length from `mtd3`. It has no updater, QSPI-write, RF-write, or
reboot operation; any mismatch remains unresolved and must not trigger a retry.

`--return-timeout` is bounded to 30–1800 seconds and defaults to 180. A failure
before the SCSI eject request is a known `qspi_write_not_started` result: the FIT
may be staged on FAT, but the radio-side QSPI updater was never triggered. A
failure after the eject request is dispatched remains `unknown` unless LUN
removal and the returning radio can be attested. In particular, disappearance of
the whole composite USB device is not accepted as proof of media eject.

### Headless UDisks/polkit setup

Mounting and ejecting an updater volume uses UDisks; Pluto+ Utils has no `sudo`
fallback. On a headless session, UDisks can select the `*-other-seat` actions.
After reviewing the group and drive identity checks, an administrator may install
the repository's narrow example rule:

```bash
sudo install -m 0644 packaging/polkit/50-pluto-plus-utils.rules \
  /etc/polkit-1/rules.d/50-pluto-plus-utils.rules
```

The example grants only mount, unmount-others, and media-eject actions to members
of `plugdev`, and only for removable USB drives whose UDisks model identifies a
Pluto or Linux File-Stor Gadget. Verify the exact host strings first:

```bash
udisksctl info --block-device /dev/sdX
```

Do not broaden the rule to `drive-power-off`: UDisks documents that USB power-off
deconfigures the device and may disable its upstream hub port, which bypasses the
Pluto updater's SCSI media-removal trigger.

After the volatile checkpoint, repeat `plan` with `--mode persistent_qspi`. These
commands fail closed unless the daemon has a separately configured privileged helper
and an exact USB identity. The web Firmware panel uses precisely the same upload,
plan, token, and receipt API; typing the selected serial is required before execution.

### Persistent update over enrolled SSH

The experimental `ssh_frm` transport supports installed radios that have network IIO
and SSH but no USB connection to the daemon host. It does not turn an IP address into
identity: the daemon requires one private enrollment binding the literal endpoint to
the exact managed IIO serial and an out-of-band verified SSH host key. Only key-based
root SSH is accepted. Discovery does not enroll a radio.

This transport is deliberately narrower than the USB firmware surface:

- only `persistent_qspi` is accepted;
- only the selected hardware-qualified canonical FIT body is accepted, whether the
  uploaded source is the published DFU or a correctly generated FRM;
- the remote staging path and updater command are fixed by the server;
- the on-radio updater must report success and the exact FIT bytes are hashed back
  from `mtd3` before reset;
- no arbitrary path, command, DFU alternate, environment write, or direct MTD write
  is exposed;
- the same IIO serial and expected firmware must return, with TX mute read back.

Every authorized attempt records `local_validation`, remote identity/TX preflight,
upload, updater dispatch, QSPI readback, cleanup, sync, reset, return, and TX-safety
phases. Failures before updater dispatch are known failures. Failures after dispatch
are unknown until the read-only receipt reconciliation succeeds. A consumed plan is
never retried.

Pluto SSH host keys can change after reboot. A replacement key is not accepted from
the network automatically. The receipt retains the verified pre-reset QSPI evidence,
but the enrollment remains locked until an operator verifies the new fingerprint
through an independent trusted path, updates the private known-hosts enrollment, and
runs `pluto firmware reconcile RECEIPT_ID` after restarting the daemon.

## Checkpoints and tests

| Checkpoint | Required evidence |
| --- | --- |
| Read-only doctor | deterministic pass/fail/unknown fixtures and API/CLI/UI parity |
| Plan | token binds serial, sysfs path, active firmware, mode, image bytes, SHA, and expiry |
| Volatile canary | exact DFU alternate, re-enumeration, current profile, dual RX, tuning, TX muted |
| Persistent write | only validated `pluto.frm`; mount/copy/sync/SCSI-LOEJ fault injection; LUN-removal proof |
| Cold verification | physical power cycle, same serial/path, version and setup reread |
| Recovery | interrupted jobs retain durable failure receipts; never fall back to boot images |

The `.15` observations above were verified on the attached unit. The remaining physical
power-cycle checkpoint has not been performed.
