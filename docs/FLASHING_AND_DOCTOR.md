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
| Pluto+ Utils standard libiio USB/IP | `libiio-continuous-metadata` | `v0.38-plutoplus-spf-libiio-metadata-v5` |
| Rover direct-USB V7 production | Rover YAML policy | currently RC16; do not use this as Pluto+ Utils' latest |

The Pluto+ Utils canonical release was published on 2026-08-12 and is the current
non-prerelease GitHub release as of this policy review:

- DFU: `plutoplus-spf-libiio-metadata-v5-d7c87a9a2809-pluto.dfu`
- SHA-256: `948b46506febacb087f3955be86015e074f8c0e3370a9dfc6a942e735d97f882`
- expected `fw_version`: `v0.38-plutoplus-spf-libiio-metadata-v5`
- source commit: `d7c87a9a28094ee6f0b23cb47df9ff737b5a69d8`
- release: <https://github.com/misko/plutosdr-fw/releases/tag/v0.38-plutoplus-spf-libiio-metadata-v5>

The release manifest says the exact bytes were persistently tested on two radios and
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
| Board report | `Analog Devices PlutoSDR Rev.C (Z7010-AD9363A)` |
| Active firmware | canonical metadata-v5 |
| Live PHY model | `ad9363a` — not canonical |
| Metadata capability | present |
| Dual-RX scan layout | voltage0..3 present |
| Persistent U-Boot tuple | unknown; credential-free SSH was correctly refused |
| QSPI cold-boot provenance | unknown |

Therefore `.15` must **not** be reflashed merely because its live PHY says AD9363A:
its active firmware is already the selected release. The next safe action is to read
and, if necessary, provision the persistent AD9361/2R2T tuple. Firmware and setup are
separate changes.

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
3. Refuse setup while a volatile direct/RAM firmware is active or boot provenance is unknown.
4. Back up `/opt/VERSIONS` and the complete output of `fw_printenv`.
5. Change only mismatching fields, preferably with one `fw_setenv -s` batch.
6. Sync and reboot; reacquire the same serial and physical path.
7. Reread all four values and require the live PHY to report `ad9361`.
8. Require scan elements 0–3 and take a paired two-receiver sample.
9. Keep DDS/TX buffers disabled and set/read back TX1 and TX2 attenuation to the safe minimum.

Pluto+ Utils currently reports this repair but does not execute it. The existing Rover
wrapper is count-scoped, not selected-serial scoped, and its baseline allowlist is stale;
wrapping it in a web button would be unsafe. A future helper action must bind the plan to
the serial, resolved sysfs path, current firmware, complete environment backup digest,
and exact four-field patch.

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
   device by `ID_SERIAL_SHORT`, copies only `pluto.frm`, syncs, unmounts, ejects, and
   waits for the exact serial to re-enumerate.
6. Remove all power, reconnect the same radio, rerun doctor, and repeat the paired-RX
   and TX-safe-state checks. A soft reboot is not persistence proof.

Guarded CLI primitives are:

```console
pluto firmware upload ./IMAGE.dfu
pluto firmware plan RADIO_ID IMAGE_ID --mode volatile_dfu \
  --expected-version v0.38-plutoplus-spf-libiio-metadata-v5
pluto firmware execute PLAN_ID --token 'ONE_TIME_TOKEN'
```

After the volatile checkpoint, repeat `plan` with `--mode persistent_qspi`. These
commands fail closed unless the daemon has a separately configured privileged helper
and an exact USB identity. The web Firmware panel uses precisely the same upload,
plan, token, and receipt API; typing the selected serial is required before execution.

## Checkpoints and tests

| Checkpoint | Required evidence |
| --- | --- |
| Read-only doctor | deterministic pass/fail/unknown fixtures and API/CLI/UI parity |
| Plan | token binds serial, sysfs path, active firmware, mode, image bytes, SHA, and expiry |
| Volatile canary | exact DFU alternate, re-enumeration, current profile, dual RX, tuning, TX muted |
| Persistent write | only validated `pluto.frm`; mount/copy/sync/eject fault injection |
| Cold verification | physical power cycle, same serial/path, version and setup reread |
| Recovery | interrupted jobs retain durable failure receipts; never fall back to boot images |

No command in this guide was run against `.15` during the review.
