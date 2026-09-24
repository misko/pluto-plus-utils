#!/usr/bin/env python3
"""Fail-closed, dry-run-first deployment planner for the v0.56 build.

This is deliberately separate from the historical Issue 111 deployer.  It
creates immutable plans only; a mutation executor cannot be enabled until the
official artifact supplies the missing immutable FIT identity and the explicit
RAM/persistent evidence contracts are reviewed.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import ipaddress
import json
import os
import stat
from pathlib import Path

from pluto_plus.bootstrap_firmware import (
    PAIRED_RX_TX_CAPABLE_LAYOUT,
    STANDALONE_FLASH_PROFILES,
    BoundSshBootstrapTransport,
    _require_iio_layout,
    _require_profile_iio_capabilities,
    inspect_bound_iiod,
)
from pluto_plus.doctor import FEATURE_103_V1_RELEASE_RAM_POLICY
from pluto_plus.firmware import validate_dfu
from pluto_plus.inventory import scan_local_usb_plutos
from pluto_plus.radio_lock import acquire_radio_lock
from pluto_plus.volatile_firmware import (
    SshRamBootTransition,
    execute_ram_boot_plan,
    prepare_ram_boot_plan,
)

FIRMWARE_SOURCE = "e39162c7cee17136b2575aadfa4c6802d7cdebed"
FIRMWARE = "v0.56-plutoplus-spf-adaptive-runtime-rates"
SOURCE_MANIFEST_SHA256 = "8a8534d8aa8061a0576bde6808dab51faeb8379248f404440fdc77c92d2ee3b9"
DFU_SHA256 = "723cbaad253c97110e1a0284119ebd1575c9066061e076f3e11f87c17cfb942b"
DFU_BYTES = 12_784_595
FIT_SHA256 = "29e582f8700bb6c31534f6c212a29cb54fb1064ae83ced160c6ac5e03cb648ed"
FIT_BYTES = 12_784_579
BUILD_RUN = 35_960_458_163
BUILD_ARTIFACT = 10_791_919_227
COMPANION_SOURCE = "f758b3af36604843299858c7e17c9050f9d1b5c1"

RAM_SERIAL = "1040007c4a94000211000b009186843ef2"
RAM_URI = "usb:3.75.5"
RAM_SYSFS_PATH = Path("/sys/bus/usb/devices/3-11")
RAM_TRANSITION_HOST = "192.168.1.18"
RAM_BASELINE = "v0.54-plutoplus-spf-counter-utc-v1-rc1"
PERSISTENT_TEST_SERIALS = {"104000b29905000e17000800065934759d"}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def private_bytes(path: Path) -> bytes:
    state = path.lstat()
    if (
        not stat.S_ISREG(state.st_mode)
        or state.st_uid != os.getuid()
        or stat.S_IMODE(state.st_mode) & 0o077
    ):
        raise ValueError("SSH secret/known-hosts file must be private and owned")
    return path.read_bytes()


def register_ram_profile() -> str:
    """Install a process-local RAM-only profile bound to the official bytes."""
    base = STANDALONE_FLASH_PROFILES[FEATURE_103_V1_RELEASE_RAM_POLICY.profile_id]
    profile_id = f"v056-{DFU_SHA256[:12]}-ram"
    required = base.required_iio_capabilities + (("iio,adaptive-scan-runtime-rates", "2"),)
    policy = base.policy.model_copy(
        update={
            "profile_id": profile_id,
            "release_tag": FIRMWARE,
            "device_firmware": FIRMWARE,
            "asset_sha256": DFU_SHA256,
            "fit_body_sha256": FIT_SHA256,
            "fit_body_size": FIT_BYTES,
            "source_commit": FIRMWARE_SOURCE,
            "hardware_qualified": False,
        }
    )
    STANDALONE_FLASH_PROFILES[profile_id] = dataclasses.replace(
        base,
        policy=policy,
        persistent_allowed=False,
        source_iio_layout=PAIRED_RX_TX_CAPABLE_LAYOUT,
        return_iio_layout=PAIRED_RX_TX_CAPABLE_LAYOUT,
        required_iio_capabilities=required,
        allowed_before_firmwares=(RAM_BASELINE,),
    )
    return profile_id


def attest_ram_return(plan, receipt_path: Path, binding: dict[str, object]) -> dict[str, object]:
    matches = [item for item in scan_local_usb_plutos() if item.serial == RAM_SERIAL]
    if len(matches) != 1 or matches[0].usb_path != str(RAM_SYSFS_PATH):
        raise ValueError("post-RAM USB inventory no longer binds the exact serial/sysfs target")
    if plan.usb_sysfs_path != str(RAM_SYSFS_PATH) or plan.transition_host != RAM_TRANSITION_HOST:
        raise ValueError("RAM plan target changed from the approved exact path")
    facts = inspect_bound_iiod(plan.usb_interface)
    profile = STANDALONE_FLASH_PROFILES[plan.profile_id]
    if facts.get("hw_serial") != RAM_SERIAL or facts.get("fw_version") != FIRMWARE:
        raise ValueError("post-RAM serial or firmware attestation failed")
    _require_iio_layout(facts, profile, profile.return_iio_layout, transport="RAM USB")
    _require_profile_iio_capabilities(facts, profile, transport="RAM USB")
    return {
        "schema": "org.leo.v056-ram-attestation/v1",
        "passed": True,
        "firmware": FIRMWARE,
        "serial": RAM_SERIAL,
        "uri": RAM_URI,
        "usb_sysfs_path": str(RAM_SYSFS_PATH),
        "ram_receipt_sha256": sha256(receipt_path),
        "release_binding": binding,
        "metadata_abi": profile.metadata_abi,
        "capabilities": {key: str(facts[key]) for key, _ in profile.required_iio_capabilities},
    }


def validate_release_assets(
    image: Path, metadata: Path, source_manifest: Path
) -> dict[str, object]:
    """Bind bytes and both source records before any plan is written."""
    raw = image.read_bytes()
    document = json.loads(metadata.read_bytes())
    expected = {
        "firmware_source_commit": FIRMWARE_SOURCE,
        "firmware": FIRMWARE,
        "source_manifest_sha256": SOURCE_MANIFEST_SHA256,
        "dfu_sha256": DFU_SHA256,
        "dfu_bytes": DFU_BYTES,
        "fit_sha256": FIT_SHA256,
        "fit_bytes": FIT_BYTES,
        "build_run": BUILD_RUN,
        "build_artifact": BUILD_ARTIFACT,
        "companion_source_commit": COMPANION_SOURCE,
    }
    if not isinstance(document, dict) or any(
        document.get(key) != value for key, value in expected.items()
    ):
        raise ValueError("release metadata does not bind the exact official v0.56 build")
    if sha256(source_manifest) != SOURCE_MANIFEST_SHA256:
        raise ValueError("source manifest digest does not bind the official build")
    if len(raw) != DFU_BYTES or hashlib.sha256(raw).hexdigest() != DFU_SHA256:
        raise ValueError("DFU bytes or SHA-256 do not bind the official build")
    fit = validate_dfu(raw)
    if len(fit) != FIT_BYTES or hashlib.sha256(fit).hexdigest() != FIT_SHA256:
        raise ValueError("DFU FIT body does not bind the official build")
    return {
        **expected,
        "metadata_sha256": sha256(metadata),
        "source_manifest_sha256": SOURCE_MANIFEST_SHA256,
        "dfu_sha256": DFU_SHA256,
        "dfu_bytes": DFU_BYTES,
        "fit_sha256": FIT_SHA256,
        "fit_bytes": FIT_BYTES,
    }


def require_target(phase: str, serial: str, uri: str) -> None:
    if phase == "ram":
        if (serial, uri) != (RAM_SERIAL, RAM_URI):
            raise ValueError("RAM canary is restricted to the exact serial and observed USB URI")
        return
    if serial not in PERSISTENT_TEST_SERIALS:
        raise ValueError(
            "persistent planning requires a selected allowlisted non-canary test serial"
        )
    if not uri.startswith("ip:"):
        raise ValueError("persistent planning requires an explicit ip: URI")
    try:
        address = ipaddress.ip_address(uri[3:])
    except ValueError as error:
        raise ValueError("persistent URI must contain one literal IP address") from error
    if not address.is_private or address.version != 4 or int(str(address).rsplit(".", 1)[1]) == 21:
        raise ValueError("persistent URI is not an allowed non-production private test endpoint")


def require_persistent_evidence(paths: list[Path]) -> dict[str, str]:
    if len(paths) != 4:
        raise ValueError(
            "persistent planning requires exact RAM, attestation, qualification, "
            "and cold-cycle evidence"
        )
    names = ("ram_receipt", "ram_attestation", "qualification_verdict", "cold_cycle_receipt")
    result = {}
    for name, path in zip(names, paths, strict=True):
        record = json.loads(path.read_bytes())
        if (
            not isinstance(record, dict)
            or record.get("passed") is not True
            or record.get("firmware") != FIRMWARE
        ):
            raise ValueError(f"persistent {name} is not passed exact-v0.56 evidence")
        result[name] = sha256(path)
    return result


def write_json_once(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("ram", "persistent"), required=True)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--source-manifest", type=Path, required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--uri", required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--ram-receipt", type=Path)
    parser.add_argument("--ram-attestation", type=Path)
    parser.add_argument("--qualification-verdict", type=Path)
    parser.add_argument("--cold-cycle-receipt", type=Path)
    parser.add_argument("--known-hosts", type=Path)
    parser.add_argument("--password-file", type=Path)
    parser.add_argument("--confirm")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    if args.execute and args.phase != "ram":
        parser.error("ordinary persistent execution is intentionally unavailable")
    if args.execute and (not args.known_hosts or not args.password_file):
        parser.error("RAM execution requires private --known-hosts and --password-file")
    require_target(args.phase, args.serial, args.uri)
    binding = validate_release_assets(args.image, args.metadata, args.source_manifest)
    evidence = {}
    if args.phase == "persistent":
        evidence = require_persistent_evidence(
            [
                args.ram_receipt,
                args.ram_attestation,
                args.qualification_verdict,
                args.cold_cycle_receipt,
            ]
        )
    output = args.evidence / "plan.json"
    write_json_once(
        output,
        {
            "schema": "org.leo.v056-deployment-plan/v1",
            "phase": args.phase,
            "dry_run": True,
            "serial": args.serial,
            "uri": args.uri,
            "release_binding": binding,
            "persistent_evidence": evidence,
            "required_live_attestation": [
                "serial",
                "firmware",
                "IIO layout",
                "runtime-rate capability",
            ],
        },
    )
    if not args.execute:
        print(output)
        return 0
    private_bytes(args.known_hosts)
    password = private_bytes(args.password_file).decode(encoding="utf-8").rstrip("\r\n")
    profile_id = register_ram_profile()
    try:
        with acquire_radio_lock(RAM_SERIAL):
            matches = [item for item in scan_local_usb_plutos() if item.serial == RAM_SERIAL]
            if len(matches) != 1 or matches[0].usb_path != str(RAM_SYSFS_PATH):
                raise ValueError("RAM canary requires the exact live serial/sysfs target")
            transport = BoundSshBootstrapTransport(
                host=RAM_TRANSITION_HOST,
                interface=None,
                known_hosts_file=args.known_hosts,
                password=password,
            )
            plan = prepare_ram_boot_plan(
                args.image,
                RAM_SYSFS_PATH,
                profile_id=profile_id,
                transition_host=RAM_TRANSITION_HOST,
                known_hosts_file=args.known_hosts,
            )
            if plan.serial != RAM_SERIAL or plan.before_firmware != RAM_BASELINE:
                raise ValueError("RAM canary baseline is not exact v0.54")
            result = execute_ram_boot_plan(
                plan,
                confirmation=args.confirm or "",
                known_hosts_file=args.known_hosts,
                transition=SshRamBootTransition(transport),
                receipt_directory=args.evidence / "receipts",
            )
            if result.outcome != "success":
                print(json.dumps(dataclasses.asdict(result), default=str))
                return 1
            attestation = attest_ram_return(plan, Path(result.receipt_path), binding)
            write_json_once(args.evidence / "ram-profile-attestation.json", attestation)
            print(json.dumps(dataclasses.asdict(result), default=str))
            return 0
    finally:
        del STANDALONE_FLASH_PROFILES[profile_id]


if __name__ == "__main__":
    raise SystemExit(main())
