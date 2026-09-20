#!/usr/bin/env python3
"""Exact-image v0.55 RAM canary, v0.54 restoration, and gated LAN deployment."""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import runpy
import stat
from datetime import UTC, datetime
from pathlib import Path

from pluto_plus.adaptive_scan import ScanTerminal, ScanVisit, TerminalState, VisitResult
from pluto_plus.bootstrap_firmware import (
    PAIRED_RX_TX_CAPABLE_LAYOUT,
    STANDALONE_FLASH_PROFILES,
    BoundSshBootstrapTransport,
    _require_iio_layout,
    _require_profile_iio_capabilities,
    execute_lan_flash_plan,
    inspect_bound_iiod,
    prepare_lan_flash_plan,
    rotate_lan_ssh_host_key_after_attested_return,
)
from pluto_plus.doctor import FEATURE_103_V1_RELEASE_RAM_POLICY
from pluto_plus.firmware import validate_dfu
from pluto_plus.hardware.discovery import discover_network_iio
from pluto_plus.inventory import scan_local_usb_plutos
from pluto_plus.local_reboot import (
    FixedSshLocalRebootTransport,
    execute_local_reboot,
    prepare_local_reboot,
)
from pluto_plus.radio_lock import acquire_radio_lock
from pluto_plus.volatile_firmware import (
    SshRamBootTransition,
    execute_ram_boot_plan,
    prepare_ram_boot_plan,
)

RAM_SERIAL = "1040007c4a94000211000b009186843ef2"
LAN_SERIAL = "10400056f695001322002d0010ad1719f2"
FIRMWARE = "v0.55-plutoplus-spf-adaptive-runtime-rates"
RESTORE_FIRMWARE = "v0.54-plutoplus-spf-counter-utc-v1-rc1"
LAN_BEFORE = "v0.53-plutoplus-spf-adaptive-scan-v2"
SOURCES = {"firmware_base": "b7fb39e42daa2b0eb8a897ee1b6c321489a93caf",
           "libiio_0_25": "c93db89b27fd46faf5479ceb5bf08460226a88ce",
           "buildroot": "a6ee97729ee2494c759a942ae8b26239bb840833"}
REQUIRED_CELLS = {"baseline-dual2p5", "baseline-single15", "dual5", "dual7p5", "dual8"}


def private_bytes(path):
    state = path.lstat()
    if (not stat.S_ISREG(state.st_mode) or state.st_uid != os.getuid()
            or stat.S_IMODE(state.st_mode) & 0o077):
        raise ValueError("SSH secret/known-hosts file must be private and owned")
    return path.read_bytes()


def manifest(image: Path, path: Path):
    raw = path.read_bytes()
    document = json.loads(raw)
    if document.get("firmware") != FIRMWARE or document.get("utc_hardware_qualified") is not False:
        raise ValueError("candidate firmware or UTC qualification identity is wrong")
    if any(document.get("sources", {}).get(key) != value for key, value in SOURCES.items()):
        raise ValueError("candidate source graph differs from reviewed v0.55 source")
    data = image.read_bytes()
    fit = validate_dfu(data)
    if (hashlib.sha256(data).hexdigest() != document.get("asset_sha256")
            or hashlib.sha256(fit).hexdigest() != document.get("fit_sha256")
            or len(fit) != document.get("fit_size")):
        raise ValueError("candidate DFU/FIT hashes or size differ from manifest")
    return document, hashlib.sha256(raw).hexdigest()


def require_gate(document, manifest_sha, ram_receipt_path, report_paths):
    """Qualify only this image after a successful serial-bound RAM boot and cells."""
    receipt = json.loads(ram_receipt_path.read_bytes())
    plan = receipt.get("plan", {})
    if (receipt.get("outcome") != "success"
            or not {"exact_path_returned_runtime", "return_attested", "tx_safe_attested"}
            <= set(receipt.get("phases", []))
            or plan.get("serial") != RAM_SERIAL
            or plan.get("image_sha256") != document["asset_sha256"]
            or plan.get("expected_firmware") != FIRMWARE
            or receipt.get("returned_serial") != RAM_SERIAL
            or receipt.get("returned_firmware") != FIRMWARE):
        raise ValueError("RAM receipt does not prove this exact candidate and canary")
    seen = set()
    digests = {}
    qualification = runpy.run_path(
        str(Path(__file__).with_name("issue111_adaptive_qualification.py"))
    )
    for path in report_paths:
        raw = path.read_bytes()
        report = json.loads(raw)
        binding = report.get("candidate_binding", {})
        if (report.get("schema") != "org.leo.issue111-adaptive-qualification/v1"
                or report.get("serial") != RAM_SERIAL
                or binding.get("firmware") != FIRMWARE
                or binding.get("image_sha256") != document["asset_sha256"]
                or binding.get("manifest_sha256") != manifest_sha
                or report.get("restored_to_pre_attempt") is not True):
            raise ValueError("capture evidence identity or restoration mismatch")
        cell = report.get("cell")
        expected = qualification["CELLS"].get(cell)
        requested = report.get("requested_setup", {})
        if expected is None or (
            requested.get("source_rate_hz"), requested.get("rx_mask"), requested.get("duration_ms")
        ) != expected:
            raise ValueError("capture request does not match the declared qualification cell")
        if cell in seen:
            raise ValueError("duplicate qualification cell")
        seen.add(cell)
        if cell == "unusual" and report.get("status") not in ("completed", "rate_rejected"):
            raise ValueError("unusual rate must complete or explicitly reject with restoration")
        if report.get("status") == "rate_rejected" and (
            report.get("visits")
            or report.get("error") not in ("RadioConfigurationError", "ValueError")
            or "rate" not in report.get("message", "").lower()
        ):
            raise ValueError("unusual rejection lacks an explicit pre-capture rate failure")
        if cell in REQUIRED_CELLS or report.get("status") == "completed":
            terminal = report.get("receipt", {}).get("terminal", {})
            accounting = report.get("accounting", {})
            records = [ScanVisit(**{**row, "result": VisitResult(row["result"])})
                       for row in report.get("visits", [])]
            for record in records:
                record.pack()
                if record.source_rate_hz != expected[0]:
                    raise ValueError("visit rate differs from the qualification request")
            terminal_record = ScanTerminal(
                **{**terminal, "state": TerminalState(terminal["state"])}
            )
            terminal_record.pack()
            computed = qualification["summarize"](
                records, terminal_record, expected[0], expected[1]
            )
            if computed != accounting:
                raise ValueError("capture accounting does not reproduce from recorded visits")
            if (report.get("status") != "completed" or terminal.get("state") != 1
                    or terminal.get("invalid") != 0 or terminal.get("cancelled") != 0
                    or terminal.get("error") != 0
                    or sum(accounting.get("partition_samples", {}).values())
                    != accounting.get("source_span_samples")
                    or accounting.get("iq_bytes", 0) <= 0
                    or accounting.get("source_span_samples", 0)
                    < expected[0] * (expected[2] - 1000) // 1000
                    or accounting.get("iq_bytes") != terminal.get("iq_bytes")):
                raise ValueError("required capture cell did not pass integrity checks")
        digests[str(path)] = hashlib.sha256(raw).hexdigest()
    if not seen >= REQUIRED_CELLS or "unusual" not in seen:
        raise ValueError("missing required baseline/runtime/unusual qualification cells")
    return {"ram_receipt_sha256": hashlib.sha256(ram_receipt_path.read_bytes()).hexdigest(),
            "reports": digests, "utc_hardware_qualified": False}


def register_profile(document, image, *, qualified):
    base = STANDALONE_FLASH_PROFILES[FEATURE_103_V1_RELEASE_RAM_POLICY.profile_id]
    profile_id = f"issue111-{document['asset_sha256'][:12]}-{'lan' if qualified else 'ram'}"
    policy = base.policy.model_copy(update={
        "profile_id": profile_id, "release_tag": FIRMWARE,
        "device_firmware": FIRMWARE, "asset_name": image.name,
        "asset_sha256": document["asset_sha256"],
        "fit_body_sha256": document["fit_sha256"], "fit_body_size": document["fit_size"],
        "source_commit": SOURCES["firmware_base"],
        "release_url": document.get("release_url", "https://github.com/misko/plutosdr-fw/issues/111"),
        "hardware_qualified": qualified, "published_at": datetime.now(UTC),
    })
    STANDALONE_FLASH_PROFILES[profile_id] = dataclasses.replace(
        base, policy=policy, persistent_allowed=qualified,
        source_iio_layout=PAIRED_RX_TX_CAPABLE_LAYOUT,
        return_iio_layout=PAIRED_RX_TX_CAPABLE_LAYOUT,
        allowed_before_firmwares=(LAN_BEFORE,) if qualified else (RESTORE_FIRMWARE,),
        required_iio_capabilities=base.required_iio_capabilities
        + (("iio,adaptive-scan-runtime-rates", "2"),),
    )
    return profile_id


def attest_ram_profile(plan, receipt_path, manifest_sha):
    """Supplement the existing RAM receipt with profile checks its executor lacks."""
    matches = [item for item in scan_local_usb_plutos()
               if item.serial == RAM_SERIAL and item.usb_path == plan.usb_sysfs_path]
    if (len(matches) != 1
            or tuple(item.name for item in matches[0].host_network_interfaces)
            != (plan.usb_interface,)):
        raise ValueError("RAM profile attestation lost exact serial/USB path/interface")
    facts = inspect_bound_iiod(plan.usb_interface)
    if facts.get("hw_serial") != RAM_SERIAL or facts.get("fw_version") != FIRMWARE:
        raise ValueError("RAM profile attestation firmware or serial mismatch")
    profile = STANDALONE_FLASH_PROFILES[plan.profile_id]
    _require_iio_layout(facts, profile, profile.return_iio_layout, transport="RAM USB")
    _require_profile_iio_capabilities(facts, profile, transport="RAM USB")
    return {"schema": "issue111.ram-profile-attestation/v1", "passed": True,
            "serial": RAM_SERIAL, "firmware": FIRMWARE, "image_sha256": plan.image_sha256,
            "manifest_sha256": manifest_sha,
            "ram_receipt_sha256": hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
            "usb_sysfs_path": plan.usb_sysfs_path, "usb_interface": plan.usb_interface,
            "rx_scan_channels": sorted(facts["cf-ad9361-lpc,scan_channels"]),
            "capabilities": {key: str(facts[key]) for key, _ in profile.required_iio_capabilities}}


def require_ram_attestation(path, document, manifest_sha, ram_receipt_path):
    raw = path.read_bytes()
    evidence = json.loads(raw)
    ram = json.loads(ram_receipt_path.read_bytes())
    plan = ram.get("plan", {})
    if (evidence.get("schema") != "issue111.ram-profile-attestation/v1"
            or evidence.get("passed") is not True or evidence.get("serial") != RAM_SERIAL
            or evidence.get("firmware") != FIRMWARE
            or evidence.get("image_sha256") != document["asset_sha256"]
            or evidence.get("manifest_sha256") != manifest_sha
            or evidence.get("ram_receipt_sha256")
            != hashlib.sha256(ram_receipt_path.read_bytes()).hexdigest()
            or evidence.get("usb_sysfs_path") != plan.get("usb_sysfs_path")
            or evidence.get("usb_interface") != plan.get("usb_interface")
            or not set(evidence.get("rx_scan_channels", [])) >= {f"voltage{i}" for i in range(4)}):
        raise ValueError("RAM profile attestation does not bind this exact image and receipt")
    base = STANDALONE_FLASH_PROFILES[FEATURE_103_V1_RELEASE_RAM_POLICY.profile_id]
    for key, value in (*base.required_iio_capabilities, ("iio,adaptive-scan-runtime-rates", "2")):
        if evidence.get("capabilities", {}).get(key) != value:
            raise ValueError("RAM profile attestation lacks a required exact capability")
    return hashlib.sha256(raw).hexdigest()


def write_json(path, document):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(document, stream, indent=2, default=str)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("ram", "restore", "lan"), required=True)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--known-hosts", type=Path, required=True)
    parser.add_argument("--password-file", type=Path)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--ram-receipt", type=Path)
    parser.add_argument("--ram-attestation", type=Path)
    parser.add_argument("--restore-receipt", type=Path)
    parser.add_argument("--report", action="append", type=Path, default=[])
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirm")
    args = parser.parse_args()
    document, manifest_sha = manifest(args.image, args.manifest)
    gate = None
    if args.phase == "lan":
        if not args.ram_receipt or not args.restore_receipt or not args.ram_attestation:
            parser.error("LAN requires RAM/restoration receipts, RAM attestation, and captures")
        gate = require_gate(document, manifest_sha, args.ram_receipt, args.report)
        gate["ram_attestation_sha256"] = require_ram_attestation(
            args.ram_attestation, document, manifest_sha, args.ram_receipt
        )
        restore_raw = args.restore_receipt.read_bytes()
        restore = json.loads(restore_raw)
        if (restore.get("outcome") != "success"
                or restore.get("plan", {}).get("serial") != RAM_SERIAL
                or restore.get("before", {}).get("firmware") != FIRMWARE
                or restore.get("after", {}).get("firmware") != RESTORE_FIRMWARE
                or restore.get("after", {}).get("serial") != RAM_SERIAL):
            raise ValueError("canary restoration receipt is not exact v0.54 success")
        gate["restore_receipt_sha256"] = hashlib.sha256(restore_raw).hexdigest()
    profile = register_profile(document, args.image, qualified=args.phase == "lan")
    private_bytes(args.known_hosts)
    serial = LAN_SERIAL if args.phase == "lan" else RAM_SERIAL
    host = "192.168.1.21" if args.phase == "lan" else "192.168.1.18"
    transport = None
    if args.execute:
        if not args.password_file:
            parser.error("execution requires an owned private --password-file")
        transport = BoundSshBootstrapTransport(
            host=host, interface=None, known_hosts_file=args.known_hosts,
            password=private_bytes(args.password_file).decode().rstrip("\r\n"),
        )
    with acquire_radio_lock(serial):
        if args.phase == "lan":
            plan, frm = prepare_lan_flash_plan(
                args.image, serial=serial, host=host, mutation_profile_id=profile,
                flash_transport=transport,
            )
        else:
            matches = [item for item in scan_local_usb_plutos() if item.serial == serial]
            if len(matches) != 1:
                raise ValueError("exact RAM canary must be one attached USB radio")
            usb = Path(matches[0].usb_path)
            if args.phase == "ram":
                plan = prepare_ram_boot_plan(
                    args.image, usb, profile_id=profile,
                    transition_host=host, known_hosts_file=args.known_hosts,
                )
                if plan.before_firmware != RESTORE_FIRMWARE:
                    raise ValueError("RAM canary source must be exact v0.54 firmware")
            else:
                observed = discover_network_iio([f"{host}/32"], max_hosts=1, workers=1)
                if (len(observed) != 1 or observed[0].serial != RAM_SERIAL
                        or observed[0].firmware_version != FIRMWARE):
                    raise ValueError("restoration must start from the exact canary firmware")
                plan = prepare_local_reboot(
                    serial, usb, ssh_host=host, known_hosts_file=args.known_hosts,
                    expected_return_firmware=RESTORE_FIRMWARE,
                    expected_return_rx_scan_channels=(
                        "voltage0", "voltage1", "voltage2", "voltage3"
                    ),
                    expected_return_tandem_agc=True, expected_return_detector_only=False,
                )
        write_json(args.evidence / "plan.json", {"phase": args.phase,
                   "manifest_sha256": manifest_sha, "gate": gate, "plan": dataclasses.asdict(plan)})
        if not args.execute:
            print(args.evidence / "plan.json")
            return 0
        if args.phase == "ram":
            result = execute_ram_boot_plan(
                plan, confirmation=args.confirm or "", known_hosts_file=args.known_hosts,
                transition=SshRamBootTransition(transport),
                receipt_directory=args.evidence / "receipts",
            )
            if result.outcome == "success":
                attestation = attest_ram_profile(plan, Path(result.receipt_path), manifest_sha)
                write_json(args.evidence / "ram-profile-attestation.json", attestation)
        elif args.phase == "restore":
            result = execute_local_reboot(
                plan, confirmation=args.confirm or "", known_hosts_file=args.known_hosts,
                transport=FixedSshLocalRebootTransport(transport),
                receipt_directory=args.evidence / "receipts",
            )
        else:
            def rotate():
                return rotate_lan_ssh_host_key_after_attested_return(
                    serial=serial, host=host, expected_firmware=FIRMWARE,
                    expected_metadata_abi=plan.expected_metadata_abi,
                    password=private_bytes(args.password_file).decode().rstrip("\r\n"),
                    known_hosts_file=args.known_hosts,
                )
            result = execute_lan_flash_plan(
                plan, frm, confirmation=args.confirm or "", transport=transport,
                receipt_directory=args.evidence / "receipts", host_key_rotator=rotate,
            )
        print(json.dumps(dataclasses.asdict(result), default=str))
        return int(result.outcome != "success")


if __name__ == "__main__":
    raise SystemExit(main())
