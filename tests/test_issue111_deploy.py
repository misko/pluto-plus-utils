from __future__ import annotations

import dataclasses
import hashlib
import json
import runpy
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from pluto_plus.adaptive_scan import ScanTerminal, ScanVisit, TerminalState, VisitResult
from pluto_plus.bootstrap_firmware import STANDALONE_FLASH_PROFILES
from pluto_plus.doctor import FEATURE_103_V1_RELEASE_RAM_POLICY

SCRIPT = Path(__file__).parents[1] / "scripts/issue111_deploy.py"


def test_manifest_requires_exact_reviewed_source_and_image(monkeypatch, tmp_path):
    module = runpy.run_path(str(SCRIPT))
    image, path = tmp_path / "candidate.dfu", tmp_path / "candidate.json"
    image.write_bytes(b"exact-image")
    document = {"firmware": module["FIRMWARE"], "utc_hardware_qualified": False,
                "sources": module["SOURCES"],
                "asset_sha256": hashlib.sha256(b"exact-image").hexdigest(),
                "fit_sha256": hashlib.sha256(b"fit").hexdigest(), "fit_size": 3}
    path.write_text(json.dumps(document))
    validate = module["manifest"]
    monkeypatch.setitem(validate.__globals__, "validate_dfu", lambda _: b"fit")
    assert validate(image, path)[0] == document
    image.write_bytes(b"other-image")
    with pytest.raises(ValueError, match="hashes"):
        validate(image, path)
    document["sources"] = {**document["sources"], "libiio_0_25": "0" * 40}
    path.write_text(json.dumps(document))
    with pytest.raises(ValueError, match="source graph"):
        validate(image, path)


def test_ram_profile_preserves_v054_capabilities_without_persistent_authority():
    module = runpy.run_path(str(SCRIPT))
    base = STANDALONE_FLASH_PROFILES[FEATURE_103_V1_RELEASE_RAM_POLICY.profile_id]
    document = {"asset_sha256": "a" * 64, "fit_sha256": "b" * 64, "fit_size": 1234}
    selected = module["register_profile"](document, Path("candidate.dfu"), qualified=False)
    try:
        profile = STANDALONE_FLASH_PROFILES[selected]
        assert not profile.policy.hardware_qualified and not profile.persistent_allowed
        assert profile.allowed_before_firmwares == (module["RESTORE_FIRMWARE"],)
        assert profile.source_iio_layout == profile.return_iio_layout
        assert set(base.required_iio_capabilities) <= set(profile.required_iio_capabilities)
        assert ("iio,adaptive-scan-runtime-rates", "2") in profile.required_iio_capabilities
        assert ("iio,buffer-counter-metadata-topology-supported", "1") in (
            profile.required_iio_capabilities
        )
    finally:
        del STANDALONE_FLASH_PROFILES[selected]


def test_gate_rejects_missing_or_wrong_image_receipt(tmp_path):
    module = runpy.run_path(str(SCRIPT))
    path = tmp_path / "ram.json"
    path.write_text(json.dumps({"outcome": "success", "plan": {"image_sha256": "wrong"}}))
    with pytest.raises(ValueError, match="RAM receipt"):
        module["require_gate"]({"asset_sha256": "a" * 64}, "b" * 64, path, [])
    path.write_text(json.dumps({
        "outcome": "success", "phases": ["exact_path_returned_runtime", "return_attested",
                                          "tx_safe_attested"],
        "plan": {"serial": module["RAM_SERIAL"], "image_sha256": "a" * 64,
                 "expected_firmware": module["FIRMWARE"]},
        "returned_serial": module["RAM_SERIAL"], "returned_firmware": module["FIRMWARE"],
    }))
    with pytest.raises(ValueError, match="missing required"):
        module["require_gate"]({"asset_sha256": "a" * 64}, "b" * 64, path, [])


def test_private_ssh_material_rejects_public_permissions(tmp_path):
    private = runpy.run_path(str(SCRIPT))["private_bytes"]
    path = tmp_path / "secret"
    path.write_bytes(b"never-print")
    path.chmod(0o644)
    with pytest.raises(ValueError, match="private"):
        private(path)
    path.chmod(0o600)
    assert private(path) == b"never-print"


@pytest.mark.parametrize("unusual_outcome", ["completed", "rate_rejected"])
def test_gate_recomputes_source_and_iq_evidence_for_every_cell(tmp_path, unusual_outcome):
    module = runpy.run_path(str(SCRIPT))
    qualification = runpy.run_path(str(SCRIPT.with_name("issue111_adaptive_qualification.py")))
    ram = tmp_path / "ram.json"
    ram.write_text(json.dumps({
        "outcome": "success", "phases": ["exact_path_returned_runtime", "return_attested",
                                          "tx_safe_attested"],
        "plan": {"serial": module["RAM_SERIAL"], "image_sha256": "a" * 64,
                 "expected_firmware": module["FIRMWARE"]},
        "returned_serial": module["RAM_SERIAL"], "returned_firmware": module["FIRMWARE"],
    }))
    paths = []
    for name, (rate, rx, duration) in qualification["CELLS"].items():
        if name.startswith("smoke-"):
            continue
        samples = rate * 120 // 1000
        visit = ScanVisit(session=1, generation=2, visit=0, selection_counter=0,
                          transition_before=0, transition_after=10, valid_start=20,
                          valid_end=20 + samples, frequency_hz=959_687_498,
                          iq_bytes=samples * 4 * rx.bit_count(), missing_samples_before=0,
                          analog_bandwidth_hz=rate, source_rate_hz=rate, target=0, profile=1,
                          result=VisitResult.COMPLETE, eligible_mask=15, effective_weight=65536,
                          profile_crc32=1, protocol_version=2)
        final_counter = rate * duration // 1000
        terminal = ScanTerminal(session=1, generation=2, final_counter=final_counter,
                                restore_before=final_counter, restore_after=final_counter + 1,
                                planned=1, delivered=1, skipped=0, invalid=0, cancelled=0,
                                iq_bytes=visit.iq_bytes, state=TerminalState.COMPLETED,
                                reason=1, error=0)
        report = {"schema": "org.leo.issue111-adaptive-qualification/v1",
                  "cell": name, "serial": module["RAM_SERIAL"], "status": "completed",
                  "candidate_binding": {"firmware": module["FIRMWARE"],
                                        "image_sha256": "a" * 64, "manifest_sha256": "b" * 64},
                  "restored_to_pre_attempt": True,
                  "requested_setup": {"source_rate_hz": rate, "rx_mask": rx,
                                      "duration_ms": duration},
                  "receipt": {"terminal": dataclasses.asdict(terminal)},
                  "visits": [dataclasses.asdict(visit)],
                  "accounting": qualification["summarize"]([visit], terminal, rate, rx)}
        path = tmp_path / f"{name}.json"
        if name == "unusual" and unusual_outcome == "rate_rejected":
            report.update({"status": "rate_rejected", "receipt": None,
                           "accounting": None, "visits": [],
                           "error": "RadioConfigurationError",
                           "message": "AD936x source rate read back 12345678, expected 12345679"})
        path.write_text(json.dumps(report))
        paths.append(path)
    gate = module["require_gate"]({"asset_sha256": "a" * 64}, "b" * 64, ram, paths)
    assert len(gate["reports"]) == 6 and gate["utc_hardware_qualified"] is False
    changed = json.loads(paths[0].read_text())
    changed["accounting"]["iq_bytes"] += 8
    paths[0].write_text(json.dumps(changed))
    with pytest.raises(ValueError, match="does not reproduce"):
        module["require_gate"]({"asset_sha256": "a" * 64}, "b" * 64, ram, paths)


def test_ram_profile_attestation_requires_marker_and_binds_receipt(monkeypatch, tmp_path):
    module = runpy.run_path(str(SCRIPT))
    document = {"asset_sha256": "a" * 64, "fit_sha256": "b" * 64, "fit_size": 1234}
    profile_id = module["register_profile"](document, Path("candidate.dfu"), qualified=False)
    profile = STANDALONE_FLASH_PROFILES[profile_id]
    facts = {**dict(profile.required_iio_capabilities), "hw_serial": module["RAM_SERIAL"],
             "fw_version": module["FIRMWARE"],
             "device_names": ["ad9361-phy", "cf-ad9361-lpc", "tandem-agc"],
             "cf-ad9361-lpc,scan_channels": [f"voltage{i}" for i in range(4)]}
    plan = SimpleNamespace(usb_sysfs_path="/sys/bus/usb/devices/3-5", usb_interface="usb0",
                           profile_id=profile_id, image_sha256="a" * 64)
    local = SimpleNamespace(serial=module["RAM_SERIAL"], usb_path=plan.usb_sysfs_path,
                            host_network_interfaces=[SimpleNamespace(name="usb0")])
    attest = module["attest_ram_profile"]
    monkeypatch.setitem(attest.__globals__, "scan_local_usb_plutos", lambda: [local])
    monkeypatch.setitem(attest.__globals__, "inspect_bound_iiod", lambda _: facts)
    receipt = tmp_path / "ram.json"
    receipt.write_text(json.dumps({"plan": {"usb_sysfs_path": plan.usb_sysfs_path,
                                           "usb_interface": "usb0"}}))
    try:
        result = attest(plan, receipt, "c" * 64)
        output = tmp_path / "attestation.json"
        output.write_text(json.dumps(result))
        assert module["require_ram_attestation"](output, document, "c" * 64, receipt)
        facts["iio,adaptive-scan-runtime-rates"] = "1"
        with pytest.raises(RuntimeError, match="capability"):
            attest(plan, receipt, "c" * 64)
        receipt.write_text(receipt.read_text() + "\n")
        with pytest.raises(ValueError, match="bind"):
            module["require_ram_attestation"](output, document, "c" * 64, receipt)
    finally:
        del STANDALONE_FLASH_PROFILES[profile_id]


def test_ram_helper_refuses_wrong_source_before_writing_plan(monkeypatch, tmp_path):
    module = runpy.run_path(str(SCRIPT))
    main = module["main"]
    namespace = main.__globals__
    monkeypatch.setitem(namespace, "manifest", lambda *_: ({}, "a" * 64))
    monkeypatch.setitem(namespace, "register_profile", lambda *_, **__: "fake")
    monkeypatch.setitem(namespace, "private_bytes", lambda _: b"")
    monkeypatch.setitem(namespace, "acquire_radio_lock", lambda _: nullcontext())
    monkeypatch.setitem(namespace, "scan_local_usb_plutos", lambda: [
        SimpleNamespace(serial=module["RAM_SERIAL"], usb_path="/sys/bus/usb/devices/3-5")
    ])
    monkeypatch.setitem(namespace, "prepare_ram_boot_plan", lambda *_, **__: (
        SimpleNamespace(before_firmware="wrong-v0.53")
    ))
    evidence = tmp_path / "evidence"
    monkeypatch.setattr("sys.argv", [str(SCRIPT), "--phase", "ram", "--image", "unused",
                                    "--manifest", "unused", "--known-hosts", "unused",
                                    "--evidence", str(evidence)])
    with pytest.raises(ValueError, match="exact v0.54"):
        main()
    assert not evidence.exists()
