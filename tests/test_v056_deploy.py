"""Offline contract tests for the fail-closed v0.56 deployment planner."""

import hashlib
import json
import runpy
from contextlib import nullcontext
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts/v056_deploy.py"


def values():
    return runpy.run_path(str(SCRIPT))


def test_ram_target_is_exact_observed_usb_canary():
    module = values()
    module["require_target"]("ram", module["RAM_SERIAL"], module["RAM_URI"])
    with pytest.raises(ValueError, match="restricted"):
        module["require_target"]("ram", module["RAM_SERIAL"], "usb:3.75.6")


def test_persistent_target_requires_allowlisted_nonproduction_endpoint():
    module = values()
    serial = next(iter(module["PERSISTENT_TEST_SERIALS"]))
    module["require_target"]("persistent", serial, "ip:192.168.1.19")
    with pytest.raises(ValueError, match="non-production"):
        module["require_target"]("persistent", serial, "ip:192.168.1.21")


def test_metadata_binds_all_official_values_before_dfu_parse(monkeypatch, tmp_path):
    module = values()
    image, metadata, source = (
        tmp_path / "a.dfu",
        tmp_path / "metadata.json",
        tmp_path / "source.yaml",
    )
    raw, source_raw = b"dfu", b"source"
    image.write_bytes(raw)
    source.write_bytes(source_raw)
    document = {
        key: module[key.upper()]
        for key in (
            "firmware_source",
            "firmware",
            "source_manifest_sha256",
            "dfu_sha256",
            "dfu_bytes",
            "build_run",
            "build_artifact",
            "companion_source",
        )
    }
    document["firmware_source_commit"] = document.pop("firmware_source")
    document["companion_source_commit"] = document.pop("companion_source")
    document["source_manifest_sha256"] = hashlib.sha256(source_raw).hexdigest()
    document["dfu_sha256"] = hashlib.sha256(raw).hexdigest()
    document["dfu_bytes"] = len(raw)
    document["fit_sha256"] = hashlib.sha256(b"fit").hexdigest()
    document["fit_bytes"] = len(b"fit")
    namespace = module["validate_release_assets"].__globals__
    monkeypatch.setitem(namespace, "SOURCE_MANIFEST_SHA256", document["source_manifest_sha256"])
    monkeypatch.setitem(namespace, "DFU_SHA256", document["dfu_sha256"])
    monkeypatch.setitem(namespace, "DFU_BYTES", document["dfu_bytes"])
    monkeypatch.setitem(namespace, "FIT_SHA256", document["fit_sha256"])
    monkeypatch.setitem(namespace, "FIT_BYTES", document["fit_bytes"])
    metadata.write_text(json.dumps(document))
    monkeypatch.setitem(namespace, "validate_dfu", lambda _: b"fit")
    assert (
        module["validate_release_assets"](image, metadata, source)["firmware"] == module["FIRMWARE"]
    )
    document["build_artifact"] = 0
    metadata.write_text(json.dumps(document))
    with pytest.raises(ValueError, match="exact official"):
        module["validate_release_assets"](image, metadata, source)


def test_persistent_evidence_requires_all_four_passed_files(tmp_path):
    module = values()
    paths = []
    for name in range(4):
        path = tmp_path / str(name)
        path.write_text(json.dumps({"passed": True, "firmware": module["FIRMWARE"]}))
        paths.append(path)
    assert len(module["require_persistent_evidence"](paths)) == 4
    paths[-1].write_text(json.dumps({"passed": False, "firmware": module["FIRMWARE"]}))
    with pytest.raises(ValueError, match="cold_cycle"):
        module["require_persistent_evidence"](paths)


def test_ram_profile_is_process_local_and_has_no_persistent_authority():
    module = values()
    profiles = module["STANDALONE_FLASH_PROFILES"]
    profile_id = module["register_ram_profile"]()
    try:
        profile = profiles[profile_id]
        assert profile.policy.profile_id == profile_id
        assert profile.policy.device_firmware == module["FIRMWARE"]
        assert profile.policy.asset_sha256 == module["DFU_SHA256"]
        assert profile.policy.fit_body_sha256 == module["FIT_SHA256"]
        assert profile.policy.fit_body_size == module["FIT_BYTES"]
        assert profile.policy.source_commit == module["FIRMWARE_SOURCE"]
        assert profile.policy.hardware_qualified is False
        assert profile.persistent_allowed is False
        assert profile.allowed_before_firmwares == (module["RAM_BASELINE"],)
        assert profile.source_iio_layout == module["PAIRED_RX_TX_CAPABLE_LAYOUT"]
        assert profile.return_iio_layout == module["PAIRED_RX_TX_CAPABLE_LAYOUT"]
        assert ("iio,adaptive-scan-runtime-rates", "2") in profile.required_iio_capabilities
    finally:
        del profiles[profile_id]


def test_ram_return_attestation_binds_exact_serial_sysfs_firmware_and_receipt(
    monkeypatch, tmp_path
):
    module = values()
    profile_id = module["register_ram_profile"]()
    profile = module["STANDALONE_FLASH_PROFILES"][profile_id]
    plan = SimpleNamespace(
        profile_id=profile_id,
        usb_interface="usb-canary",
        usb_sysfs_path=str(module["RAM_SYSFS_PATH"]),
        transition_host=module["RAM_TRANSITION_HOST"],
    )
    inventory = SimpleNamespace(
        serial=module["RAM_SERIAL"], usb_path=str(module["RAM_SYSFS_PATH"])
    )
    facts = {
        "hw_serial": module["RAM_SERIAL"],
        "fw_version": module["FIRMWARE"],
        **dict(profile.required_iio_capabilities),
    }
    receipt = tmp_path / "receipt.json"
    receipt.write_text('{"outcome":"success"}')
    attest = module["attest_ram_return"]
    namespace = attest.__globals__
    monkeypatch.setitem(namespace, "scan_local_usb_plutos", lambda: [inventory])
    monkeypatch.setitem(namespace, "inspect_bound_iiod", lambda _: facts)
    monkeypatch.setitem(namespace, "_require_iio_layout", lambda *_args, **_kwargs: None)
    monkeypatch.setitem(
        namespace, "_require_profile_iio_capabilities", lambda *_args, **_kwargs: None
    )
    try:
        result = attest(plan, receipt, {"dfu_sha256": module["DFU_SHA256"]})
        assert result["passed"] is True
        assert result["serial"] == module["RAM_SERIAL"]
        assert result["usb_sysfs_path"] == str(module["RAM_SYSFS_PATH"])
        assert result["ram_receipt_sha256"] == hashlib.sha256(receipt.read_bytes()).hexdigest()
        inventory.usb_path = "/sys/bus/usb/devices/3-99"
        with pytest.raises(ValueError, match="serial/sysfs"):
            attest(plan, receipt, {})
    finally:
        del module["STANDALONE_FLASH_PROFILES"][profile_id]


def test_cli_rejects_persistent_execute_before_any_plan_or_hardware_call(monkeypatch, tmp_path):
    module = values()
    main = module["main"]
    namespace = main.__globals__
    called = False

    def unexpected(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("persistent execute must not reach a mutable operation")

    monkeypatch.setitem(namespace, "validate_release_assets", unexpected)
    monkeypatch.setitem(namespace, "write_json_once", unexpected)
    monkeypatch.setattr(
        "sys.argv",
        [
            str(SCRIPT),
            "--phase",
            "persistent",
            "--execute",
            "--image",
            "unused.dfu",
            "--metadata",
            "unused.json",
            "--source-manifest",
            "unused.yaml",
            "--serial",
            next(iter(module["PERSISTENT_TEST_SERIALS"])),
            "--uri",
            "ip:192.168.1.19",
            "--evidence",
            str(tmp_path / "evidence"),
        ],
    )
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 2
    assert called is False
    assert not (tmp_path / "evidence").exists()


def test_cli_ram_execute_uses_exact_bindings_and_writes_receipt_attestation(
    monkeypatch, tmp_path
):
    module = values()
    main = module["main"]
    namespace = main.__globals__
    evidence = tmp_path / "evidence"
    known_hosts = tmp_path / "known_hosts"
    password_file = tmp_path / "password"
    known_hosts.write_text("host-key")
    password_file.write_text("password\n")
    known_hosts.chmod(0o600)
    password_file.chmod(0o600)
    receipt = tmp_path / "receipt.json"
    receipt.write_text('{"outcome":"success"}')
    calls = {}

    @dataclass
    class Result:
        outcome: str
        receipt_path: str

    def fake_prepare(image, sysfs_path, *, profile_id, transition_host, known_hosts_file):
        profile = namespace["STANDALONE_FLASH_PROFILES"][profile_id]
        assert profile.persistent_allowed is False
        assert profile.policy.hardware_qualified is False
        assert sysfs_path == module["RAM_SYSFS_PATH"]
        assert transition_host == module["RAM_TRANSITION_HOST"]
        assert known_hosts_file == known_hosts
        calls["profile_id"] = profile_id
        return SimpleNamespace(
            serial=module["RAM_SERIAL"],
            before_firmware=module["RAM_BASELINE"],
            usb_sysfs_path=str(module["RAM_SYSFS_PATH"]),
            transition_host=module["RAM_TRANSITION_HOST"],
            usb_interface="usb-canary",
            profile_id=profile_id,
        )

    def fake_execute(plan, *, confirmation, known_hosts_file, transition, receipt_directory):
        assert plan.profile_id == calls["profile_id"]
        assert confirmation == "RAM BOOT"
        assert known_hosts_file == known_hosts
        assert receipt_directory == evidence / "receipts"
        calls["transition"] = transition
        return Result(outcome="success", receipt_path=str(receipt))

    def fake_attest(plan, receipt_path, binding):
        assert plan.profile_id == calls["profile_id"]
        assert receipt_path == receipt
        assert binding == {"firmware": module["FIRMWARE"]}
        return {"passed": True, "serial": module["RAM_SERIAL"], "receipt": str(receipt)}

    monkeypatch.setitem(
        namespace,
        "validate_release_assets",
        lambda *_: {"firmware": module["FIRMWARE"]},
    )
    monkeypatch.setitem(namespace, "acquire_radio_lock", lambda serial: nullcontext())
    monkeypatch.setitem(
        namespace,
        "scan_local_usb_plutos",
        lambda: [
            SimpleNamespace(
                serial=module["RAM_SERIAL"], usb_path=str(module["RAM_SYSFS_PATH"])
            )
        ],
    )
    monkeypatch.setitem(namespace, "BoundSshBootstrapTransport", lambda **kwargs: kwargs)
    monkeypatch.setitem(namespace, "SshRamBootTransition", lambda transport: transport)
    monkeypatch.setitem(namespace, "prepare_ram_boot_plan", fake_prepare)
    monkeypatch.setitem(namespace, "execute_ram_boot_plan", fake_execute)
    monkeypatch.setitem(namespace, "attest_ram_return", fake_attest)
    monkeypatch.setattr(
        "sys.argv",
        [
            str(SCRIPT),
            "--phase",
            "ram",
            "--execute",
            "--image",
            "unused.dfu",
            "--metadata",
            "unused.json",
            "--source-manifest",
            "unused.yaml",
            "--serial",
            module["RAM_SERIAL"],
            "--uri",
            module["RAM_URI"],
            "--evidence",
            str(evidence),
            "--known-hosts",
            str(known_hosts),
            "--password-file",
            str(password_file),
            "--confirm",
            "RAM BOOT",
        ],
    )

    assert main() == 0
    assert "transition" in calls
    assert json.loads((evidence / "plan.json").read_text())["dry_run"] is True
    assert json.loads((evidence / "ram-profile-attestation.json").read_text()) == {
        "passed": True,
        "receipt": str(receipt),
        "serial": module["RAM_SERIAL"],
    }
    assert calls["profile_id"] not in namespace["STANDALONE_FLASH_PROFILES"]
