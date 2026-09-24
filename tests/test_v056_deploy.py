"""Offline contract tests for the fail-closed v0.56 deployment planner."""

import hashlib
import json
import runpy
from pathlib import Path

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
