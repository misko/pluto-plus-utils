"""Strict, additive qualification of the opt-in scanner host runtime."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import pluto_plus.hardware.preflight as preflight


@pytest.fixture
def scanner_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    prefix = tmp_path / "release/.venv"
    native = prefix / "lib/libiio.so.0.25"
    binding = prefix / "lib/python3.11/site-packages/iio.py"
    receipt = prefix / preflight.METADATA_RUNTIME_RECEIPT
    for path in (native, binding, receipt):
        path.parent.mkdir(parents=True, exist_ok=True)
    native.write_bytes(b"pinned scanner native fixture")
    binding.write_text("# pinned scanner binding fixture\n")
    document = {
        "schema_version": 1,
        "metadata_abi": 3,
        "source_ref": preflight.SCANNER_GLRT_RUNTIME_SOURCE_COMMIT,
        "source_commit": preflight.SCANNER_GLRT_RUNTIME_SOURCE_COMMIT,
        "native_libiio_path": str(native),
        "native_libiio_sha256": hashlib.sha256(native.read_bytes()).hexdigest(),
        "pylibiio_path": str(binding),
        "pylibiio_sha256": hashlib.sha256(binding.read_bytes()).hexdigest(),
        "metadata_buffer_parameters": list(preflight.METADATA_BUFFER_PARAMETERS[3]),
    }
    receipt.write_text(json.dumps(document))

    class MetadataBuffer:
        def __init__(
            self,
            device,
            samples_count,
            request,
            metadata_capacity=65536,
            batch_frames=1,
            ddr_burst_bytes=0,
            ddr_ring_bytes=0,
            ddr_ring_frames=0,
            ddr_ring_continuous=False,
            direct_async_frames=0,
            drop_backlog_on_overrun=True,
        ):
            pass

        def cancel_metadata_session(self):
            pass

        def metadata_status_raw(self, capacity=65536):
            pass

        def drain_metadata(self, capacity=65536):
            pass

    native_loads: list[str] = []
    module = SimpleNamespace(MetadataBuffer=MetadataBuffer, __file__=str(binding))
    monkeypatch.setattr(preflight.sys, "prefix", str(prefix))
    monkeypatch.setattr(preflight, "CDLL", lambda path, **_kwargs: native_loads.append(path))
    monkeypatch.setattr(preflight, "_mapped_libiio_paths", lambda: (native,))
    monkeypatch.setattr(preflight.importlib, "import_module", lambda _name: module)
    monkeypatch.setattr(
        preflight,
        "inspect_iio_environment",
        lambda **_kwargs: SimpleNamespace(healthy=True, actionable_message=""),
    )
    return SimpleNamespace(
        prefix=prefix,
        native=native,
        binding=binding,
        receipt=receipt,
        document=document,
        module=module,
        native_loads=native_loads,
    )


def test_scanner_runtime_accepts_exact_source_hashes_and_public_apis(scanner_runtime):
    result = preflight.verify_metadata_runtime(expected_abi=3)
    assert result.source_commit == preflight.SCANNER_GLRT_RUNTIME_SOURCE_COMMIT
    assert result.native_libiio_path == str(scanner_runtime.native)
    assert scanner_runtime.native_loads == [str(scanner_runtime.native)]
    # Installing the opt-in never changes the established default source pins.
    assert preflight.METADATA_RUNTIME_SOURCE_COMMITS[3] == (
        "f6c450eada95ce99fe8756ebc244bfcf6ddcc72a"
    )


@pytest.mark.parametrize("abi", (1, 2, 4))
def test_scanner_source_is_not_accepted_for_other_abis(scanner_runtime, abi):
    document = scanner_runtime.document
    document["metadata_abi"] = abi
    document["metadata_buffer_parameters"] = list(preflight.METADATA_BUFFER_PARAMETERS[abi])
    scanner_runtime.receipt.write_text(json.dumps(document))
    with pytest.raises(RuntimeError, match="wrong source commit"):
        preflight.verify_metadata_runtime(expected_abi=abi)
    assert scanner_runtime.native_loads == []


def test_scanner_runtime_rejects_arbitrary_source_before_native_load(scanner_runtime):
    scanner_runtime.document["source_commit"] = "0" * 40
    scanner_runtime.receipt.write_text(json.dumps(scanner_runtime.document))
    with pytest.raises(RuntimeError, match="wrong source commit"):
        preflight.verify_metadata_runtime(expected_abi=3)
    assert scanner_runtime.native_loads == []


@pytest.mark.parametrize("name", ("native", "binding"))
def test_scanner_runtime_rejects_tampering_before_native_load(scanner_runtime, name):
    getattr(scanner_runtime, name).write_bytes(b"tampered")
    with pytest.raises(RuntimeError, match="hash changed"):
        preflight.verify_metadata_runtime(expected_abi=3)
    assert scanner_runtime.native_loads == []


@pytest.mark.parametrize("name", tuple(preflight.SCANNER_GLRT_BUFFER_METHODS))
def test_scanner_runtime_requires_each_public_method(scanner_runtime, name):
    delattr(scanner_runtime.module.MetadataBuffer, name)
    with pytest.raises(RuntimeError, match=f"lacks {name}"):
        preflight.verify_metadata_runtime(expected_abi=3)


@pytest.mark.parametrize("name", tuple(preflight.SCANNER_GLRT_BUFFER_METHODS))
def test_scanner_runtime_rejects_wrong_method_signature(scanner_runtime, name):
    setattr(scanner_runtime.module.MetadataBuffer, name, lambda self, wrong, extra: None)
    with pytest.raises(RuntimeError, match=f"{name} has the wrong ABI"):
        preflight.verify_metadata_runtime(expected_abi=3)
