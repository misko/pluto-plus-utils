from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

import pluto_plus.hardware.preflight as preflight
from pluto_plus.hardware.preflight import (
    IioEnvironmentStatus,
    inspect_iio_environment,
    verify_metadata_runtime,
)


def _spec(name: str) -> SimpleNamespace:
    return SimpleNamespace(origin=f"/venv/{name}.py")


def _locator(name: str) -> SimpleNamespace:
    return _spec(name)


def _modules(*, backends: tuple[str, ...] = ("local", "ip", "usb")) -> dict[str, ModuleType]:
    iio = ModuleType("iio")
    iio.version = (0, 25, "v0.25")  # type: ignore[attr-defined]
    iio.backends = list(backends)  # type: ignore[attr-defined]
    iio._lib = SimpleNamespace(_name="/opt/spf/lib/libiio.so.0")  # type: ignore[attr-defined]
    return {"iio": iio, "adi": ModuleType("adi")}


def test_preflight_distinguishes_missing_hardware_extra() -> None:
    report = inspect_iio_environment(
        locate_module=lambda name: None if name == "adi" else _spec(name),
        locate_library=lambda _name: "libiio.so.0",
    )

    assert report.status is IioEnvironmentStatus.HARDWARE_EXTRA_MISSING
    assert report.healthy is False
    assert report.pyadi_path is None
    assert "uv sync --extra hardware" in report.actionable_message


def test_preflight_distinguishes_missing_native_libiio() -> None:
    report = inspect_iio_environment(
        locate_module=_locator,
        locate_library=lambda _name: None,
    )

    assert report.status is IioEnvironmentStatus.NATIVE_LIBIIO_MISSING
    assert report.native_libiio_path is None
    assert "native libiio" in report.message


def test_preflight_preserves_underlying_abi_error() -> None:
    def incompatible(_name: str) -> ModuleType:
        raise AttributeError("undefined symbol: iio_get_backends_count")

    report = inspect_iio_environment(
        locate_module=_locator,
        locate_library=lambda _name: "libiio.so.0",
        load_module=incompatible,
    )

    assert report.status is IioEnvironmentStatus.LIBIIO_ABI_INCOMPATIBLE
    assert report.native_libiio_candidate == "libiio.so.0"
    assert report.underlying_error == ("AttributeError: undefined symbol: iio_get_backends_count")


def test_preflight_distinguishes_missing_usb_backend() -> None:
    modules = _modules(backends=("local", "ip"))
    report = inspect_iio_environment(
        locate_module=_locator,
        locate_library=lambda _name: "libiio.so.0",
        load_module=modules.__getitem__,
    )

    assert report.status is IioEnvironmentStatus.USB_BACKEND_MISSING
    assert report.backends == ("local", "ip")
    assert "WITH_USB_BACKEND=ON" in report.actionable_message


def test_preflight_healthy_report_includes_version_path_and_backends() -> None:
    modules = _modules()
    report = inspect_iio_environment(
        locate_module=_locator,
        locate_library=lambda _name: "libiio.so.0",
        load_module=modules.__getitem__,
    )

    assert report.status is IioEnvironmentStatus.READY
    assert report.healthy is True
    assert report.libiio_version == "0.25 (v0.25)"
    assert report.native_libiio_path == "/opt/spf/lib/libiio.so.0"
    assert report.backends == ("local", "ip", "usb")


def test_ip_only_preflight_does_not_require_usb_backend(tmp_path: Path) -> None:
    modules = _modules(backends=("ip",))
    report = inspect_iio_environment(
        require_usb=False,
        locate_module=_locator,
        locate_library=lambda _name: "libiio.so.0",
        load_module=modules.__getitem__,
        maps_path=tmp_path / "missing-maps",
    )

    assert report.status is IioEnvironmentStatus.READY
    assert report.healthy is True


def test_pyadi_import_failure_is_classified_after_native_load() -> None:
    modules = _modules()

    def load(name: str) -> ModuleType:
        if name == "adi":
            raise ImportError("cannot import name ad9361")
        return modules[name]

    report = inspect_iio_environment(
        locate_module=_locator,
        locate_library=lambda _name: "libiio.so.0",
        load_module=load,
    )

    assert report.status is IioEnvironmentStatus.LIBIIO_ABI_INCOMPATIBLE
    assert report.underlying_error == "ImportError: cannot import name ad9361"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_metadata_runtime_gate_binds_release_local_hashes_and_constructor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix = tmp_path / "release/.venv"
    native = prefix / "lib/libiio.so.0.25"
    binding = prefix / "lib/python3.11/site-packages/iio.py"
    receipt = prefix / "share/pluto-plus-utils/metadata-runtime.json"
    native.parent.mkdir(parents=True)
    binding.parent.mkdir(parents=True)
    receipt.parent.mkdir(parents=True)
    native.write_bytes(b"exact native build")
    binding.write_text("# exact binding\n")
    receipt.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "metadata_abi": 1,
                "source_ref": "spf-frame-metadata-source/v0.25-final-v3",
                "source_commit": "c26258bfa33098c2b215e19cf85d448e89499b1a",
                "native_libiio_path": str(native),
                "native_libiio_sha256": _sha256(native),
                "pylibiio_path": str(binding),
                "pylibiio_sha256": _sha256(binding),
                "metadata_buffer_parameters": [
                    "self",
                    "device",
                    "samples_count",
                    "metadata_capacity",
                ],
            }
        )
    )

    class MetadataBuffer:
        def __init__(
            self, device: object, samples_count: int, metadata_capacity: int = 64 * 1024
        ) -> None:
            pass

    module = SimpleNamespace(MetadataBuffer=MetadataBuffer, __file__=str(binding))
    monkeypatch.setattr(preflight.sys, "prefix", str(prefix))
    monkeypatch.setattr(preflight, "CDLL", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(preflight, "_mapped_libiio_paths", lambda: (native,))
    monkeypatch.setattr(preflight.importlib, "import_module", lambda _name: module)
    monkeypatch.setattr(
        preflight,
        "inspect_iio_environment",
        lambda **_kwargs: SimpleNamespace(
            healthy=True,
            native_libiio_path=str(native),
            actionable_message="",
        ),
    )

    result = verify_metadata_runtime(expected_abi=1)

    assert result.metadata_abi == 1
    assert result.native_libiio_sha256 == _sha256(native)
    assert result.pylibiio_path == str(binding)


def test_metadata_runtime_gate_accepts_exact_abi3_request_constructor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix = tmp_path / "release/.venv"
    native = prefix / "lib/libiio.so.0.25"
    binding = prefix / "lib/python3.11/site-packages/iio.py"
    receipt = prefix / "share/pluto-plus-utils/metadata-runtime.json"
    native.parent.mkdir(parents=True)
    binding.parent.mkdir(parents=True)
    receipt.parent.mkdir(parents=True)
    native.write_bytes(b"exact ABI3 native build")
    binding.write_text("# exact ABI3 binding\n")
    receipt.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "metadata_abi": 3,
                "source_ref": "single-rx-metadata-rc1-source/libiio-v1",
                "source_commit": "5dc200af10961e50d3b019cd38bdb8dd3c0e8c3c",
                "native_libiio_path": str(native),
                "native_libiio_sha256": _sha256(native),
                "pylibiio_path": str(binding),
                "pylibiio_sha256": _sha256(binding),
                "metadata_buffer_parameters": [
                    "self",
                    "device",
                    "samples_count",
                    "request",
                    "metadata_capacity",
                    "batch_frames",
                ],
            }
        )
    )

    class MetadataBuffer:
        def __init__(
            self,
            device: object,
            samples_count: int,
            request: bytes,
            metadata_capacity: int = 64 * 1024,
            batch_frames: int = 1,
        ) -> None:
            pass

    module = SimpleNamespace(MetadataBuffer=MetadataBuffer, __file__=str(binding))
    monkeypatch.setattr(preflight.sys, "prefix", str(prefix))
    monkeypatch.setattr(preflight, "CDLL", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(preflight, "_mapped_libiio_paths", lambda: (native,))
    monkeypatch.setattr(preflight.importlib, "import_module", lambda _name: module)
    monkeypatch.setattr(
        preflight,
        "inspect_iio_environment",
        lambda **_kwargs: SimpleNamespace(
            healthy=True,
            native_libiio_path=str(native),
            actionable_message="",
        ),
    )

    result = verify_metadata_runtime(expected_abi=3)

    assert result.metadata_abi == 3
    assert result.source_commit == "5dc200af10961e50d3b019cd38bdb8dd3c0e8c3c"


def test_metadata_runtime_gate_rejects_missing_receipt_and_changed_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix = tmp_path / "release/.venv"
    prefix.mkdir(parents=True)
    monkeypatch.setattr(preflight.sys, "prefix", str(prefix))
    with pytest.raises(RuntimeError, match="receipt is missing"):
        verify_metadata_runtime(expected_abi=1)

    native = prefix / "lib/libiio.so.0.25"
    binding = prefix / "lib/python3.11/site-packages/iio.py"
    receipt = prefix / "share/pluto-plus-utils/metadata-runtime.json"
    native.parent.mkdir(parents=True)
    binding.parent.mkdir(parents=True)
    receipt.parent.mkdir(parents=True)
    native.write_bytes(b"changed native build")
    binding.write_text("# exact binding\n")
    receipt.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "metadata_abi": 1,
                "source_ref": "spf-frame-metadata-source/v0.25-final-v3",
                "source_commit": "c26258bfa33098c2b215e19cf85d448e89499b1a",
                "native_libiio_path": str(native),
                "native_libiio_sha256": "0" * 64,
                "pylibiio_path": str(binding),
                "pylibiio_sha256": _sha256(binding),
                "metadata_buffer_parameters": [
                    "self",
                    "device",
                    "samples_count",
                    "metadata_capacity",
                ],
            }
        )
    )

    class MetadataBuffer:
        def __init__(
            self, device: object, samples_count: int, metadata_capacity: int = 64 * 1024
        ) -> None:
            pass

    module = SimpleNamespace(MetadataBuffer=MetadataBuffer, __file__=str(binding))
    monkeypatch.setattr(preflight, "CDLL", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(preflight, "_mapped_libiio_paths", lambda: (native,))
    monkeypatch.setattr(preflight.importlib, "import_module", lambda _name: module)
    monkeypatch.setattr(
        preflight,
        "inspect_iio_environment",
        lambda **_kwargs: SimpleNamespace(
            healthy=True,
            native_libiio_path=str(native),
            actionable_message="",
        ),
    )
    with pytest.raises(RuntimeError, match="native libiio hash changed"):
        verify_metadata_runtime(expected_abi=1)


def test_metadata_runtime_rejects_iio_imported_before_exact_native(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix = tmp_path / "release/.venv"
    native = prefix / "lib/libiio.so.0.25"
    binding = prefix / "lib/python3.11/site-packages/iio.py"
    receipt = prefix / "share/pluto-plus-utils/metadata-runtime.json"
    native.parent.mkdir(parents=True)
    binding.parent.mkdir(parents=True)
    receipt.parent.mkdir(parents=True)
    native.write_bytes(b"exact native build")
    binding.write_text("# exact binding\n")
    receipt.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "metadata_abi": 1,
                "source_ref": "spf-frame-metadata-source/v0.25-final-v3",
                "source_commit": "c26258bfa33098c2b215e19cf85d448e89499b1a",
                "native_libiio_path": str(native),
                "native_libiio_sha256": _sha256(native),
                "pylibiio_path": str(binding),
                "pylibiio_sha256": _sha256(binding),
                "metadata_buffer_parameters": [
                    "self",
                    "device",
                    "samples_count",
                    "metadata_capacity",
                ],
            }
        )
    )
    monkeypatch.setattr(preflight.sys, "prefix", str(prefix))
    monkeypatch.setitem(preflight.sys.modules, "iio", ModuleType("iio"))
    monkeypatch.setattr(
        preflight,
        "_mapped_libiio_paths",
        lambda: (Path("/usr/lib/x86_64-linux-gnu/libiio.so.0.26"),),
    )

    with pytest.raises(RuntimeError, match="imported before"):
        verify_metadata_runtime(expected_abi=1)


def test_loaded_library_path_resolves_versioned_release_mapping(tmp_path: Path) -> None:
    prefix = tmp_path / "release/.venv"
    native = prefix / "lib/libiio.so.0.25"
    native.parent.mkdir(parents=True)
    native.write_bytes(b"native")
    maps = tmp_path / "maps"
    maps.write_text(
        f"7f00-7f01 r-xp 00000000 00:00 1 {native}\n",
        encoding="utf-8",
    )
    iio = ModuleType("iio")
    iio._lib = SimpleNamespace(_name="libiio.so.0")  # type: ignore[attr-defined]

    assert preflight._loaded_library_path(iio, "libiio.so.0", maps_path=maps) == str(native)
