from __future__ import annotations

from pathlib import Path
from types import ModuleType, SimpleNamespace

from pluto_plus.hardware.preflight import IioEnvironmentStatus, inspect_iio_environment


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
    assert report.underlying_error == (
        "AttributeError: undefined symbol: iio_get_backends_count"
    )


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
