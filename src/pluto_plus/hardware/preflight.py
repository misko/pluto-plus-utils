"""Read-only host libiio readiness checks with deterministic failure classes."""

from __future__ import annotations

import importlib
import importlib.util
import sys
from collections.abc import Callable, Sequence
from ctypes.util import find_library
from enum import StrEnum
from pathlib import Path
from types import ModuleType
from typing import Any

from pydantic import BaseModel, ConfigDict


class IioEnvironmentStatus(StrEnum):
    """Stable result codes suitable for CLI and JSON consumers."""

    READY = "ready"
    HARDWARE_EXTRA_MISSING = "hardware_extra_missing"
    NATIVE_LIBIIO_MISSING = "native_libiio_missing"
    LIBIIO_ABI_INCOMPATIBLE = "libiio_abi_incompatible"
    USB_BACKEND_MISSING = "usb_backend_missing"


class IioEnvironmentReport(BaseModel):
    """Passive description of this Python process's libiio environment."""

    model_config = ConfigDict(frozen=True)

    healthy: bool
    status: IioEnvironmentStatus
    message: str
    remediation: str | None = None
    python_executable: str
    pyadi_path: str | None = None
    pylibiio_path: str | None = None
    native_libiio_candidate: str | None = None
    native_libiio_path: str | None = None
    libiio_version: str | None = None
    backends: tuple[str, ...] = ()
    underlying_error: str | None = None

    @property
    def actionable_message(self) -> str:
        parts = [self.message]
        if self.underlying_error:
            parts.append(f"Underlying error: {self.underlying_error}")
        if self.remediation:
            parts.append(f"Remediation: {self.remediation}")
        return " ".join(parts)


def inspect_iio_environment(
    *,
    require_usb: bool = True,
    locate_module: Callable[[str], Any | None] = importlib.util.find_spec,
    locate_library: Callable[[str], str | None] = find_library,
    load_module: Callable[[str], ModuleType] = importlib.import_module,
    maps_path: Path = Path("/proc/self/maps"),
) -> IioEnvironmentReport:
    """Inspect Python/native libiio without discovering or opening any hardware."""

    pyadi_path = _module_path("adi", locate_module)
    pylibiio_path = _module_path("iio", locate_module)
    if pyadi_path is None or pylibiio_path is None:
        missing = []
        if pyadi_path is None:
            missing.append("pyadi-iio")
        if pylibiio_path is None:
            missing.append("pylibiio")
        return _report(
            IioEnvironmentStatus.HARDWARE_EXTRA_MISSING,
            f"Python hardware dependency missing: {', '.join(missing)}.",
            remediation="Install the project hardware extra with `uv sync --extra hardware`.",
            pyadi_path=pyadi_path,
            pylibiio_path=pylibiio_path,
        )

    native_candidate = locate_library("iio")
    if not native_candidate:
        return _report(
            IioEnvironmentStatus.NATIVE_LIBIIO_MISSING,
            "The pylibiio binding is installed, but the native libiio loader cannot find libiio.",
            remediation=(
                "Install the supported native libiio build with its USB backend, run the "
                "platform linker-cache update if required, then rerun `pluto environment`."
            ),
            pyadi_path=pyadi_path,
            pylibiio_path=pylibiio_path,
        )

    try:
        iio = load_module("iio")
    except (AttributeError, ImportError, OSError) as error:
        return _report(
            IioEnvironmentStatus.LIBIIO_ABI_INCOMPATIBLE,
            "The native libiio library was found but is incompatible with pylibiio.",
            remediation=(
                "Install a matched native libiio and pylibiio pair; do not combine the PyPI "
                "binding with an older ambient system library."
            ),
            pyadi_path=pyadi_path,
            pylibiio_path=pylibiio_path,
            native_libiio_candidate=native_candidate,
            underlying_error=_exception_text(error),
        )

    version = _format_version(getattr(iio, "version", None))
    backends = _normalize_backends(getattr(iio, "backends", ()))
    native_path = _loaded_library_path(iio, native_candidate, maps_path=maps_path)
    try:
        load_module("adi")
    except (AttributeError, ImportError, OSError) as error:
        return _report(
            IioEnvironmentStatus.LIBIIO_ABI_INCOMPATIBLE,
            "libiio loaded, but pyadi-iio could not import against this binding.",
            remediation="Install a matched pyadi-iio, pylibiio, and native libiio set.",
            pyadi_path=pyadi_path,
            pylibiio_path=pylibiio_path,
            native_libiio_candidate=native_candidate,
            native_libiio_path=native_path,
            libiio_version=version,
            backends=backends,
            underlying_error=_exception_text(error),
        )

    if require_usb and "usb" not in {backend.casefold() for backend in backends}:
        return _report(
            IioEnvironmentStatus.USB_BACKEND_MISSING,
            "libiio loaded, but it does not advertise the USB backend required for Pluto USB.",
            remediation="Rebuild or install native libiio with WITH_USB_BACKEND=ON and libusb.",
            pyadi_path=pyadi_path,
            pylibiio_path=pylibiio_path,
            native_libiio_candidate=native_candidate,
            native_libiio_path=native_path,
            libiio_version=version,
            backends=backends,
        )

    return _report(
        IioEnvironmentStatus.READY,
        (
            "The pyadi-iio, pylibiio, native libiio, and USB backend preflight passed."
            if require_usb
            else "The pyadi-iio, pylibiio, and native libiio preflight passed."
        ),
        healthy=True,
        pyadi_path=pyadi_path,
        pylibiio_path=pylibiio_path,
        native_libiio_candidate=native_candidate,
        native_libiio_path=native_path,
        libiio_version=version,
        backends=backends,
    )


def _report(
    status: IioEnvironmentStatus,
    message: str,
    *,
    healthy: bool = False,
    remediation: str | None = None,
    pyadi_path: str | None = None,
    pylibiio_path: str | None = None,
    native_libiio_candidate: str | None = None,
    native_libiio_path: str | None = None,
    libiio_version: str | None = None,
    backends: tuple[str, ...] = (),
    underlying_error: str | None = None,
) -> IioEnvironmentReport:
    return IioEnvironmentReport(
        healthy=healthy,
        status=status,
        message=message,
        remediation=remediation,
        python_executable=sys.executable,
        pyadi_path=pyadi_path,
        pylibiio_path=pylibiio_path,
        native_libiio_candidate=native_libiio_candidate,
        native_libiio_path=native_libiio_path,
        libiio_version=libiio_version,
        backends=backends,
        underlying_error=underlying_error,
    )


def _module_path(name: str, locate_module: Callable[[str], Any | None]) -> str | None:
    try:
        specification = locate_module(name)
    except (ImportError, ValueError):
        return None
    if specification is None:
        return None
    origin = getattr(specification, "origin", None)
    return str(origin) if origin else "<installed>"


def _format_version(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        parts = [str(part) for part in value if str(part)]
        if len(parts) >= 2:
            base = ".".join(parts[:2])
            return base if len(parts) == 2 else f"{base} ({'.'.join(parts[2:])})"
    return str(value)


def _normalize_backends(value: object) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return ()
    return tuple(str(backend) for backend in value)


def _loaded_library_path(iio: ModuleType, candidate: str, *, maps_path: Path) -> str:
    library = getattr(iio, "_lib", None)
    loaded_name = str(getattr(library, "_name", "") or candidate)
    direct = Path(loaded_name)
    if direct.is_absolute():
        return str(direct.resolve())
    basename = direct.name
    try:
        mappings = maps_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return loaded_name
    paths = {
        fields[-1]
        for line in mappings
        if len(fields := line.split()) >= 6
        and fields[-1].startswith("/")
        and Path(fields[-1]).name == basename
    }
    return sorted(paths)[0] if paths else loaded_name


def _exception_text(error: BaseException) -> str:
    message = str(error).strip()
    return f"{type(error).__name__}: {message}" if message else type(error).__name__
