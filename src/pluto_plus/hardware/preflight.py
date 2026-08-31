"""Read-only host libiio readiness checks with deterministic failure classes."""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import inspect
import json
import os
import sys
from collections.abc import Callable, Sequence
from ctypes import CDLL, RTLD_GLOBAL
from ctypes.util import find_library
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from types import ModuleType
from typing import Any

from pydantic import BaseModel, ConfigDict

METADATA_RUNTIME_RECEIPT = Path("share/pluto-plus-utils/metadata-runtime.json")
METADATA_RUNTIME_SOURCE_COMMITS = {
    1: "c26258bfa33098c2b215e19cf85d448e89499b1a",
    2: "6305ea1d43436ff8bdd83aa6c9e5abf7244aa5f7",
    3: "f31a200ed6a884f054e513ce0707a342ee8bd679",
    4: "98a5e6139459a01a5a42ca7cd3e98d807156b6b0",
}
_RING_METADATA_BUFFER_PARAMETERS = (
    "self",
    "device",
    "samples_count",
    "request",
    "metadata_capacity",
    "batch_frames",
    "ddr_burst_bytes",
    "ddr_ring_bytes",
    "ddr_ring_frames",
    "ddr_ring_continuous",
)
_DIRECT_ASYNC_METADATA_BUFFER_PARAMETERS = (
    *_RING_METADATA_BUFFER_PARAMETERS,
    "direct_async_frames",
)
METADATA_BUFFER_PARAMETERS = {
    1: ("self", "device", "samples_count", "metadata_capacity"),
    2: ("self", "device", "samples_count", "request", "metadata_capacity"),
    3: _DIRECT_ASYNC_METADATA_BUFFER_PARAMETERS,
    4: _RING_METADATA_BUFFER_PARAMETERS,
}


@dataclass(frozen=True, slots=True)
class MetadataRuntimeVerification:
    """Immutable attestation of one release-local metadata host runtime."""

    metadata_abi: int
    source_ref: str
    source_commit: str
    native_libiio_path: str
    native_libiio_sha256: str
    pylibiio_path: str
    pylibiio_sha256: str
    receipt_path: str


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


def verify_metadata_runtime(expected_abi: int = 1) -> MetadataRuntimeVerification:
    """Fail unless this process has the exact release-local metadata runtime.

    The installer receipt binds the selected firmware ABI to immutable libiio
    source, native and Python file hashes, constructor shape, and absolute
    release-local paths.  Ambient system libiio is never an accepted fallback.
    """

    if expected_abi not in METADATA_RUNTIME_SOURCE_COMMITS:
        raise ValueError("expected metadata ABI must be 1, 2, 3, or 4")
    prefix = Path(sys.prefix).resolve(strict=True)
    try:
        receipt_path = (prefix / METADATA_RUNTIME_RECEIPT).resolve(strict=True)
    except OSError as error:
        raise RuntimeError("release-local metadata runtime receipt is missing") from error
    if not receipt_path.is_relative_to(prefix):
        raise RuntimeError("metadata runtime receipt escaped the release prefix")
    try:
        document = json.loads(receipt_path.read_text())
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"metadata runtime receipt is unreadable: {error}") from error
    receipt = _validate_metadata_runtime_receipt(
        document,
        prefix=prefix,
        receipt_path=receipt_path,
        expected_abi=expected_abi,
    )
    native_path = Path(receipt.native_libiio_path)
    binding_path = Path(receipt.pylibiio_path)
    # Native code must never run before its receipt-bound digest has been
    # checked.  In particular, do not turn a malformed receipt into an
    # arbitrary release-local shared-library execution primitive.
    if _sha256(native_path) != receipt.native_libiio_sha256:
        raise RuntimeError("release-local native libiio hash changed after installation")
    if _sha256(binding_path) != receipt.pylibiio_sha256:
        raise RuntimeError("release-local pylibiio hash changed after installation")
    already_imported = sys.modules.get("iio")
    mapped_before = _mapped_libiio_paths()
    if mapped_before and not _is_exact_native_loaded(native_path):
        cause = (
            "pylibiio was imported"
            if already_imported is not None
            else "native libiio was loaded"
        )
        raise RuntimeError(
            f"{cause} before the release-local metadata runtime was preloaded"
        )
    try:
        CDLL(str(native_path), mode=RTLD_GLOBAL)
    except OSError as error:
        raise RuntimeError(
            f"release-local metadata libiio could not be preloaded: {error}"
        ) from error
    try:
        iio = importlib.import_module("iio")
    except (AttributeError, ImportError, OSError) as error:
        raise RuntimeError(f"release-local pylibiio could not be imported: {error}") from error
    loaded_binding_path = Path(str(getattr(iio, "__file__", ""))).resolve(strict=True)
    if loaded_binding_path != binding_path:
        raise RuntimeError(
            f"loaded pylibiio is {loaded_binding_path}, expected {receipt.pylibiio_path}"
        )
    metadata_buffer = getattr(iio, "MetadataBuffer", None)
    if metadata_buffer is None:
        raise RuntimeError("release-local pylibiio lacks MetadataBuffer")
    parameters = tuple(inspect.signature(metadata_buffer.__init__).parameters)
    if parameters != METADATA_BUFFER_PARAMETERS[expected_abi]:
        raise RuntimeError(
            f"MetadataBuffer constructor is {parameters}, expected "
            f"{METADATA_BUFFER_PARAMETERS[expected_abi]}"
        )
    if not _is_exact_native_loaded(native_path):
        raise RuntimeError(
            f"release-local metadata libiio is not the loaded libiio: {native_path}"
        )
    environment = inspect_iio_environment(require_usb=False)
    if not environment.healthy:
        raise RuntimeError(environment.actionable_message)
    # inspect_iio_environment also imports pyadi.  Re-check after that import so
    # a second ambient SONAME cannot be hidden behind the healthy API report.
    if not _is_exact_native_loaded(native_path):
        raise RuntimeError("pyadi loaded a native libiio outside the release runtime")
    return receipt


def _mapped_libiio_paths(maps_path: Path = Path("/proc/self/maps")) -> tuple[Path, ...]:
    """Return all mapped libiio objects as canonical paths.

    ``ctypes.CDLL._name`` commonly remains the unresolved string
    ``libiio.so.0`` even when an absolute release-local object satisfied that
    SONAME.  The process map is the authoritative observation on Linux.
    """

    try:
        lines = maps_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ()
    paths: set[Path] = set()
    for line in lines:
        fields = line.split()
        if len(fields) < 6:
            continue
        deleted = fields[-1] == "(deleted)"
        raw = fields[-2] if deleted else fields[-1]
        if not raw.startswith("/"):
            continue
        path = Path(raw)
        if not path.name.startswith("libiio.so"):
            continue
        if deleted:
            paths.add(Path(f"{raw}.deleted-mapping"))
        else:
            try:
                paths.add(path.resolve(strict=True))
            except OSError:
                paths.add(path)
    return tuple(sorted(paths))


def _is_exact_native_loaded(native_path: Path) -> bool:
    try:
        expected = native_path.resolve(strict=True)
    except OSError:
        return False
    mapped = _mapped_libiio_paths()
    return bool(mapped) and all(path == expected for path in mapped)


def _validate_metadata_runtime_receipt(
    document: object,
    *,
    prefix: Path,
    receipt_path: Path,
    expected_abi: int,
) -> MetadataRuntimeVerification:
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        raise RuntimeError("metadata runtime receipt has an unsupported schema")
    if document.get("metadata_abi") != expected_abi:
        raise RuntimeError("metadata runtime receipt ABI does not match the radio")
    source_commit = str(document.get("source_commit") or "")
    if source_commit != METADATA_RUNTIME_SOURCE_COMMITS[expected_abi]:
        raise RuntimeError("metadata runtime receipt has the wrong source commit")
    parameters = tuple(document.get("metadata_buffer_parameters") or ())
    if parameters != METADATA_BUFFER_PARAMETERS[expected_abi]:
        raise RuntimeError("metadata runtime receipt has the wrong constructor ABI")
    native_path = _receipt_file(document, "native_libiio_path", prefix)
    binding_path = _receipt_file(document, "pylibiio_path", prefix)
    native_hash = _receipt_hash(document, "native_libiio_sha256")
    binding_hash = _receipt_hash(document, "pylibiio_sha256")
    source_ref = str(document.get("source_ref") or "")
    if not source_ref:
        raise RuntimeError("metadata runtime receipt lacks its immutable source ref")
    return MetadataRuntimeVerification(
        metadata_abi=expected_abi,
        source_ref=source_ref,
        source_commit=source_commit,
        native_libiio_path=str(native_path),
        native_libiio_sha256=native_hash,
        pylibiio_path=str(binding_path),
        pylibiio_sha256=binding_hash,
        receipt_path=str(receipt_path),
    )


def _receipt_file(document: dict[object, object], name: str, prefix: Path) -> Path:
    raw = document.get(name)
    if not isinstance(raw, str) or not raw:
        raise RuntimeError(f"metadata runtime receipt lacks {name}")
    path = Path(raw)
    if not path.is_absolute():
        raise RuntimeError(f"metadata runtime receipt {name} is not absolute")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise RuntimeError(f"metadata runtime receipt {name} is unavailable") from error
    if not resolved.is_file() or not resolved.is_relative_to(prefix):
        raise RuntimeError(f"metadata runtime receipt {name} is not release-local")
    return resolved


def _receipt_hash(document: dict[object, object], name: str) -> str:
    value = document.get(name)
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise RuntimeError(f"metadata runtime receipt {name} is malformed")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


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

    preloaded = (
        _preload_project_native_libiio()
        if locate_library is find_library and load_module is importlib.import_module
        else None
    )
    native_candidate = locate_library("iio") or preloaded
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
        and (
            Path(fields[-1]).name == basename
            or (
                basename.startswith("libiio.so")
                and Path(fields[-1]).name.startswith("libiio.so")
            )
        )
    }
    if not paths:
        return loaded_name
    prefix = str(Path(sys.prefix).resolve()) + os.sep
    release_local = sorted(path for path in paths if path.startswith(prefix))
    return release_local[0] if release_local else sorted(paths)[0]


def _exception_text(error: BaseException) -> str:
    message = str(error).strip()
    return f"{type(error).__name__}: {message}" if message else type(error).__name__


def _preload_project_native_libiio() -> str | None:
    """Load an explicit or venv-local libiio without changing global linker state."""

    configured = os.environ.get("PLUTO_LIBIIO_LIBRARY", "").strip()
    candidates = (
        (Path(configured),)
        if configured
        else (
            Path(sys.prefix) / "lib" / "libiio.so.0",
            Path(sys.prefix) / "lib64" / "libiio.so.0",
        )
    )
    for candidate in candidates:
        try:
            resolved = candidate.expanduser().resolve(strict=True)
        except OSError:
            continue
        if not resolved.is_file():
            continue
        try:
            CDLL(str(resolved), mode=RTLD_GLOBAL)
        except OSError:
            continue
        return str(resolved)
    return None
