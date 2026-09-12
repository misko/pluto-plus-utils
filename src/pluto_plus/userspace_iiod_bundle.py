"""Checked, volatile companion files for the existing no-flash iiOD lifecycle.

This is an explicit local release input, never a network request. The daemon
must already be built with paths/RPATH matching ``remote_directory``. No loader
environment, installed library, firmware, or public V1 lifecycle receipt changes.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from pluto_plus.userspace_iiod import (
    RemoteIiodBinaryIdentity,
    RemoteIiodPaths,
    UserspaceIiodLifecycleError,
    UserspaceIiodProcessIdentity,
    UserspaceIiodTransport,
)

_ROOT = re.compile(r"/tmp/ppu-iiod-bundle-[0-9a-f]{32}\Z")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_BUNDLE_BYTES = 128 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class IiodBundleFile:
    name: str
    sha256: str
    executable: bool
    payload: bytes

    def __post_init__(self) -> None:
        if (
            not isinstance(self.name, str)
            or not _NAME.fullmatch(self.name)
            or self.name in {"owner", "iiod"}
            or type(self.executable) is not bool
            or not isinstance(self.payload, bytes)
            or not 0 < len(self.payload) <= MAX_FILE_BYTES
            or hashlib.sha256(self.payload).hexdigest() != self.sha256
        ):
            raise ValueError("invalid companion file snapshot")


@dataclass(frozen=True, slots=True)
class IiodCompanionBundle:
    remote_directory: str
    manifest_sha256: str
    daemon_sha256: str
    daemon_bytes: int
    files: tuple[IiodBundleFile, ...]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.remote_directory, str)
            or not _ROOT.fullmatch(self.remote_directory)
            or not isinstance(self.manifest_sha256, str)
            or not _DIGEST.fullmatch(self.manifest_sha256)
            or not isinstance(self.daemon_sha256, str)
            or not _DIGEST.fullmatch(self.daemon_sha256)
            or type(self.daemon_bytes) is not int
            or not 0 < self.daemon_bytes <= MAX_FILE_BYTES
            or not isinstance(self.files, tuple)
            or not 1 <= len(self.files) <= 16
            or any(not isinstance(file, IiodBundleFile) for file in self.files)
            or len({file.name for file in self.files}) != len(self.files)
            or self.daemon_bytes + sum(len(file.payload) for file in self.files) > MAX_BUNDLE_BYTES
        ):
            raise ValueError("invalid companion bundle snapshot")


def _pairs(items: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate bundle manifest key")
        result[key] = value
    return result


def _read(directory: int, name: str, maximum: int) -> bytes:
    fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid not in {0, os.geteuid()}
            or before.st_mode & 0o022
            or not 0 < before.st_size <= maximum
        ):
            raise ValueError("bundle input must be one bounded, trusted regular file")
        data = bytearray()
        while len(data) <= before.st_size:
            part = os.read(fd, min(1024 * 1024, before.st_size + 1 - len(data)))
            if not part:
                break
            data.extend(part)
        after = os.fstat(fd)
        if before != after or len(data) != before.st_size:
            # Reading may update atime; it is not part of content identity.
            fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode")
            if len(data) != before.st_size or any(
                getattr(before, key) != getattr(after, key) for key in fields
            ):
                raise ValueError("bundle input changed while reading")
        return bytes(data)
    finally:
        os.close(fd)


def load_iiod_companion_bundle(path: Path) -> IiodCompanionBundle:
    """Snapshot and hash every companion before any remote filesystem write."""
    if not path.is_absolute() or ".." in path.parts or not _NAME.fullmatch(path.name):
        raise ValueError("bundle manifest path must be absolute and normalized")
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        facts = os.fstat(directory)
        if facts.st_uid not in {0, os.geteuid()} or facts.st_mode & 0o022:
            raise ValueError("bundle directory must not be group/other writable")
        raw = _read(directory, path.name, 65536)
        manifest = json.loads(raw, object_pairs_hook=_pairs)
        if (
            not isinstance(manifest, dict)
            or manifest.keys()
            != {"schema_version", "remote_directory", "daemon_sha256", "daemon_bytes", "files"}
            or type(manifest["schema_version"]) is not int
            or manifest["schema_version"] != 1
        ):
            raise ValueError("unsupported bundle manifest schema")
        root, daemon, size = (
            manifest[key] for key in ("remote_directory", "daemon_sha256", "daemon_bytes")
        )
        if not isinstance(root, str) or not _ROOT.fullmatch(root):
            raise ValueError("bundle remote directory is not a scoped /tmp path")
        if (
            not isinstance(daemon, str)
            or not _DIGEST.fullmatch(daemon)
            or type(size) is not int
            or not 0 < size <= MAX_FILE_BYTES
        ):
            raise ValueError("invalid bundle daemon identity")
        entries = manifest["files"]
        if not isinstance(entries, list) or not 1 <= len(entries) <= 16:
            raise ValueError("bundle must declare 1..16 companion files")
        files: list[IiodBundleFile] = []
        seen: set[str] = {path.name, "iiod", "owner"}
        total = size
        for entry in entries:
            if not isinstance(entry, dict) or entry.keys() != {
                "name",
                "sha256",
                "bytes",
                "executable",
            }:
                raise ValueError("invalid bundle file schema")
            name, digest, count, executable = (
                entry[key] for key in ("name", "sha256", "bytes", "executable")
            )
            if (
                not isinstance(name, str)
                or not _NAME.fullmatch(name)
                or name in seen
                or not isinstance(digest, str)
                or not _DIGEST.fullmatch(digest)
                or type(count) is not int
                or not 0 < count <= MAX_FILE_BYTES
                or type(executable) is not bool
            ):
                raise ValueError("invalid or duplicate bundle file identity")
            total += count
            if total > MAX_BUNDLE_BYTES:
                raise ValueError("bundle exceeds total byte limit")
            seen.add(name)
            payload = _read(directory, name, count)
            if len(payload) != count or hashlib.sha256(payload).hexdigest() != digest:
                raise ValueError(f"bundle file digest/size mismatch: {name}")
            files.append(IiodBundleFile(name, digest, executable, payload))
        return IiodCompanionBundle(
            root, hashlib.sha256(raw).hexdigest(), daemon, size, tuple(files)
        )
    finally:
        os.close(directory)


class IiodCompanionTransport(UserspaceIiodTransport, Protocol):
    def stage_companions(self, bundle: IiodCompanionBundle, owner: str) -> None: ...
    def verify_companions(self, bundle: IiodCompanionBundle, owner: str) -> None: ...
    def cleanup_companions(self, bundle: IiodCompanionBundle, owner: str) -> None: ...


class BundledIiodTransport:
    """Compose companion ownership around the existing process-identity checks.

    The lifecycle calls cleanup only after it proves the daemon is absent.
    Failed verification retains the companion directory; no recursive deletion.
    Existing immutable daemon receipts still describe exactly their three files.
    """

    def __init__(self, transport: IiodCompanionTransport, manifest_path: Path) -> None:
        self._transport = transport
        self._path = manifest_path
        self._bundle: IiodCompanionBundle | None = None
        self._owner: str | None = None
        self._paths: RemoteIiodPaths | None = None

    def attest_radio_serial(self) -> str:
        return self._transport.attest_radio_serial()

    def stage(
        self, paths: RemoteIiodPaths, payload: bytes, *, expected_sha256: str
    ) -> RemoteIiodBinaryIdentity:
        if self._bundle is not None:
            raise UserspaceIiodLifecycleError("companion bundle still owned from an earlier stage")
        bundle = load_iiod_companion_bundle(self._path)
        if (
            bundle.daemon_bytes != len(payload)
            or bundle.daemon_sha256 != expected_sha256
            or hashlib.sha256(payload).hexdigest() != expected_sha256
        ):
            raise UserspaceIiodLifecycleError("companion bundle daemon digest mismatch")
        binary = self._transport.stage(paths, payload, expected_sha256=expected_sha256)
        if binary != RemoteIiodBinaryIdentity(paths.binary, len(payload), expected_sha256):
            raise UserspaceIiodLifecycleError("staged daemon identity differs from bundle")
        # Set ownership before I/O: cleanup can inspect an interrupted upload.
        self._owner = paths.binary.removeprefix("/tmp/ppu-iiod-").removesuffix(".bin")
        self._bundle = bundle
        self._paths = paths
        self._transport.stage_companions(bundle, self._owner)
        return binary

    def start(
        self, paths: RemoteIiodPaths, binary: RemoteIiodBinaryIdentity
    ) -> UserspaceIiodProcessIdentity:
        if self._bundle is None or self._owner is None or paths != self._paths:
            raise UserspaceIiodLifecycleError("companion bundle not staged")
        self._transport.verify_companions(self._bundle, self._owner)
        return self._transport.start(paths, binary)

    def inspect(self, paths: RemoteIiodPaths) -> UserspaceIiodProcessIdentity | None:
        return self._transport.inspect(paths)

    def read_log_tail(
        self, paths: RemoteIiodPaths, process: UserspaceIiodProcessIdentity
    ) -> bytes:
        if paths != self._paths or self._bundle is None:
            raise UserspaceIiodLifecycleError("diagnostic log belongs to a different bundle")
        read = getattr(self._transport, "read_log_tail", None)
        if not callable(read):
            raise UserspaceIiodLifecycleError("transport lacks bounded daemon diagnostics")
        return read(paths, process)

    def terminate(
        self, paths: RemoteIiodPaths, process: UserspaceIiodProcessIdentity, *, timeout_s: float
    ) -> bool:
        return self._transport.terminate(paths, process, timeout_s=timeout_s)

    def cleanup(self, paths: RemoteIiodPaths, binary: RemoteIiodBinaryIdentity) -> tuple[str, ...]:
        if self._bundle is not None and paths != self._paths:
            # Failed-start cleanup may leave an unresolved previous process.
            # A subsequent session must never remove that process's dependencies.
            raise UserspaceIiodLifecycleError("companion cleanup belongs to a different session")
        removed = self._transport.cleanup(paths, binary)
        if self._bundle is not None and self._owner is not None:
            self._transport.cleanup_companions(self._bundle, self._owner)
            self._bundle = None
            self._owner = None
            self._paths = None
        return removed
