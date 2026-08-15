"""Authenticated Unix-socket boundary for privileged firmware execution.

Composition is deliberately explicit.  An unprivileged daemon constructs
``UnixFirmwareHelperClient`` with the content-addressed staging root.  A small,
separately launched privileged process constructs ``UnixFirmwareHelperServer``
with:

* an exact-radio identity probe;
* an allowlist predicate for peer credentials; and
* a concrete ``PrivilegedFirmwareExecutor`` (normally ``SystemFirmwareExecutor``).

There is intentionally no generic command field, plugin loader, or shell seam.
The protocol exposes exactly two domain operations.  The helper re-attests the
radio and copies a hash-verified, size-bounded, non-symlink staging file into a
private execution directory before delegating.  Site packaging should own the
root service definition and construct the hardware-specific DFU transition and
QSPI updater described by ``SystemFirmwareExecutor``; this module does not
weaken those identity seams for convenience.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import socket
import stat
import struct
import subprocess
import tempfile
import uuid
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final, NoReturn, cast

from pluto_plus.firmware import (
    FirmwareAuthorizationError,
    FirmwareError,
    FirmwareIdentityError,
    FirmwareImageError,
    PrivilegedFirmwareExecutor,
    RadioFirmwareIdentity,
    validate_dfu,
    validate_frm,
)

PROTOCOL_VERSION: Final = 1
MAX_FRAME_BYTES: Final = 16 * 1024
DEFAULT_MAX_IMAGE_BYTES: Final = 128 * 1024 * 1024
_HEADER = struct.Struct("!I")
_PEER_CREDENTIALS = struct.Struct("3i")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_REQUEST_ID = re.compile(r"[0-9a-f]{32}\Z")
_ACTIONS: Final = frozenset({"load_volatile_dfu", "flash_persistent_qspi"})


class FirmwareHelperError(FirmwareError):
    """The privileged-helper boundary rejected or could not process a request."""


class FirmwareHelperProtocolError(FirmwareHelperError):
    """A peer sent a malformed or unsupported protocol message."""


class FirmwareHelperUnavailableError(FirmwareHelperError):
    """The helper disconnected, timed out, or could not be reached."""


@dataclass(frozen=True, slots=True)
class PeerCredentials:
    pid: int
    uid: int
    gid: int


@dataclass(frozen=True, slots=True)
class _ImageClaim:
    relative_path: PurePosixPath
    sha256: str
    size: int


def _reject_constant(value: str) -> NoReturn:
    raise ValueError(f"non-finite JSON value {value!r} is forbidden")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _encode_frame(payload: Mapping[str, object]) -> bytes:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_FRAME_BYTES:
        raise FirmwareHelperProtocolError("JSON frame exceeds the protocol limit")
    return _HEADER.pack(len(body)) + body


def _read_exact(connection: socket.socket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        try:
            chunk = connection.recv(length - len(chunks))
        except TimeoutError as caught:
            raise FirmwareHelperUnavailableError("helper socket timed out") from caught
        except OSError as caught:
            raise FirmwareHelperUnavailableError(f"helper socket read failed: {caught}") from caught
        if not chunk:
            raise FirmwareHelperUnavailableError("helper disconnected before completing a frame")
        chunks.extend(chunk)
    return bytes(chunks)


def _decode_frame(connection: socket.socket) -> dict[str, object]:
    header = _read_exact(connection, _HEADER.size)
    (length,) = _HEADER.unpack(header)
    if length == 0 or length > MAX_FRAME_BYTES:
        raise FirmwareHelperProtocolError("invalid or oversized JSON frame")
    raw = _read_exact(connection, length)
    try:
        value = json.loads(
            raw,
            parse_constant=_reject_constant,
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as caught:
        raise FirmwareHelperProtocolError(f"malformed JSON frame: {caught}") from caught
    if not isinstance(value, dict):
        raise FirmwareHelperProtocolError("JSON frame must contain an object")
    if not all(isinstance(key, str) for key in value):  # pragma: no cover - JSON guarantees it
        raise FirmwareHelperProtocolError("JSON object keys must be strings")
    return cast(dict[str, object], value)


def _expect_exact_keys(value: Mapping[str, object], expected: set[str], context: str) -> None:
    actual = set(value)
    if actual != expected:
        raise FirmwareHelperProtocolError(
            f"{context} fields must be exactly {sorted(expected)}; got {sorted(actual)}"
        )


def _expect_string(value: object, field: str, *, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise FirmwareHelperProtocolError(f"{field} must be a non-empty bounded string")
    return value


def _parse_radio(value: object) -> RadioFirmwareIdentity:
    if not isinstance(value, dict):
        raise FirmwareHelperProtocolError("radio must be an object")
    radio = cast(dict[str, object], value)
    _expect_exact_keys(radio, {"serial", "usb_sysfs_path", "observed_firmware"}, "radio")
    serial = _expect_string(radio["serial"], "radio.serial", maximum=256)
    sysfs = _expect_string(radio["usb_sysfs_path"], "radio.usb_sysfs_path", maximum=1024)
    firmware = _expect_string(
        radio["observed_firmware"], "radio.observed_firmware", maximum=256
    )
    try:
        identity = RadioFirmwareIdentity(serial, sysfs, firmware)
    except ValueError as caught:
        raise FirmwareHelperProtocolError(f"invalid radio identity: {caught}") from caught
    sysfs_path = PurePosixPath(sysfs)
    if (
        sysfs_path.parent != PurePosixPath("/sys/bus/usb/devices")
        or sysfs_path.name in {"", ".", ".."}
    ):
        raise FirmwareHelperProtocolError("radio sysfs path must name one direct USB device")
    return identity


def _parse_image(value: object, maximum_size: int) -> _ImageClaim:
    if not isinstance(value, dict):
        raise FirmwareHelperProtocolError("image must be an object")
    image = cast(dict[str, object], value)
    _expect_exact_keys(image, {"path", "sha256", "size"}, "image")
    path_text = _expect_string(image["path"], "image.path", maximum=2048)
    relative = PurePosixPath(path_text)
    if relative.is_absolute() or not relative.parts or any(
        part in {"", ".", ".."} for part in relative.parts
    ):
        raise FirmwareHelperProtocolError("image.path must be a confined relative path")
    digest = _expect_string(image["sha256"], "image.sha256", maximum=64)
    if _SHA256.fullmatch(digest) is None:
        raise FirmwareHelperProtocolError("image.sha256 must be lowercase hexadecimal")
    size = image["size"]
    if isinstance(size, bool) or not isinstance(size, int) or size <= 0 or size > maximum_size:
        raise FirmwareHelperProtocolError("image.size is outside the configured bounds")
    return _ImageClaim(relative, digest, size)


def _serialize_radio(radio: RadioFirmwareIdentity) -> dict[str, object]:
    return {
        "serial": radio.serial,
        "usb_sysfs_path": radio.usb_sysfs_path,
        "observed_firmware": radio.observed_firmware,
    }


def _hash_file(path: Path, *, maximum_size: int) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise FirmwareImageError("staged image is not a regular file")
        if metadata.st_size <= 0 or metadata.st_size > maximum_size:
            raise FirmwareImageError("staged image size is outside configured bounds")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > maximum_size:
                raise FirmwareImageError("staged image exceeds configured bounds")
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest(), size


class UnixFirmwareHelperClient:
    """Unprivileged ``PrivilegedFirmwareExecutor`` implemented over AF_UNIX.

    ``effective_uid`` reports the actual client UID; it never pretends the
    daemon is root.  ``authorize_execution`` tells ``FirmwareManager`` that
    authorization is enforced by the process boundary.  Every operation is
    still independently authorized by the helper using ``SO_PEERCRED``.
    """

    def __init__(
        self,
        *,
        socket_path: Path,
        staging_root: Path,
        timeout_s: float = 150,
        maximum_image_bytes: int = DEFAULT_MAX_IMAGE_BYTES,
        uid_provider: Callable[[], int] = os.geteuid,
    ) -> None:
        if timeout_s <= 0 or maximum_image_bytes <= 0:
            raise ValueError("timeout and maximum image size must be positive")
        self._socket_path = socket_path
        self._staging_root = staging_root
        self._timeout = timeout_s
        self._maximum_image_bytes = maximum_image_bytes
        self._uid = uid_provider

    def effective_uid(self) -> int:
        return self._uid()

    def authorize_execution(self) -> None:
        # The server authorizes every mutating request.  This method exists so
        # FirmwareManager does not mistake the process boundary for local root.
        return None

    def load_volatile_dfu(self, radio: RadioFirmwareIdentity, image: Path) -> None:
        self._execute("load_volatile_dfu", radio, image)

    def flash_persistent_qspi(
        self, radio: RadioFirmwareIdentity, image: Path, *, target_name: str
    ) -> None:
        if target_name != "pluto.frm":
            raise FirmwareImageError("persistent updater target must be exactly pluto.frm")
        self._execute("flash_persistent_qspi", radio, image, target_name=target_name)

    def _execute(
        self,
        action: str,
        radio: RadioFirmwareIdentity,
        image: Path,
        *,
        target_name: str | None = None,
    ) -> None:
        claim = self._claim(image)
        request: dict[str, object] = {
            "version": PROTOCOL_VERSION,
            "request_id": uuid.uuid4().hex,
            "action": action,
            "radio": _serialize_radio(radio),
            "image": {
                "path": claim.relative_path.as_posix(),
                "sha256": claim.sha256,
                "size": claim.size,
            },
        }
        if target_name is not None:
            request["target_name"] = target_name
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self._timeout)
                connection.connect(str(self._socket_path))
                # Peer credentials are authorized before the helper reads a
                # request. An unauthorized helper may therefore finish its
                # structured response and close while this send is still in
                # progress; consume the already-buffered response below.
                with suppress(BrokenPipeError):
                    connection.sendall(_encode_frame(request))
                response = _decode_frame(connection)
        except FirmwareHelperError:
            raise
        except TimeoutError as caught:
            raise FirmwareHelperUnavailableError("firmware helper timed out") from caught
        except OSError as caught:
            raise FirmwareHelperUnavailableError(
                f"firmware helper connection failed: {caught}"
            ) from caught
        self._handle_response(response, cast(str, request["request_id"]))

    def _claim(self, image: Path) -> _ImageClaim:
        if not image.is_absolute():
            raise FirmwareImageError("staged image path must be absolute")
        try:
            relative = image.relative_to(self._staging_root)
        except ValueError as caught:
            raise FirmwareImageError("staged image is outside the configured root") from caught
        if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
            raise FirmwareImageError("staged image path is invalid")
        digest, size = _hash_file(image, maximum_size=self._maximum_image_bytes)
        return _ImageClaim(PurePosixPath(*relative.parts), digest, size)

    @staticmethod
    def _handle_response(response: dict[str, object], request_id: str) -> None:
        _expect_exact_keys(response, {"version", "request_id", "ok", "error"}, "response")
        if response["version"] != PROTOCOL_VERSION:
            raise FirmwareHelperProtocolError("helper response used an unsupported version")
        ok = response["ok"]
        error = response["error"]
        if not isinstance(ok, bool):
            raise FirmwareHelperProtocolError("response.ok must be boolean")
        if ok:
            if response["request_id"] != request_id:
                raise FirmwareHelperProtocolError("helper response did not match the request")
            if error is not None:
                raise FirmwareHelperProtocolError("successful response contains an error")
            return
        if not isinstance(error, dict):
            raise FirmwareHelperProtocolError("failed response must contain an error object")
        details = cast(dict[str, object], error)
        _expect_exact_keys(details, {"code", "message"}, "response.error")
        code = _expect_string(details["code"], "response.error.code", maximum=64)
        message = _expect_string(details["message"], "response.error.message", maximum=1024)
        # The helper authenticates SO_PEERCRED before reading a request.  An
        # unauthorized peer therefore receives the all-zero sentinel rather
        # than an attacker-controlled request ID.
        response_id = response["request_id"]
        if response_id != request_id and not (
            response_id == "0" * 32 and code == "unauthorized"
        ):
            raise FirmwareHelperProtocolError("helper response did not match the request")
        if code == "unauthorized":
            raise FirmwareAuthorizationError(message)
        if code == "identity_mismatch":
            raise FirmwareIdentityError(message)
        if code == "invalid_image":
            raise FirmwareImageError(message)
        if code == "timeout":
            raise FirmwareHelperUnavailableError(message)
        if code in {"invalid_request", "unsupported_version"}:
            raise FirmwareHelperProtocolError(message)
        raise FirmwareHelperError(message)


class UnixFirmwareHelperServer:
    """One-request-per-connection privileged helper server."""

    def __init__(
        self,
        *,
        socket_path: Path,
        staging_root: Path,
        execution_root: Path,
        executor: PrivilegedFirmwareExecutor,
        identity_probe: Callable[[str], RadioFirmwareIdentity],
        authorize_peer: Callable[[PeerCredentials], bool],
        peer_credentials: Callable[[socket.socket], PeerCredentials] | None = None,
        uid_provider: Callable[[], int] = os.geteuid,
        request_timeout_s: float = 160,
        maximum_image_bytes: int = DEFAULT_MAX_IMAGE_BYTES,
    ) -> None:
        if request_timeout_s <= 0 or maximum_image_bytes <= 0:
            raise ValueError("timeout and maximum image size must be positive")
        self._socket_path = socket_path
        self._staging_root = staging_root
        self._execution_root = execution_root
        self._executor = executor
        self._identity_probe = identity_probe
        self._authorize_peer = authorize_peer
        self._peer_credentials = peer_credentials or self.linux_peer_credentials
        self._uid = uid_provider
        self._request_timeout = request_timeout_s
        self._maximum_image_bytes = maximum_image_bytes

    @staticmethod
    def linux_peer_credentials(connection: socket.socket) -> PeerCredentials:
        raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _PEER_CREDENTIALS.size)
        return PeerCredentials(*_PEER_CREDENTIALS.unpack(raw))

    def serve_forever(self, stop: Callable[[], bool]) -> None:
        """Bind the configured socket and serve until ``stop`` returns true."""

        self._validate_directory(self._socket_path.parent, "socket directory")
        self._validate_directory(self._staging_root, "staging root")
        self._validate_directory(self._execution_root, "execution root")
        if self._socket_path.exists() or self._socket_path.is_symlink():
            raise FirmwareHelperError("helper socket path already exists")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        bound_inode: tuple[int, int] | None = None
        try:
            listener.bind(str(self._socket_path))
            os.chmod(self._socket_path, 0o660)
            socket_stat = self._socket_path.lstat()
            bound_inode = (socket_stat.st_dev, socket_stat.st_ino)
            listener.listen(16)
            listener.settimeout(0.2)
            while not stop():
                try:
                    connection, _ = listener.accept()
                except TimeoutError:
                    continue
                with connection:
                    self.handle_connection(connection)
        finally:
            listener.close()
            if bound_inode is not None:
                try:
                    current = self._socket_path.lstat()
                except FileNotFoundError:
                    pass
                else:
                    if stat.S_ISSOCK(current.st_mode) and (
                        current.st_dev,
                        current.st_ino,
                    ) == bound_inode:
                        self._socket_path.unlink()

    def handle_connection(self, connection: socket.socket) -> None:
        """Handle one framed request; public for socket-activation adapters/tests."""

        connection.settimeout(self._request_timeout)
        request_id = "0" * 32
        try:
            peer = self._peer_credentials(connection)
            if not self._authorize_peer(peer):
                raise FirmwareAuthorizationError("peer UID is not authorized")
            request = _decode_frame(connection)
            candidate_id = request.get("request_id")
            if isinstance(candidate_id, str) and _REQUEST_ID.fullmatch(candidate_id):
                request_id = candidate_id
            self._dispatch(request)
            response = self._response(request_id, ok=True)
        except Exception as caught:
            response = self._response(request_id, ok=False, error=self._map_error(caught))
        try:
            connection.sendall(_encode_frame(response))
        except (OSError, FirmwareHelperError):
            # The authorized operation may already have completed; never retry a
            # mutation merely because the caller disconnected before its reply.
            return

    def _dispatch(self, request: dict[str, object]) -> None:
        common = {"version", "request_id", "action", "radio", "image"}
        action = request.get("action")
        expected = common | ({"target_name"} if action == "flash_persistent_qspi" else set())
        _expect_exact_keys(request, expected, "request")
        if request["version"] != PROTOCOL_VERSION:
            raise FirmwareHelperProtocolError("unsupported protocol version")
        request_id = _expect_string(request["request_id"], "request_id", maximum=32)
        if _REQUEST_ID.fullmatch(request_id) is None:
            raise FirmwareHelperProtocolError("request_id must be 32 lowercase hex characters")
        action = _expect_string(request["action"], "action", maximum=64)
        if action not in _ACTIONS:
            raise FirmwareHelperProtocolError("action is not in the firmware helper allowlist")
        if self._uid() != 0 or self._executor.effective_uid() != 0:
            raise FirmwareAuthorizationError("privileged helper is not running as root")
        radio = _parse_radio(request["radio"])
        image = _parse_image(request["image"], self._maximum_image_bytes)
        current = self._identity_probe(radio.serial)
        if current != radio:
            raise FirmwareIdentityError("live radio identity does not match the request")
        target_name: str | None = None
        if action == "flash_persistent_qspi":
            target_name = _expect_string(request["target_name"], "target_name", maximum=32)
            if target_name != "pluto.frm":
                raise FirmwareImageError("persistent updater target must be exactly pluto.frm")

        private_image, private_directory = self._copy_verified(image, action)
        try:
            # Re-attest after all non-mutating image work, immediately before
            # entering the injected mutating executor.
            if self._identity_probe(radio.serial) != radio:
                raise FirmwareIdentityError("live radio identity changed before execution")
            if action == "load_volatile_dfu":
                self._executor.load_volatile_dfu(radio, private_image)
            else:
                self._executor.flash_persistent_qspi(
                    radio, private_image, target_name=cast(str, target_name)
                )
        finally:
            private_image.unlink(missing_ok=True)
            with suppress(OSError):
                private_directory.rmdir()

    def _copy_verified(self, claim: _ImageClaim, action: str) -> tuple[Path, Path]:
        source_fd = self._open_confined(claim.relative_path)
        private_directory = Path(tempfile.mkdtemp(prefix="request-", dir=self._execution_root))
        os.chmod(private_directory, 0o700)
        destination = private_directory / (
            "firmware.dfu" if action == "load_volatile_dfu" else "pluto.frm"
        )
        destination_fd: int | None = None
        digest = hashlib.sha256()
        copied = 0
        try:
            metadata = os.fstat(source_fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != claim.size:
                raise FirmwareImageError("staged image type or size changed")
            destination_fd = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o400,
            )
            while True:
                chunk = os.read(source_fd, 1024 * 1024)
                if not chunk:
                    break
                copied += len(chunk)
                if copied > claim.size or copied > self._maximum_image_bytes:
                    raise FirmwareImageError("staged image exceeded its claimed size")
                digest.update(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(destination_fd, view)
                    view = view[written:]
            os.fsync(destination_fd)
        except Exception:
            destination.unlink(missing_ok=True)
            with suppress(OSError):
                private_directory.rmdir()
            raise
        finally:
            os.close(source_fd)
            if destination_fd is not None:
                os.close(destination_fd)
        if copied != claim.size or digest.hexdigest() != claim.sha256:
            destination.unlink(missing_ok=True)
            private_directory.rmdir()
            raise FirmwareImageError("staged image digest or size changed")
        try:
            content = destination.read_bytes()
            if action == "load_volatile_dfu":
                validate_dfu(content)
            else:
                validate_frm(content)
        except Exception:
            destination.unlink(missing_ok=True)
            private_directory.rmdir()
            raise
        return destination, private_directory

    def _open_confined(self, relative: PurePosixPath) -> int:
        """Open beneath staging root without following any path-component symlink."""

        root_fd = os.open(self._staging_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        directory_fd = root_fd
        try:
            for part in relative.parts[:-1]:
                next_fd = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=directory_fd,
                )
                if directory_fd != root_fd:
                    os.close(directory_fd)
                directory_fd = next_fd
            return os.open(
                relative.parts[-1],
                os.O_RDONLY | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
        except OSError as caught:
            if caught.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise FirmwareImageError("staged image path contains a symlink") from caught
            raise FirmwareImageError(f"cannot open confined staged image: {caught}") from caught
        finally:
            if directory_fd != root_fd:
                os.close(directory_fd)
            os.close(root_fd)

    @staticmethod
    def _validate_directory(path: Path, label: str) -> None:
        try:
            metadata = path.lstat()
        except OSError as caught:
            raise FirmwareHelperError(f"{label} is unavailable: {caught}") from caught
        if not stat.S_ISDIR(metadata.st_mode) or path.is_symlink():
            raise FirmwareHelperError(f"{label} must be a real directory")

    @staticmethod
    def _response(
        request_id: str,
        *,
        ok: bool,
        error: tuple[str, str] | None = None,
    ) -> dict[str, object]:
        return {
            "version": PROTOCOL_VERSION,
            "request_id": request_id,
            "ok": ok,
            "error": None if error is None else {"code": error[0], "message": error[1]},
        }

    @staticmethod
    def _map_error(error: BaseException) -> tuple[str, str]:
        if isinstance(error, FirmwareAuthorizationError):
            return "unauthorized", str(error)
        if isinstance(error, FirmwareIdentityError):
            return "identity_mismatch", str(error)
        if isinstance(error, FirmwareImageError):
            return "invalid_image", str(error)
        if isinstance(error, (TimeoutError, subprocess.TimeoutExpired)):
            return "timeout", "privileged firmware operation timed out"
        if isinstance(error, FirmwareHelperProtocolError):
            code = (
                "unsupported_version"
                if str(error) == "unsupported protocol version"
                else "invalid_request"
            )
            return code, str(error)
        if isinstance(error, FirmwareError):
            return "execution_failed", str(error)
        return "internal_error", "privileged firmware operation failed"
