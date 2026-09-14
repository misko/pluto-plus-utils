"""Bounded U-Boot command parsing and exclusive Linux UART access.

Electrical setup, identity probes and RAM/return recipes require a shipped board
qualification. This module does not guess them from a U-Boot banner.
"""

from __future__ import annotations

import fcntl
import os
import re
import select
import stat
import termios
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Protocol

from .contracts import RecoveryError


class Wire(Protocol):
    def write(self, data: bytes) -> None: ...
    def read(self, timeout: float) -> bytes: ...


def serial_owners(target: Path) -> list[int]:
    """Find existing readers that do not participate in our advisory lock."""
    expected = target.stat().st_rdev
    owners: list[int] = []
    for process in Path("/proc").iterdir():
        if not process.name.isdecimal() or int(process.name) == os.getpid():
            continue
        try:
            descriptors = tuple((process / "fd").iterdir())
        except OSError:
            continue
        for descriptor in descriptors:
            try:
                info = descriptor.stat()
            except OSError:
                continue
            if stat.S_ISCHR(info.st_mode) and info.st_rdev == expected:
                owners.append(int(process.name))
                break
    return owners


class SerialWire:
    """Use an explicitly selected stable adapter path, without toggling DTR/RTS."""

    def __init__(self, adapter: Path) -> None:
        self.adapter = adapter.absolute()
        self.fd: int | None = None

    @contextmanager
    def lease(self) -> Iterator[None]:
        if self.adapter.parent not in (Path("/dev/serial/by-id"), Path("/dev/serial/by-path")):
            raise RecoveryError("target_unbound", "select a stable serial by-id/by-path endpoint")
        target = self.adapter.resolve(strict=True)
        before = target.stat()
        if not stat.S_ISCHR(before.st_mode):
            raise RecoveryError("target_unbound", "adapter is not a character device")
        owners = serial_owners(target)
        if owners:
            raise RecoveryError(
                "transport_busy",
                "close the UART reader owned by PID(s): " + ", ".join(str(pid) for pid in owners),
            )
        fd = os.open(target, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK | os.O_NOFOLLOW)
        saved = None
        try:
            opened = os.fstat(fd)
            if (before.st_dev, before.st_ino, before.st_rdev) != (
                opened.st_dev,
                opened.st_ino,
                opened.st_rdev,
            ) or self.adapter.resolve(strict=True) != target:
                raise RecoveryError("target_unbound", "serial endpoint changed while opening")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.ioctl(fd, termios.TIOCEXCL)
            saved = termios.tcgetattr(fd)
            attrs = termios.tcgetattr(fd)
            attrs[0] = attrs[1] = attrs[3] = 0
            attrs[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
            attrs[4] = attrs[5] = termios.B115200
            attrs[6][termios.VMIN] = attrs[6][termios.VTIME] = 0
            termios.tcsetattr(fd, termios.TCSANOW, attrs)
            self.fd = fd
            yield
        finally:
            self.fd = None
            if saved is not None:
                termios.tcsetattr(fd, termios.TCSANOW, saved)
                fcntl.ioctl(fd, termios.TIOCNXCL)
            os.close(fd)

    def write(self, data: bytes) -> None:
        if self.fd is None:
            raise RecoveryError("transport_closed", "serial lease is required")
        deadline = time.monotonic() + 10
        while data:
            if time.monotonic() >= deadline:
                raise RecoveryError("command_timeout", "serial write did not complete")
            _, ready, _ = select.select([], [self.fd], [], 0.1)
            if ready:
                count = os.write(self.fd, data)
                if count == 0:
                    raise RecoveryError("transport_disconnected", "serial write returned zero")
                data = data[count:]

    def read(self, timeout: float) -> bytes:
        if self.fd is None:
            raise RecoveryError("transport_closed", "serial lease is required")
        ready, _, _ = select.select([self.fd], [], [], timeout)
        if not ready:
            return b""
        data = os.read(self.fd, 65536)
        if not data:
            raise RecoveryError("transport_disconnected", "serial connection closed")
        return data


class Console:
    def __init__(
        self,
        wire: Wire,
        log: Callable[[bytes], object],
        *,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.wire, self.log, self.monotonic = wire, log, monotonic
        self.poisoned = False

    def command(self, command: str, *, timeout: float = 120, maximum: int = 2**20) -> bytes:
        if self.poisoned:
            raise RecoveryError("reconnect_required", "previous serial command was uncertain")
        if any(c in command for c in "\r\n") or len(command) > 1024:
            raise RecoveryError(
                "command_invalid", "only bounded reviewed command templates are allowed"
            )
        nonce = uuid.uuid4().hex
        begin, ok, fail = (f"PPU_{kind}_{nonce}".encode() for kind in ("BEGIN", "OK", "FAIL"))
        script = (
            b"echo "
            + begin
            + b"; if "
            + command.encode("ascii")
            + b"; then echo "
            + ok
            + b"; else echo "
            + fail
            + b"; fi\n"
        )
        raw = bytearray()
        try:
            self.wire.write(script)
            deadline = self.monotonic() + timeout
            while self.monotonic() < deadline:
                raw.extend(self.wire.read(min(0.1, max(0, deadline - self.monotonic()))))
                if len(raw) > maximum:
                    raise RecoveryError("command_invalid", "serial response exceeds bound")
                lines = bytes(raw).replace(b"\r", b"\n").split(b"\n")
                # Ignore partial final line, echoed script and stale prompts.
                complete = lines[:-1]
                if begin not in complete:
                    continue
                body = complete[complete.index(begin) + 1 :]
                if re.search(
                    rb"undefined instruction|data abort|Resetting CPU|^DRAM:  ",
                    b"\n".join(body),
                    re.MULTILINE,
                ):
                    raise RecoveryError(
                        "target_reset", "CPU fault or unexpected reboot during command"
                    )
                if fail in body:
                    raise RecoveryError("command_failed", "U-Boot returned a failure marker")
                if ok in body:
                    payload = b"\n".join(body[: body.index(ok)])
                    if re.search(rb"(?i)(?:\bERROR\b|\bfailed\b|Unknown command)", payload):
                        raise RecoveryError("command_failed", "U-Boot reported an explicit error")
                    self.log(bytes(raw))
                    return payload
            raise RecoveryError("command_timeout", "completion was not observed")
        except BaseException:
            self.poisoned = True
            self.log(bytes(raw) or b"no serial response")
            raise

    def sf(self, operation: str, start: int, size: int, *, ram: int = 0) -> None:
        if (
            operation not in {"read", "write", "erase"}
            or not (
                type(start) is int
                and type(size) is int
                and 0 <= start < start + size <= 128 * 1024**2
            )
            or type(ram) is not int
            or not 0 <= ram <= 0xFFFFFFFF
        ):
            raise RecoveryError("command_invalid", "invalid qualified flash command")
        args = f"{start:x} {size:x}" if operation == "erase" else f"{ram:x} {start:x} {size:x}"
        output = self.command(f"sf {operation} {args}")
        verb = {"read": "Read", "write": "Written", "erase": "Erased"}[operation]
        pattern = rb"SF: (\d+) bytes @ (0x[0-9a-fA-F]+|0) " + verb.encode() + rb": OK"
        matches = re.findall(pattern, output)
        if len(matches) != 1 or (int(matches[0][0]), int(matches[0][1], 16)) != (size, start):
            self.poisoned = True
            raise RecoveryError("command_unverified", "SF count, offset or completion differs")

    def memory(self, address: int, size: int) -> bytes:
        if not 0 <= address < address + size <= 2**32 or not 0 < size <= 65536:
            raise RecoveryError("command_invalid", "invalid memory read")
        output = self.command(f"md.b {address:x} {size:x}", maximum=size * 6 + 4096)
        data = bytearray()
        for line in output.splitlines():
            match = re.fullmatch(rb"([0-9a-fA-F]{8}): ((?:[0-9a-fA-F]{2} ){1,16}).*", line)
            if match is None:
                continue
            if int(match[1], 16) != address + len(data):
                raise RecoveryError("command_unverified", "memory address discontinuity")
            data.extend(bytes.fromhex(match[2].decode()))
        if len(data) != size:
            raise RecoveryError("command_unverified", "memory read byte count differs")
        return bytes(data)
