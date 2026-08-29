"""Process-wide advisory locks shared by local USB radio workflows."""

from __future__ import annotations

import fcntl
import hashlib
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO


class RadioLockError(RuntimeError):
    """A shared local-radio lock could not be acquired safely."""


def shared_radio_lock_root() -> Path:
    """Return the one user-scoped lock root used by every local USB workflow."""

    return Path("/tmp") / f"pluto-plus-utils-radio-locks-{os.getuid()}"


def radio_lock_path(serial: str, *, root: Path | None = None) -> Path:
    """Return a non-sensitive, fixed-length lock path for one exact serial."""

    normalized = serial.strip()
    if not normalized or len(normalized) > 128:
        raise ValueError("radio lock serial must contain between 1 and 128 characters")
    token = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return (root or shared_radio_lock_root()) / f"radio-{token}.lock"


@contextmanager
def acquire_radio_lock(serial: str, *, root: Path | None = None) -> Iterator[BinaryIO]:
    """Acquire the nonblocking OS lock shared by daemon capture and maintenance."""

    lock_root = root or shared_radio_lock_root()
    _prepare_private_directory(lock_root)
    path = radio_lock_path(serial, root=lock_root)
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    stream: BinaryIO | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        opened = os.fstat(descriptor)
        linked = path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino)
        ):
            raise RadioLockError("radio lock is not one owned regular file")
        if stat.S_IMODE(opened.st_mode) != 0o600:
            os.fchmod(descriptor, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RadioLockError(f"radio {serial!r} is already owned by another process") from error
        stream = os.fdopen(descriptor, "r+b", buffering=0)
        descriptor = -1
        yield stream
    except OSError as error:
        raise RadioLockError(f"cannot acquire radio lock {path}: {error}") from error
    finally:
        if stream is not None:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
            stream.close()
        if descriptor >= 0:
            os.close(descriptor)


def _prepare_private_directory(path: Path) -> None:
    if not path.is_absolute() or ".." in path.parts:
        raise RadioLockError("radio lock root must be absolute and normalized")
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    except OSError as error:
        raise RadioLockError(f"cannot create radio lock root {path}: {error}") from error
    try:
        state = path.lstat()
    except OSError as error:
        raise RadioLockError(f"cannot inspect radio lock root {path}: {error}") from error
    if (
        not stat.S_ISDIR(state.st_mode)
        or state.st_uid != os.getuid()
        or stat.S_IMODE(state.st_mode) != 0o700
    ):
        raise RadioLockError("radio lock root must be one owned mode-0700 directory")
