"""Private absent-only evidence and a hash-linked, fsynced event journal."""

from __future__ import annotations

import fcntl
import json
import os
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TypeVar

from .contracts import Blob, Contract, Event, Plan, RecoveryError, Session, canonical, digest

T = TypeVar("T", bound=Contract)
MAX_BLOB = 128 * 1024 * 1024


def read_regular(path: Path, maximum: int = MAX_BLOB) -> bytes:
    """Read stable bytes without following a final symlink or special file."""
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > maximum:
        raise RecoveryError("evidence_invalid", "expected one bounded regular file")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise RecoveryError("evidence_changed", "file changed while opening")
        data = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ) or len(data) != opened.st_size:
        raise RecoveryError("evidence_changed", "file changed during read")
    return data


def publish(path: Path, data: bytes) -> None:
    """Publish absent-only, including a durable directory entry."""
    fd, temporary = tempfile.mkstemp(prefix=".pending-", dir=path.parent)
    temp = Path(temporary)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temp, path, follow_symlinks=False)
        temp.unlink()
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        temp.unlink(missing_ok=True)


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise RecoveryError("evidence_invalid", "duplicate JSON key")
        result[key] = value
    return result


def parse(data: bytes, model: type[T]) -> T:
    raw = json.loads(data, object_pairs_hook=_pairs)
    value = model.model_validate(raw)
    if canonical(value) != data:
        raise RecoveryError("evidence_invalid", "contract is not canonical JSON")
    return value


class Store:
    def __init__(self, root: Path) -> None:
        self.root = root.absolute()
        for path in (self.root, self.root / "blobs", self.root / "events"):
            state = path.lstat()
            if (
                not stat.S_ISDIR(state.st_mode)
                or state.st_uid != os.getuid()
                or stat.S_IMODE(state.st_mode) != 0o700
                or path.resolve() != path
            ):
                raise RecoveryError("evidence_invalid", "session directories must be owned 0700")
        self.session = self.document("session.json", Session)

    @classmethod
    def create(cls, root: Path, session: Session) -> Store:
        root = root.absolute()
        if root.parent.resolve() != root.parent:
            raise RecoveryError("evidence_invalid", "session parent must not contain symlinks")
        root.mkdir(mode=0o700)
        (root / "blobs").mkdir(mode=0o700)
        (root / "events").mkdir(mode=0o700)
        publish(root / "session.json", canonical(session))
        return cls(root)

    def document(self, name: str, model: type[T]) -> T:
        path = self.root / name
        self._private(path)
        return parse(read_regular(path, 4 * 1024 * 1024), model)

    @staticmethod
    def _private(path: Path) -> None:
        state = path.lstat()
        if state.st_uid != os.getuid() or stat.S_IMODE(state.st_mode) != 0o600:
            raise RecoveryError("evidence_invalid", "evidence must be owned mode 0600")

    @contextmanager
    def lock(self, *, guide: bool = False) -> Iterator[None]:
        name = "guide-lock" if guide else "lock"
        fd = os.open(self.root / name, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            self._private(self.root / name)
            if not stat.S_ISREG(os.fstat(fd).st_mode) or os.fstat(fd).st_nlink != 1:
                raise RecoveryError("session_busy", "invalid session lock")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise RecoveryError("session_busy", "another process owns this session") from error
            yield
        finally:
            os.close(fd)

    def put(self, data: bytes) -> Blob:
        if not 0 < len(data) <= MAX_BLOB:
            raise RecoveryError("evidence_invalid", "invalid blob size")
        blob = Blob(sha256=digest(data), size=len(data))
        path = self.root / "blobs" / blob.sha256
        try:
            publish(path, data)
        except FileExistsError:
            if self.get(blob) != data:
                raise RecoveryError("evidence_changed", "existing blob differs") from None
        return blob

    def get(self, blob: Blob) -> bytes:
        path = self.root / "blobs" / blob.sha256
        self._private(path)
        data = read_regular(path, blob.size)
        if len(data) != blob.size or digest(data) != blob.sha256:
            raise RecoveryError("evidence_changed", "blob length or digest differs")
        return data

    def events(self) -> tuple[Event, ...]:
        events: list[Event] = []
        previous = None
        paths = sorted((self.root / "events").glob("*.json"))
        for sequence, path in enumerate(paths):
            self._private(path)
            data = read_regular(path, 4 * 1024 * 1024)
            event = parse(data, Event)
            if (
                path.name != f"{sequence:08d}.json"
                or event.sequence != sequence
                or event.previous_sha256 != previous
            ):
                raise RecoveryError("journal_invalid", "event sequence or hash chain differs")
            events.append(event)
            previous = digest(data)
        return tuple(events)

    def record(self, kind: str, data: dict[str, object] | None = None) -> Event:
        # Callers hold lock across observation, intent, dispatch and recording.
        events = self.events()
        event = Event(
            sequence=len(events),
            previous_sha256=(digest(canonical(events[-1])) if events else None),
            kind=kind,
            data=data or {},
        )
        publish(self.root / "events" / f"{len(events):08d}.json", canonical(event))
        return event

    def latest(self, kind: str) -> Event:
        for event in reversed(self.events()):
            if event.kind == kind:
                return event
        raise RecoveryError("evidence_missing", f"{kind} evidence is required")

    def status(self) -> dict[str, object]:
        events = self.events()
        state = "discovered"
        for event in events:
            if event.kind in {
                "bootstrap_ready",
                "backup_verified",
                "plan_ready",
                "ram_boot_verified",
                "flash_verified",
                "awaiting_cold_boot",
                "recovered",
                "failed",
                "interrupted",
            }:
                state = event.kind
            elif event.kind in {"erase_intent", "program_intent", "ram_boot_intent"}:
                state = "interrupted"
        next_actions = {
            "discovered": "select a qualified profile and capture SD bootstrap evidence",
            "bootstrap_ready": "capture and verify a complete physical backup",
            "backup_verified": "supply target boot provenance and exact rollback artifacts",
            "plan_ready": "review the plan and run the qualified RAM test",
            "ram_boot_verified": "review and execute the exact repair plan",
            "flash_verified": "perform the guided QSPI cold boot and attest return",
            "awaiting_cold_boot": "perform the guided QSPI cold boot and attest return",
            "interrupted": "resume by identifying the target and reading current physical flash",
            "failed": "inspect private failure evidence and resolve the reported blocker",
            "recovered": "retain receipt; conservative Linux update restrictions still apply",
        }
        return {
            "session_id": self.session.session_id,
            "state": state,
            "event_count": len(events),
            "next_action": next_actions[state],
        }

    def sanitized(self) -> dict[str, object]:
        checks = []
        for event in self.events():
            # Never recursively serialize arbitrary event data or private logs.
            checks.append(
                {
                    "sequence": event.sequence,
                    "kind": event.kind,
                    "event_sha256": digest(canonical(event)),
                }
            )
        result: dict[str, object] = {"schema_version": 1, **self.status(), "checks": checks}
        if any(e.kind == "plan_ready" for e in self.events()):
            plan = parse(
                self.get(Blob.model_validate(self.latest("plan_ready").data["plan"])), Plan
            )
            result["repair"] = {
                "plan_sha256": plan.sha256,
                "profile_sha256": plan.profile_sha256,
                "qualification_id": plan.observation.qualification_id,
                "policy_version": plan.policy_version,
                "original_flash": plan.original.model_dump(),
                "expected_flash": plan.expected.model_dump(),
                "patches": [p.model_dump() for p in plan.patches],
                "sectors": [s.model_dump() for s in plan.sectors],
            }
        return result
