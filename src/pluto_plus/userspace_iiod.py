"""Ephemeral, no-flash lifecycle for one attested radio-local iiOD.

The public lifecycle exposes no remote command parameter.  Its production
transport can only stage one byte payload, start one TCP iiOD server on the
fixed alternate port, inspect that exact process, terminate it, and remove the
three session-unique files it owns beneath ``/tmp``.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import socket
import stat
import subprocess
import sys
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, Protocol

from pluto_plus.persistent_hop import (
    PERSISTENT_HOP_CAPABILITIES,
    PERSISTENT_HOP_METADATA_ABI,
)

USERSPACE_IIOD_PORT: Final[Literal[30432]] = 30_432
STOCK_IIOD_PORT: Final[Literal[30431]] = 30_431
_MAX_BINARY_BYTES = 64 * 1024 * 1024
_MAX_CREDENTIAL_BYTES = 4_096
_TOKEN = re.compile(r"^[0-9a-f]{32}$")
_SERIAL = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REMOTE_PATH = re.compile(r"^/tmp/ppu-iiod-[0-9a-f]{32}[.](?:bin|pid|log)$")
_PROCESS_REPORT_FIELDS = frozenset(
    {
        "pid",
        "start_ticks",
        "exe_path",
        "binary_bytes",
        "binary_sha256",
        "radio_serial",
        "port",
    }
)


class UserspaceIiodLifecycleError(RuntimeError):
    """The alternate iiOD could not be proven safe or completely removed."""

    def __init__(
        self,
        message: str,
        *,
        start_receipt: UserspaceIiodStartReceipt | None = None,
        stop_receipt: UserspaceIiodStopReceipt | None = None,
    ) -> None:
        super().__init__(message)
        self.start_receipt = start_receipt
        self.stop_receipt = stop_receipt


@dataclass(frozen=True, slots=True)
class RemoteIiodPaths:
    """The only three remote filesystem paths owned by one lifecycle."""

    binary: str
    pid: str
    log: str

    def __post_init__(self) -> None:
        paths = (self.binary, self.pid, self.log)
        if len(set(paths)) != 3 or any(not _REMOTE_PATH.fullmatch(path) for path in paths):
            raise ValueError("userspace iiOD paths must be three unique canonical /tmp paths")
        stems = {path.rsplit(".", maxsplit=1)[0] for path in paths}
        if len(stems) != 1:
            raise ValueError("userspace iiOD paths must share one session-unique stem")


@dataclass(frozen=True, slots=True)
class RemoteIiodBinaryIdentity:
    path: str
    bytes: int
    sha256: str

    def __post_init__(self) -> None:
        if not _REMOTE_PATH.fullmatch(self.path) or not self.path.endswith(".bin"):
            raise ValueError("userspace iiOD binary path is invalid")
        if not 0 < self.bytes <= _MAX_BINARY_BYTES:
            raise ValueError("userspace iiOD binary size is outside its bound")
        if not _SHA256.fullmatch(self.sha256):
            raise ValueError("userspace iiOD binary digest is invalid")


@dataclass(frozen=True, slots=True)
class UserspaceIiodProcessIdentity:
    """Stable remote process identity, including PID-reuse defenses."""

    pid: int
    start_ticks: int
    exe_path: str
    binary_bytes: int
    binary_sha256: str
    radio_serial: str
    port: Literal[30432] = USERSPACE_IIOD_PORT

    def __post_init__(self) -> None:
        if self.pid <= 1 or self.start_ticks <= 0:
            raise ValueError("userspace iiOD PID identity is invalid")
        if not _REMOTE_PATH.fullmatch(self.exe_path) or not self.exe_path.endswith(".bin"):
            raise ValueError("userspace iiOD executable path is invalid")
        if not 0 < self.binary_bytes <= _MAX_BINARY_BYTES:
            raise ValueError("userspace iiOD executable size is outside its bound")
        if not _SHA256.fullmatch(self.binary_sha256):
            raise ValueError("userspace iiOD executable digest is invalid")
        if not _SERIAL.fullmatch(self.radio_serial):
            raise ValueError("userspace iiOD radio serial is invalid")
        if self.port != USERSPACE_IIOD_PORT:
            raise ValueError("userspace iiOD may listen only on port 30432")


@dataclass(frozen=True, slots=True)
class UserspaceIiodStartReceipt:
    schema_version: Literal[1]
    session_id: str
    host: str
    expected_serial: str
    known_hosts_sha256: str
    paths: RemoteIiodPaths
    binary: RemoteIiodBinaryIdentity
    process: UserspaceIiodProcessIdentity
    stock_endpoint_healthy: bool
    alternate_endpoint_ready: bool

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("userspace iiOD start receipt schema is invalid")
        _require_receipt_target(self.session_id, self.host, self.expected_serial)
        if not _SHA256.fullmatch(self.known_hosts_sha256):
            raise ValueError("userspace iiOD known-hosts digest is invalid")
        if self.paths.binary != self.binary.path:
            raise ValueError("userspace iiOD receipt binary path changed")
        _require_exact_process(self.process, self.binary, self.expected_serial)
        if not self.stock_endpoint_healthy or not self.alternate_endpoint_ready:
            raise ValueError("successful userspace iiOD start receipt must be healthy")


@dataclass(frozen=True, slots=True)
class UserspaceIiodStopReceipt:
    schema_version: Literal[1]
    session_id: str
    host: str
    expected_process: UserspaceIiodProcessIdentity | None
    observed_process: UserspaceIiodProcessIdentity | None
    identity_verified: bool
    term_sent: bool
    exit_confirmed: bool
    removed_paths: tuple[str, ...]
    alternate_port_closed: bool
    stock_endpoint_healthy: bool
    outcome: Literal["stopped", "cleanup_failed"]
    errors: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("userspace iiOD stop receipt schema is invalid")
        _require_receipt_target(self.session_id, self.host, None)
        if self.outcome not in {"stopped", "cleanup_failed"}:
            raise ValueError("userspace iiOD stop receipt outcome is invalid")
        if len(set(self.removed_paths)) != len(self.removed_paths) or any(
            not _REMOTE_PATH.fullmatch(path) for path in self.removed_paths
        ):
            raise ValueError("userspace iiOD stop receipt cleanup paths are invalid")
        if self.outcome == "stopped":
            expected_identity_ok = self.expected_process is None or (
                self.identity_verified and self.observed_process == self.expected_process
            )
            if not (
                expected_identity_ok
                and self.exit_confirmed
                and len(self.removed_paths) == 3
                and self.alternate_port_closed
                and self.stock_endpoint_healthy
                and not self.errors
            ):
                raise ValueError("successful userspace iiOD stop receipt is incomplete")
        elif not self.errors:
            raise ValueError("failed userspace iiOD stop receipt requires errors")


class UserspaceIiodTransport(Protocol):
    """Narrow semantic port; it deliberately has no arbitrary command method."""

    def attest_radio_serial(self) -> str: ...

    def stage(
        self,
        paths: RemoteIiodPaths,
        payload: bytes,
        *,
        expected_sha256: str,
    ) -> RemoteIiodBinaryIdentity: ...

    def start(
        self,
        paths: RemoteIiodPaths,
        binary: RemoteIiodBinaryIdentity,
    ) -> UserspaceIiodProcessIdentity: ...

    def inspect(self, paths: RemoteIiodPaths) -> UserspaceIiodProcessIdentity | None: ...

    def terminate(
        self,
        paths: RemoteIiodPaths,
        process: UserspaceIiodProcessIdentity,
        *,
        timeout_s: float,
    ) -> bool: ...

    def cleanup(
        self,
        paths: RemoteIiodPaths,
        binary: RemoteIiodBinaryIdentity,
    ) -> tuple[str, ...]: ...


PortProbe = Callable[[str, int, float], bool]
SerialProbe = Callable[[str, int, str, float], bool]


def tcp_port_probe(host: str, port: int, timeout_s: float) -> bool:
    """Bounded production TCP readiness/closure probe."""

    _require_probe_target(host, port, timeout_s)
    try:
        with socket.create_connection((host, port), timeout=timeout_s):
            return True
    except (OSError, TimeoutError):
        return False


def persistent_hop_endpoint_probe(
    host: str,
    port: int,
    expected_serial: str,
    timeout_s: float,
) -> bool:
    """Attest serial, ABI 3, and every persistent-hop capability, bounded.

    libiio context creation runs in a short-lived subprocess because it cannot
    itself provide a reliable wall-clock bound during network connection.  The
    child uses :class:`IioPersistentHopBackend`, the same production readback
    path used by an actual capture, but never opens a receive buffer or changes
    radio settings.
    """

    _require_probe_target(host, port, timeout_s)
    _require_serial(expected_serial)
    argv = (
        sys.executable,
        "-m",
        "pluto_plus.userspace_iiod_probe",
        host,
        str(port),
        expected_serial,
    )
    try:
        completed = subprocess.run(  # noqa: S603
            argv,
            capture_output=True,
            check=False,
            timeout=timeout_s,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if completed.returncode != 0:
        return False
    try:
        fields = _parse_report(completed.stdout)
    except UserspaceIiodLifecycleError:
        return False
    base_matches = (
        fields.get("serial") == expected_serial
        and fields.get("metadata_abi") == PERSISTENT_HOP_METADATA_ABI
    )
    if port == STOCK_IIOD_PORT:
        return base_matches and len(fields) == 2
    capabilities = tuple(
        fields.get(f"capability_{index}") for index in range(len(PERSISTENT_HOP_CAPABILITIES))
    )
    return (
        base_matches
        and capabilities == PERSISTENT_HOP_CAPABILITIES
        and len(fields) == len(PERSISTENT_HOP_CAPABILITIES) + 2
    )


@dataclass(frozen=True, slots=True)
class SshCommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes


class SshCommandRunner(Protocol):
    def run(
        self,
        argv: Sequence[str],
        *,
        stdin: bytes | None,
        timeout_s: float,
    ) -> SshCommandResult: ...


class SubprocessSshCommandRunner:
    """Bounded subprocess execution without a local shell."""

    def run(
        self,
        argv: Sequence[str],
        *,
        stdin: bytes | None,
        timeout_s: float,
    ) -> SshCommandResult:
        try:
            completed = subprocess.run(  # noqa: S603
                tuple(argv),
                input=stdin,
                capture_output=True,
                check=False,
                timeout=timeout_s,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise UserspaceIiodLifecycleError(
                f"pinned SSH subprocess could not run: {type(error).__name__}: {error}"
            ) from error
        return SshCommandResult(completed.returncode, completed.stdout, completed.stderr)


@dataclass(frozen=True, slots=True)
class _PrivateFileIdentity:
    path: Path
    device: int
    inode: int
    bytes: int
    modified_ns: int
    changed_ns: int
    sha256: str


class _CredentialPin:
    def __init__(self, host: str, known_hosts_file: Path, password_file: Path) -> None:
        self.host = host
        known_payload, self.known_hosts = _read_private_file(
            known_hosts_file, label="SSH known-hosts"
        )
        _require_exact_known_host(known_payload, host)
        password_payload, self.password = _read_private_file(password_file, label="SSH password")
        if (
            not password_payload.endswith(b"\n")
            or password_payload.count(b"\n") != 1
            or not password_payload[:-1]
            or b"\r" in password_payload
            or b"\x00" in password_payload
        ):
            raise ValueError("SSH password file must contain one nonempty newline-terminated line")

    def verify(self) -> None:
        known_payload, known = _read_private_file(self.known_hosts.path, label="SSH known-hosts")
        password_payload, password = _read_private_file(self.password.path, label="SSH password")
        if known != self.known_hosts or password != self.password:
            raise UserspaceIiodLifecycleError("pinned SSH credential file changed")
        _require_exact_known_host(known_payload, self.host)
        if (
            not password_payload.endswith(b"\n")
            or password_payload.count(b"\n") != 1
            or not password_payload[:-1]
        ):
            raise UserspaceIiodLifecycleError("pinned SSH password content changed")


_ATTEST_SERIAL_SCRIPT = b"""set -eu
serial=$(cat /sys/kernel/config/usb_gadget/composite_gadget/strings/0x409/serialnumber)
test -n "$serial"
printf 'PPU\\tserial\\t%s\\n' "$serial"
"""

_START_SCRIPT = b"""set -eu
umask 077
binary=$1
pidfile=$2
log=$3
expected_bytes=$4
expected_sha=$5
expected_serial=$6
test -f "$binary" && test ! -L "$binary" && test -x "$binary"
test "$(wc -c <"$binary" | tr -d ' ')" = "$expected_bytes"
test "$(sha256sum "$binary" | awk '{print $1}')" = "$expected_sha"
test ! -e "$pidfile" && test ! -e "$log"
serial=$(cat /sys/kernel/config/usb_gadget/composite_gadget/strings/0x409/serialnumber)
test "$serial" = "$expected_serial"
nohup "$binary" -u local: -p 30432 >"$log" 2>&1 </dev/null &
pid=$!
printf '%s\\n' "$pid" >"$pidfile"
attempt=0
while [ "$attempt" -lt 50 ]; do
  if [ -r "/proc/$pid/stat" ] && [ "$(readlink -f "/proc/$pid/exe")" = "$binary" ]; then
    break
  fi
  kill -0 "$pid" 2>/dev/null || exit 1
  attempt=$((attempt + 1))
  sleep 0.1
done
test -r "/proc/$pid/stat"
exe=$(readlink -f "/proc/$pid/exe")
test "$exe" = "$binary"
start_ticks=$(awk '{print $22}' "/proc/$pid/stat")
test "$start_ticks" -gt 0
test "$(sha256sum "$exe" | awk '{print $1}')" = "$expected_sha"
printf 'PPU\\tpid\\t%s\\n' "$pid"
printf 'PPU\\tstart_ticks\\t%s\\n' "$start_ticks"
printf 'PPU\\texe_path\\t%s\\n' "$exe"
printf 'PPU\\tbinary_bytes\\t%s\\n' "$expected_bytes"
printf 'PPU\\tbinary_sha256\\t%s\\n' "$expected_sha"
printf 'PPU\\tradio_serial\\t%s\\n' "$serial"
printf 'PPU\\tport\\t30432\\n'
"""

_INSPECT_SCRIPT = b"""set -eu
binary=$1
pidfile=$2
expected_serial=$3
if [ ! -e "$pidfile" ]; then printf 'PPU\\tstate\\tabsent\\n'; exit 0; fi
test -f "$pidfile" && test ! -L "$pidfile"
pid=$(cat "$pidfile")
case "$pid" in ''|*[!0-9]*) exit 1;; esac
if [ ! -r "/proc/$pid/stat" ]; then printf 'PPU\\tstate\\tabsent\\n'; exit 0; fi
exe=$(readlink -f "/proc/$pid/exe")
start_ticks=$(awk '{print $22}' "/proc/$pid/stat")
bytes=$(wc -c <"$exe" | tr -d ' ')
sha=$(sha256sum "$exe" | awk '{print $1}')
serial=$(cat /sys/kernel/config/usb_gadget/composite_gadget/strings/0x409/serialnumber)
test "$serial" = "$expected_serial"
printf 'PPU\\tstate\\trunning\\n'
printf 'PPU\\tpid\\t%s\\n' "$pid"
printf 'PPU\\tstart_ticks\\t%s\\n' "$start_ticks"
printf 'PPU\\texe_path\\t%s\\n' "$exe"
printf 'PPU\\tbinary_bytes\\t%s\\n' "$bytes"
printf 'PPU\\tbinary_sha256\\t%s\\n' "$sha"
printf 'PPU\\tradio_serial\\t%s\\n' "$serial"
printf 'PPU\\tport\\t30432\\n'
"""

_TERMINATE_SCRIPT = b"""set -eu
binary=$1
pidfile=$2
expected_pid=$3
expected_start=$4
expected_sha=$5
expected_serial=$6
wait_seconds=$7
test -f "$pidfile" && test ! -L "$pidfile"
test "$(cat "$pidfile")" = "$expected_pid"
test -r "/proc/$expected_pid/stat"
test "$(awk '{print $22}' "/proc/$expected_pid/stat")" = "$expected_start"
test "$(readlink -f "/proc/$expected_pid/exe")" = "$binary"
test "$(sha256sum "/proc/$expected_pid/exe" | awk '{print $1}')" = "$expected_sha"
serial=$(cat /sys/kernel/config/usb_gadget/composite_gadget/strings/0x409/serialnumber)
test "$serial" = "$expected_serial"
kill -TERM "$expected_pid"
elapsed=0
while kill -0 "$expected_pid" 2>/dev/null; do
  test "$elapsed" -lt "$wait_seconds"
  sleep 1
  elapsed=$((elapsed + 1))
done
printf 'PPU\\texit_confirmed\\t1\\n'
"""

_CLEANUP_SCRIPT = b"""set -eu
binary=$1
pidfile=$2
log=$3
for path in "$binary" "$pidfile" "$log"; do
  test ! -L "$path"
  if [ -e "$path" ]; then test -f "$path"; fi
done
if [ -e "$pidfile" ]; then
  pid=$(cat "$pidfile")
  case "$pid" in ''|*[!0-9]*) exit 1;; esac
  test ! -e "/proc/$pid"
fi
rm -f "$binary" "$pidfile" "$log"
test ! -e "$binary" && test ! -e "$pidfile" && test ! -e "$log"
printf 'PPU\\tremoved_binary\\t%s\\n' "$binary"
printf 'PPU\\tremoved_pid\\t%s\\n' "$pidfile"
printf 'PPU\\tremoved_log\\t%s\\n' "$log"
"""


class PinnedPasswordSshIiodTransport:
    """Password-file SSH transport pinned to one radio and private host key."""

    def __init__(
        self,
        *,
        host: str,
        expected_serial: str,
        known_hosts_file: Path,
        password_file: Path,
        runner: SshCommandRunner | None = None,
    ) -> None:
        self.host = _require_physical_lan_host(host)
        self.expected_serial = _require_serial(expected_serial)
        self._credentials = _CredentialPin(self.host, known_hosts_file, password_file)
        self._runner = runner or SubprocessSshCommandRunner()
        self._base_argv = (
            "sshpass",
            "-f",
            str(self._credentials.password.path),
            "ssh",
            "-T",
            "-F",
            "/dev/null",
            "-o",
            "BatchMode=no",
            "-o",
            "NumberOfPasswordPrompts=1",
            "-o",
            "PreferredAuthentications=password",
            "-o",
            "PasswordAuthentication=yes",
            "-o",
            "PubkeyAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={self._credentials.known_hosts.path}",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "CheckHostIP=yes",
            "-o",
            "UpdateHostKeys=no",
            "-o",
            "ConnectTimeout=5",
            f"root@{self.host}",
        )

    @property
    def known_hosts_sha256(self) -> str:
        return self._credentials.known_hosts.sha256

    def attest_radio_serial(self) -> str:
        fields = self._script(_ATTEST_SERIAL_SCRIPT, (), timeout_s=10)
        _require_keys(fields, {"serial"})
        return _required(fields, "serial")

    def stage(
        self,
        paths: RemoteIiodPaths,
        payload: bytes,
        *,
        expected_sha256: str,
    ) -> RemoteIiodBinaryIdentity:
        if hashlib.sha256(payload).hexdigest() != expected_sha256:
            raise UserspaceIiodLifecycleError("userspace iiOD stage payload digest changed")
        command = (
            "set -euC; umask 077; "
            f"test ! -e {paths.binary}; "
            f"test ! -e {paths.pid}; "
            f"test ! -e {paths.log}; "
            f"cat > {paths.binary}; chmod 700 {paths.binary}; "
            f"test \"$(wc -c <{paths.binary} | tr -d ' ')\" = {len(payload)}; "
            f"test \"$(sha256sum {paths.binary} | awk '{{print $1}}')\" = {expected_sha256}; "
            f"printf 'PPU\\tpath\\t%s\\n' {paths.binary}; "
            f"printf 'PPU\\tbytes\\t%s\\n' {len(payload)}; "
            f"printf 'PPU\\tsha256\\t%s\\n' {expected_sha256}"
        )
        fields = self._command(command, stdin=payload, timeout_s=90)
        _require_keys(fields, {"path", "bytes", "sha256"})
        return RemoteIiodBinaryIdentity(
            path=_required(fields, "path"),
            bytes=_required_int(fields, "bytes"),
            sha256=_required_digest(fields, "sha256"),
        )

    def start(
        self,
        paths: RemoteIiodPaths,
        binary: RemoteIiodBinaryIdentity,
    ) -> UserspaceIiodProcessIdentity:
        fields = self._script(
            _START_SCRIPT,
            (
                paths.binary,
                paths.pid,
                paths.log,
                str(binary.bytes),
                binary.sha256,
                self.expected_serial,
            ),
            timeout_s=15,
        )
        _require_keys(fields, _PROCESS_REPORT_FIELDS)
        return _process_identity(fields)

    def inspect(self, paths: RemoteIiodPaths) -> UserspaceIiodProcessIdentity | None:
        fields = self._script(
            _INSPECT_SCRIPT,
            (paths.binary, paths.pid, self.expected_serial),
            timeout_s=10,
        )
        state = _required(fields, "state")
        if state == "absent":
            _require_keys(fields, {"state"})
            return None
        if state != "running":
            raise UserspaceIiodLifecycleError("remote iiOD inspection returned an invalid state")
        _require_keys(fields, {"state", *_PROCESS_REPORT_FIELDS})
        return _process_identity(fields)

    def terminate(
        self,
        paths: RemoteIiodPaths,
        process: UserspaceIiodProcessIdentity,
        *,
        timeout_s: float,
    ) -> bool:
        wait_seconds = max(1, int(timeout_s))
        fields = self._script(
            _TERMINATE_SCRIPT,
            (
                paths.binary,
                paths.pid,
                str(process.pid),
                str(process.start_ticks),
                process.binary_sha256,
                self.expected_serial,
                str(wait_seconds),
            ),
            timeout_s=wait_seconds + 5,
        )
        _require_keys(fields, {"exit_confirmed"})
        return _required(fields, "exit_confirmed") == "1"

    def cleanup(
        self,
        paths: RemoteIiodPaths,
        binary: RemoteIiodBinaryIdentity,
    ) -> tuple[str, ...]:
        if binary.path != paths.binary:
            raise UserspaceIiodLifecycleError("userspace iiOD cleanup binary path changed")
        fields = self._script(
            _CLEANUP_SCRIPT,
            (
                paths.binary,
                paths.pid,
                paths.log,
            ),
            timeout_s=10,
        )
        _require_keys(fields, {"removed_binary", "removed_pid", "removed_log"})
        return (
            _required(fields, "removed_binary"),
            _required(fields, "removed_pid"),
            _required(fields, "removed_log"),
        )

    def _script(
        self,
        script: bytes,
        arguments: tuple[str, ...],
        *,
        timeout_s: float,
    ) -> dict[str, str]:
        if any(not _safe_remote_argument(value) for value in arguments):
            raise UserspaceIiodLifecycleError("fixed iiOD remote argument is invalid")
        command = "/bin/sh -s --" + "".join(f" {value}" for value in arguments)
        return self._command(command, stdin=script, timeout_s=timeout_s)

    def _command(
        self,
        command: str,
        *,
        stdin: bytes | None,
        timeout_s: float,
    ) -> dict[str, str]:
        self._credentials.verify()
        if timeout_s <= 0 or timeout_s > 120:
            raise ValueError("pinned SSH command timeout is outside 0..120 seconds")
        result = self._runner.run(
            (*self._base_argv, command),
            stdin=stdin,
            timeout_s=timeout_s,
        )
        if result.returncode != 0:
            detail = result.stderr.decode(errors="replace").strip()[-1_000:]
            raise UserspaceIiodLifecycleError(
                f"fixed remote iiOD operation exited {result.returncode}: {detail}"
            )
        return _parse_report(result.stdout)


class UserspaceIiodLifecycle:
    """Own one alternate iiOD from exact-byte stage through verified removal."""

    def __init__(
        self,
        *,
        host: str,
        expected_serial: str,
        known_hosts_file: Path,
        password_file: Path,
        port_probe: PortProbe = tcp_port_probe,
        serial_probe: SerialProbe = persistent_hop_endpoint_probe,
        transport: UserspaceIiodTransport | None = None,
        session_id_factory: Callable[[], str] | None = None,
        probe_timeout_s: float = 10.0,
        stop_timeout_s: float = 15.0,
    ) -> None:
        self.host = _require_physical_lan_host(host)
        self.expected_serial = _require_serial(expected_serial)
        self._credentials = _CredentialPin(self.host, known_hosts_file, password_file)
        self._transport = transport or PinnedPasswordSshIiodTransport(
            host=self.host,
            expected_serial=self.expected_serial,
            known_hosts_file=known_hosts_file,
            password_file=password_file,
        )
        self._port_probe = port_probe
        self._serial_probe = serial_probe
        self._session_id_factory = session_id_factory or _random_session_id
        if not 0 < probe_timeout_s <= 60 or not 0 < stop_timeout_s <= 60:
            raise ValueError("userspace iiOD lifecycle timeouts must be within 0..60 seconds")
        self._probe_timeout_s = probe_timeout_s
        self._stop_timeout_s = stop_timeout_s
        self._active: UserspaceIiodStartReceipt | None = None

    @property
    def active(self) -> UserspaceIiodStartReceipt | None:
        return self._active

    def start(self, binary_payload: bytes) -> UserspaceIiodStartReceipt:
        if self._active is not None:
            raise UserspaceIiodLifecycleError("userspace iiOD lifecycle is already active")
        payload = bytes(binary_payload)
        if not 0 < len(payload) <= _MAX_BINARY_BYTES:
            raise ValueError("userspace iiOD binary size is outside its bound")
        self._credentials.verify()
        if not self._serial_probe(
            self.host,
            STOCK_IIOD_PORT,
            self.expected_serial,
            self._probe_timeout_s,
        ):
            raise UserspaceIiodLifecycleError("stock iiOD endpoint is not healthy before stage")
        if self._transport.attest_radio_serial() != self.expected_serial:
            raise UserspaceIiodLifecycleError("SSH radio serial differs from the exact target")
        if self._port_probe(self.host, USERSPACE_IIOD_PORT, self._probe_timeout_s):
            raise UserspaceIiodLifecycleError("alternate iiOD port 30432 is already open")

        session_id = self._session_id_factory()
        paths = _session_paths(session_id)
        digest = hashlib.sha256(payload).hexdigest()
        expected_binary = RemoteIiodBinaryIdentity(paths.binary, len(payload), digest)
        process: UserspaceIiodProcessIdentity | None = None
        try:
            staged = self._transport.stage(paths, payload, expected_sha256=digest)
            if staged != expected_binary:
                raise UserspaceIiodLifecycleError("remote staged iiOD bytes changed")
            process = self._transport.start(paths, staged)
            _require_exact_process(process, staged, self.expected_serial)
            if not _wait_for_open_port(
                self._port_probe,
                self.host,
                USERSPACE_IIOD_PORT,
                self._probe_timeout_s,
            ):
                raise UserspaceIiodLifecycleError("alternate iiOD listener did not become ready")
            if not self._serial_probe(
                self.host,
                USERSPACE_IIOD_PORT,
                self.expected_serial,
                self._probe_timeout_s,
            ):
                raise UserspaceIiodLifecycleError("alternate iiOD readiness probe failed")
            observed = self._transport.inspect(paths)
            if observed != process:
                raise UserspaceIiodLifecycleError("alternate iiOD identity changed after readiness")
        except BaseException as primary:
            cleanup = self._cleanup_failed_start(paths, expected_binary, process)
            if isinstance(primary, UserspaceIiodLifecycleError):
                primary.stop_receipt = cleanup
            if cleanup.errors:
                primary.add_note("userspace iiOD cleanup failed: " + "; ".join(cleanup.errors))
            raise

        receipt = UserspaceIiodStartReceipt(
            schema_version=1,
            session_id=session_id,
            host=self.host,
            expected_serial=self.expected_serial,
            known_hosts_sha256=self._credentials.known_hosts.sha256,
            paths=paths,
            binary=expected_binary,
            process=process,
            stock_endpoint_healthy=True,
            alternate_endpoint_ready=True,
        )
        self._active = receipt
        return receipt

    def stop(self) -> UserspaceIiodStopReceipt:
        active = self._active
        if active is None:
            raise UserspaceIiodLifecycleError("userspace iiOD lifecycle is not active")
        receipt = self._stop_owned(active)
        if receipt.outcome != "stopped":
            raise UserspaceIiodLifecycleError(
                "userspace iiOD cleanup was not fully attested",
                start_receipt=active,
                stop_receipt=receipt,
            )
        self._active = None
        return receipt

    @contextmanager
    def session(self, binary_payload: bytes) -> Iterator[UserspaceIiodStartReceipt]:
        start = self.start(binary_payload)
        try:
            yield start
        except BaseException as primary:
            try:
                self.stop()
            except BaseException as cleanup:
                primary.add_note(
                    f"userspace iiOD context cleanup failed: {type(cleanup).__name__}: {cleanup}"
                )
            raise
        else:
            self.stop()

    def _stop_owned(self, active: UserspaceIiodStartReceipt) -> UserspaceIiodStopReceipt:
        errors: list[str] = []
        observed: UserspaceIiodProcessIdentity | None = None
        identity_verified = False
        term_sent = False
        exit_confirmed = False
        removed: tuple[str, ...] = ()
        try:
            self._credentials.verify()
            observed = self._transport.inspect(active.paths)
            if observed != active.process:
                raise UserspaceIiodLifecycleError("alternate iiOD process identity changed")
            identity_verified = True
            exit_confirmed = self._transport.terminate(
                active.paths,
                active.process,
                timeout_s=self._stop_timeout_s,
            )
            term_sent = exit_confirmed
            if not exit_confirmed:
                raise UserspaceIiodLifecycleError("alternate iiOD did not exit after TERM")
            removed = self._transport.cleanup(active.paths, active.binary)
            if removed != (
                active.paths.binary,
                active.paths.pid,
                active.paths.log,
            ):
                raise UserspaceIiodLifecycleError("alternate iiOD cleanup paths changed")
        except BaseException as error:
            errors.append(f"{type(error).__name__}: {error}")
        alternate_closed = False
        stock_healthy = False
        try:
            alternate_closed = not self._port_probe(
                self.host, USERSPACE_IIOD_PORT, self._probe_timeout_s
            )
            if not alternate_closed:
                raise UserspaceIiodLifecycleError("alternate iiOD port 30432 remains open")
        except BaseException as error:
            errors.append(f"alternate port probe: {type(error).__name__}: {error}")
        try:
            stock_healthy = self._serial_probe(
                self.host,
                STOCK_IIOD_PORT,
                self.expected_serial,
                self._probe_timeout_s,
            )
            if not stock_healthy:
                raise UserspaceIiodLifecycleError("stock iiOD endpoint is not healthy")
        except BaseException as error:
            errors.append(f"stock endpoint probe: {type(error).__name__}: {error}")
        return UserspaceIiodStopReceipt(
            schema_version=1,
            session_id=active.session_id,
            host=self.host,
            expected_process=active.process,
            observed_process=observed,
            identity_verified=identity_verified,
            term_sent=term_sent,
            exit_confirmed=exit_confirmed,
            removed_paths=removed,
            alternate_port_closed=alternate_closed,
            stock_endpoint_healthy=stock_healthy,
            outcome="stopped" if not errors else "cleanup_failed",
            errors=tuple(errors),
        )

    def _cleanup_failed_start(
        self,
        paths: RemoteIiodPaths,
        binary: RemoteIiodBinaryIdentity,
        process: UserspaceIiodProcessIdentity | None,
    ) -> UserspaceIiodStopReceipt:
        errors: list[str] = []
        observed: UserspaceIiodProcessIdentity | None = None
        identity_verified = False
        term_sent = False
        exit_confirmed = False
        removed: tuple[str, ...] = ()
        try:
            observed = self._transport.inspect(paths)
            if process is not None and observed != process:
                raise UserspaceIiodLifecycleError("failed start changed process identity")
            if observed is not None:
                _require_exact_process(observed, binary, self.expected_serial)
                identity_verified = True
                exit_confirmed = self._transport.terminate(
                    paths, observed, timeout_s=self._stop_timeout_s
                )
                term_sent = exit_confirmed
                if not exit_confirmed:
                    raise UserspaceIiodLifecycleError("failed-start iiOD did not exit after TERM")
            else:
                exit_confirmed = True
            if not self._port_probe(self.host, USERSPACE_IIOD_PORT, self._probe_timeout_s):
                removed = self._transport.cleanup(paths, binary)
                if removed != (paths.binary, paths.pid, paths.log):
                    raise UserspaceIiodLifecycleError("failed-start cleanup paths changed")
            else:
                raise UserspaceIiodLifecycleError("failed-start alternate port remains open")
        except BaseException as error:
            errors.append(f"{type(error).__name__}: {error}")
        alternate_closed = False
        stock_healthy = False
        try:
            alternate_closed = not self._port_probe(
                self.host, USERSPACE_IIOD_PORT, self._probe_timeout_s
            )
        except BaseException as error:
            errors.append(f"alternate port probe: {type(error).__name__}: {error}")
        try:
            stock_healthy = self._serial_probe(
                self.host,
                STOCK_IIOD_PORT,
                self.expected_serial,
                self._probe_timeout_s,
            )
        except BaseException as error:
            errors.append(f"stock endpoint probe: {type(error).__name__}: {error}")
        if not alternate_closed:
            errors.append("alternate iiOD port 30432 is not closed")
        if not stock_healthy:
            errors.append("stock iiOD endpoint is not healthy")
        return UserspaceIiodStopReceipt(
            schema_version=1,
            session_id=paths.binary.removeprefix("/tmp/ppu-iiod-").removesuffix(".bin"),
            host=self.host,
            expected_process=process,
            observed_process=observed,
            identity_verified=identity_verified,
            term_sent=term_sent,
            exit_confirmed=exit_confirmed,
            removed_paths=removed,
            alternate_port_closed=alternate_closed,
            stock_endpoint_healthy=stock_healthy,
            outcome="stopped" if not errors else "cleanup_failed",
            errors=tuple(errors),
        )


class UserspaceIiodDeployment:
    """Leo-facing provider that owns a stable local binary and one lifecycle.

    The alternate port is intentionally absent from the constructor: this
    deployment can only start iiOD on :30432 and verify the stock endpoint on
    :30431.  Probes remain injectable so callers can use their existing,
    exact-serial IIO client and tests need no network or radio.
    """

    def __init__(
        self,
        *,
        host: str,
        expected_serial: str,
        binary_path: Path,
        known_hosts_path: Path,
        password_path: Path,
        port_probe: PortProbe = tcp_port_probe,
        serial_probe: SerialProbe = persistent_hop_endpoint_probe,
        transport: UserspaceIiodTransport | None = None,
        runner: SshCommandRunner | None = None,
        session_id_factory: Callable[[], str] | None = None,
        probe_timeout_s: float = 10.0,
        stop_timeout_s: float = 15.0,
    ) -> None:
        if transport is not None and runner is not None:
            raise ValueError("inject either an iiOD transport or an SSH runner, not both")
        selected_transport = transport or PinnedPasswordSshIiodTransport(
            host=host,
            expected_serial=expected_serial,
            known_hosts_file=known_hosts_path,
            password_file=password_path,
            runner=runner,
        )
        self.binary_path = _canonical_local_path(binary_path, label="userspace iiOD binary")
        self._lifecycle = UserspaceIiodLifecycle(
            host=host,
            expected_serial=expected_serial,
            known_hosts_file=known_hosts_path,
            password_file=password_path,
            port_probe=port_probe,
            serial_probe=serial_probe,
            transport=selected_transport,
            session_id_factory=session_id_factory,
            probe_timeout_s=probe_timeout_s,
            stop_timeout_s=stop_timeout_s,
        )

    @property
    def active(self) -> UserspaceIiodStartReceipt | None:
        return self._lifecycle.active

    def enter_and_attest(self) -> UserspaceIiodStartReceipt:
        """Read one stable local binary snapshot, stage it, and attest iiOD."""

        return self._lifecycle.start(_read_local_binary(self.binary_path))

    def exit_and_verify(self) -> UserspaceIiodStopReceipt:
        """Stop only the attested process and prove exact cleanup/restoration."""

        return self._lifecycle.stop()

    @contextmanager
    def session(self) -> Iterator[UserspaceIiodStartReceipt]:
        start = self.enter_and_attest()
        try:
            yield start
        except BaseException as primary:
            try:
                self.exit_and_verify()
            except BaseException as cleanup:
                primary.add_note(
                    f"userspace iiOD deployment cleanup failed: {type(cleanup).__name__}: {cleanup}"
                )
            raise
        else:
            self.exit_and_verify()


def _random_session_id() -> str:
    return os.urandom(16).hex()


def _wait_for_open_port(
    probe: PortProbe,
    host: str,
    port: int,
    timeout_s: float,
) -> bool:
    """Wait within one deadline for a newly spawned listener to accept TCP."""

    deadline = time.monotonic() + timeout_s
    while (remaining := deadline - time.monotonic()) > 0:
        if probe(host, port, remaining):
            return True
        time.sleep(min(0.05, remaining))
    return False


def _session_paths(session_id: str) -> RemoteIiodPaths:
    if not _TOKEN.fullmatch(session_id):
        raise UserspaceIiodLifecycleError("userspace iiOD session ID is not canonical random hex")
    stem = f"/tmp/ppu-iiod-{session_id}"
    return RemoteIiodPaths(f"{stem}.bin", f"{stem}.pid", f"{stem}.log")


def _require_physical_lan_host(host: str) -> str:
    if not isinstance(host, str) or host != host.strip():
        raise ValueError("userspace iiOD host must be one literal 192.168.1.* address")
    try:
        address = ipaddress.IPv4Address(host)
    except ipaddress.AddressValueError as error:
        raise ValueError("userspace iiOD host must be one literal 192.168.1.* address") from error
    network = ipaddress.IPv4Network("192.168.1.0/24")
    if str(address) != host or address not in network or address in {network[0], network[-1]}:
        raise ValueError("userspace iiOD host must be one usable literal 192.168.1.* address")
    return host


def _require_serial(serial: str) -> str:
    if not isinstance(serial, str) or not _SERIAL.fullmatch(serial):
        raise ValueError("userspace iiOD requires one exact canonical radio serial")
    return serial


def _require_probe_target(host: str, port: int, timeout_s: float) -> None:
    _require_physical_lan_host(host)
    if port not in {STOCK_IIOD_PORT, USERSPACE_IIOD_PORT}:
        raise ValueError("iiOD probe may target only ports 30431 or 30432")
    if not 0 < timeout_s <= 60:
        raise ValueError("iiOD probe timeout must be within 0..60 seconds")


def _require_receipt_target(session_id: str, host: str, serial: str | None) -> None:
    if not _TOKEN.fullmatch(session_id):
        raise ValueError("userspace iiOD receipt session ID is invalid")
    _require_physical_lan_host(host)
    if serial is not None:
        _require_serial(serial)


def _canonical_local_path(path: Path, *, label: str) -> Path:
    selected = path.expanduser().absolute()
    if not selected.is_absolute() or ".." in selected.parts:
        raise ValueError(f"{label} path must be absolute and normalized")
    return selected


def _read_local_binary(path: Path) -> bytes:
    selected = _canonical_local_path(path, label="userspace iiOD binary")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        before = selected.lstat()
        descriptor = os.open(selected, flags)
    except OSError as error:
        raise UserspaceIiodLifecycleError(
            f"userspace iiOD binary cannot be opened safely: {error}"
        ) from error
    try:
        opened = os.fstat(descriptor)
        if _stable_file_facts(before) != _stable_file_facts(opened):
            raise UserspaceIiodLifecycleError("userspace iiOD binary changed while opening")
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or not 0 < opened.st_size <= _MAX_BINARY_BYTES
        ):
            raise UserspaceIiodLifecycleError(
                "userspace iiOD binary must be one bounded regular file"
            )
        payload = os.read(descriptor, opened.st_size + 1)
        if len(payload) != opened.st_size or os.read(descriptor, 1):
            raise UserspaceIiodLifecycleError("userspace iiOD binary changed during read")
        if _stable_file_facts(os.fstat(descriptor)) != _stable_file_facts(opened):
            raise UserspaceIiodLifecycleError("userspace iiOD binary changed during read")
    finally:
        os.close(descriptor)
    return payload


def _read_private_file(path: Path, *, label: str) -> tuple[bytes, _PrivateFileIdentity]:
    selected = _canonical_local_path(path, label=label)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        before = selected.lstat()
        descriptor = os.open(selected, flags)
    except OSError as error:
        raise ValueError(f"{label} cannot be opened safely: {error}") from error
    try:
        opened = os.fstat(descriptor)
        if _stable_file_facts(before) != _stable_file_facts(opened):
            raise ValueError(f"{label} changed while opening")
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) not in {0o400, 0o600}
            or opened.st_nlink != 1
            or not 0 < opened.st_size <= _MAX_CREDENTIAL_BYTES
        ):
            raise ValueError(f"{label} must be one owned mode-0400/0600 regular file")
        payload = os.read(descriptor, opened.st_size + 1)
        if len(payload) != opened.st_size or os.read(descriptor, 1):
            raise ValueError(f"{label} changed during read")
        if _stable_file_facts(os.fstat(descriptor)) != _stable_file_facts(opened):
            raise ValueError(f"{label} changed during read")
    finally:
        os.close(descriptor)
    return payload, _PrivateFileIdentity(
        path=selected,
        device=opened.st_dev,
        inode=opened.st_ino,
        bytes=opened.st_size,
        modified_ns=opened.st_mtime_ns,
        changed_ns=opened.st_ctime_ns,
        sha256=hashlib.sha256(payload).hexdigest(),
    )


def _stable_file_facts(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _require_exact_known_host(payload: bytes, host: str) -> None:
    try:
        lines = [
            line.strip()
            for line in payload.decode("ascii").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    except UnicodeDecodeError as error:
        raise ValueError("SSH known-hosts must be ASCII") from error
    if not lines:
        raise ValueError("SSH known-hosts contains no pinned key")
    for line in lines:
        fields = line.split()
        if (
            len(fields) < 3
            or fields[0] != host
            or not fields[1].startswith(("ssh-", "ecdsa-", "sk-"))
        ):
            raise ValueError("SSH known-hosts must contain only exact literal-host keys")


def _safe_remote_argument(value: str) -> bool:
    return bool(value) and all(character.isalnum() or character in "/._:-" for character in value)


def _parse_report(payload: bytes) -> dict[str, str]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise UserspaceIiodLifecycleError("remote iiOD report is not UTF-8") from error
    fields: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) != 3 or parts[0] != "PPU" or not parts[1] or parts[1] in fields:
            raise UserspaceIiodLifecycleError("remote iiOD report is malformed")
        fields[parts[1]] = parts[2]
    if not fields:
        raise UserspaceIiodLifecycleError("remote iiOD report is empty")
    return fields


def _required(fields: dict[str, str], name: str) -> str:
    value = fields.get(name, "")
    if not value:
        raise UserspaceIiodLifecycleError(f"remote iiOD report lacks {name}")
    return value


def _require_keys(fields: dict[str, str], expected: set[str] | frozenset[str]) -> None:
    if fields.keys() != expected:
        raise UserspaceIiodLifecycleError("remote iiOD report fields are not exact")


def _required_int(fields: dict[str, str], name: str) -> int:
    raw = _required(fields, name)
    try:
        value = int(raw)
    except ValueError as error:
        raise UserspaceIiodLifecycleError(f"remote iiOD {name} is not an integer") from error
    if str(value) != raw or value <= 0:
        raise UserspaceIiodLifecycleError(f"remote iiOD {name} is not canonical and positive")
    return value


def _required_digest(fields: dict[str, str], name: str) -> str:
    value = _required(fields, name)
    if not _SHA256.fullmatch(value):
        raise UserspaceIiodLifecycleError(f"remote iiOD {name} is not SHA-256")
    return value


def _process_identity(fields: dict[str, str]) -> UserspaceIiodProcessIdentity:
    port = _required_int(fields, "port")
    if port != USERSPACE_IIOD_PORT:
        raise UserspaceIiodLifecycleError("remote iiOD process uses a noncanonical port")
    return UserspaceIiodProcessIdentity(
        pid=_required_int(fields, "pid"),
        start_ticks=_required_int(fields, "start_ticks"),
        exe_path=_required(fields, "exe_path"),
        binary_bytes=_required_int(fields, "binary_bytes"),
        binary_sha256=_required_digest(fields, "binary_sha256"),
        radio_serial=_required(fields, "radio_serial"),
        port=USERSPACE_IIOD_PORT,
    )


def _require_exact_process(
    process: UserspaceIiodProcessIdentity,
    binary: RemoteIiodBinaryIdentity,
    expected_serial: str,
) -> None:
    if (
        process.exe_path != binary.path
        or process.binary_bytes != binary.bytes
        or process.binary_sha256 != binary.sha256
        or process.radio_serial != expected_serial
        or process.port != USERSPACE_IIOD_PORT
    ):
        raise UserspaceIiodLifecycleError("remote iiOD process identity is not exact")
