"""Fixed read-only flash observations and a journaled SSH integrity boundary."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shlex
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Protocol

from pluto_plus.flash_safety import (
    LEGACY_ADDRESS_LIMIT,
    FlashDecision,
    FlashObservation,
    FlashPartition,
    FlashSafetyError,
    decode_environment,
    require_same_flash,
    validate_flash,
    verify_protected,
)
from pluto_plus.flash_writer import tools_observation_script

FLASH_COMMAND = "/bin/sh -s -- ppu-flash-safety-v1"
_LOCK = "/tmp/ppu-physical-flash.lock"

# Keep the read and encoder statuses separate: a pipeline can hide an MTD error.
# Released Pluto BusyBox has uuencode -m, but no base64 applet.
FLASH_READ_SCRIPT = rb"""set -eu
umask 077
size=$1; device=$2; lock=$3; owner=$4
test "$(cat "$lock/owner")" = "$owner"
chunk="$lock/read.bin"
trap 'rm -f "$chunk"' EXIT
trap 'exit 1' HUP INT TERM
head -c "$size" "$device" >"$chunk"
test "$(wc -c <"$chunk")" = "$size"
if command -v base64 >/dev/null 2>&1; then
  base64 "$chunk"
elif command -v uuencode >/dev/null 2>&1; then
  encoded=$(uuencode -m - <"$chunk")
  printf '%s\n' "$encoded" | sed '1d;$d'
else
  echo 'flash backup requires base64 or uuencode -m' >&2
  exit 1
fi
"""

# No unbounded upper-bank reads. Protected partitions are read here only after
# their observed physical ranges have been checked. Offsets come from MTD sysfs,
# not cumulative /proc/mtd sizes. The fixed updater's config is also constrained.
OBSERVE_SCRIPT = rb"""set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
emit() { printf '%s=%s\n' "$1" "$2"; }
digest() { sha256sum "$1" | awk '{print $1}'; }
test "$(id -u)" = 0
emit serial "$(cat /sys/kernel/config/usb_gadget/composite_gadget/strings/0x409/serialnumber)"
emit boot_id "$(cat /proc/sys/kernel/random/boot_id)"
emit kernel "$(uname -r):$(digest /opt/VERSIONS)"
emit board_identity "$(digest /sys/firmware/fdt)"
updater=$(digest /sbin/update_frm.sh)
emit updater_sha256 "$updater"
config_digest=$(digest /etc/device_config)
test "$config_digest" = 8938c87cd4949f07c33ec2f638d339a45c1c6d5bd0c4e777b64dcaf00577c3f9
""" + tools_observation_script() + rb"""
emit tools_sha256 "$(printf '%s\n' "$tools" | sha256sum | awk '{print $1}')"
env_config=$(sed '/^[[:space:]]*#/d; /^[[:space:]]*$/d' /etc/fw_env.config | awk '{$1=$1;print}')
test "$env_config" = '/dev/mtd1 0x0000 0x20000 0x20000'
emit environment_sha256 "$(digest /etc/fw_env.config)"
nor_count=0
for nor in /sys/bus/spi/devices/*/spi-nor; do
  test -d "$nor" || continue
  nor_count=$((nor_count + 1))
  emit flash_identity "$(cat "$nor/manufacturer"):$(cat "$nor/partname"):$(cat "$nor/jedec_id")"
done
test "$nor_count" = 1
capacity=0
count=0
for p in /sys/class/mtd/mtd[0-9]*; do
  case "$p" in *ro) continue;; esac
  test -d "$p" || continue
  test "$(cat "$p/type")" = nor
  test "$(cat "$p/numeraseregions")" = 0
  test "$(cat "$p/writesize")" = 1
  # Reject nested MTD partitions: offset must be relative to the physical chip.
  test "$(basename "$(readlink -f "$p/..")")" = mtd
  start=$(cat "$p/offset"); size=$(cat "$p/size"); erase=$(cat "$p/erasesize")
  case "$start:$size:$erase" in *[!0-9:]*) exit 1;; esac
  test "$size" -gt 0 && test "$size" -le 134217728
  end=$((start + size))
  if test "$end" -gt "$capacity"; then capacity=$end; fi
  emit "$(basename "$p")" "$(cat "$p/name"):$start:$size:$erase"
  count=$((count + 1))
done
test "$count" = 4
emit capacity "$capacity"
test "$(cat /sys/class/mtd/mtd0/offset)" = 0
boot_size=$(cat /sys/class/mtd/mtd0/size)
test "$boot_size" -gt 0 && test "$boot_size" -le 16777216
test "$(wc -c </dev/mtd0)" = "$boot_size"
emit boot_sha256 "$(digest /dev/mtd0)"
for index in 1 2; do
  p=/sys/class/mtd/mtd$index
  start=$(cat "$p/offset"); size=$(cat "$p/size")
  test "$start" -ge 0 && test "$size" -gt 0
  test "$((start + size))" -le 16777216
  test "$(wc -c </dev/mtd$index)" = "$size"
  emit "protected$index" "$(digest /dev/mtd$index)"
done
"""


class FlashSshTransport(Protocol):
    def run(
        self,
        command: str,
        *,
        stdin: bytes | None = None,
        timeout_s: float = 15,
    ) -> str: ...


def observe_flash(transport: FlashSshTransport) -> FlashObservation:
    raw = transport.run(FLASH_COMMAND, stdin=OBSERVE_SCRIPT, timeout_s=120)
    if len(raw) > 16384:
        raise FlashSafetyError("flash_observation_invalid", "oversized observation")
    fields: dict[str, str] = {}
    for line in raw.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in fields or not value:
            raise FlashSafetyError("flash_observation_invalid", "incomplete/duplicate observation")
        fields[key] = value
    expected = {
        "serial",
        "board_identity",
        "protected1",
        "protected2",
        "boot_id",
        "kernel",
        "updater_sha256",
        "tools_sha256",
        "boot_sha256",
        "flash_identity",
        "capacity",
        "environment_sha256",
        "mtd0",
        "mtd1",
        "mtd2",
        "mtd3",
    }
    if set(fields) != expected:
        raise FlashSafetyError("flash_observation_invalid", "unexpected flash observation fields")
    if any(not re.fullmatch(r"[0-9a-f]{64}", fields[key]) for key in ("protected1", "protected2")):
        raise FlashSafetyError("flash_observation_invalid", "invalid protected-region digests")
    try:
        partitions = []
        for index in range(4):
            name, start, size, erase = fields[f"mtd{index}"].split(":")
            if not all(re.fullmatch(r"[0-9]{1,9}", v) for v in (start, size, erase)):
                raise ValueError("invalid partition number")
            partitions.append(FlashPartition(index, name, int(start), int(size), int(erase)))
        if not re.fullmatch(r"[0-9]{1,9}", fields["capacity"]):
            raise ValueError("invalid capacity")
        return FlashObservation(
            board_identity=fields["board_identity"],
            serial=fields["serial"],
            boot_id=fields["boot_id"],
            kernel=fields["kernel"],
            updater_sha256=fields["updater_sha256"],
            tools_sha256=fields["tools_sha256"],
            boot_sha256=fields["boot_sha256"],
            flash_identity=fields["flash_identity"],
            capacity=int(fields["capacity"]),
            partitions=tuple(partitions),
            environment_sha256=fields["environment_sha256"],
            report_sha256=hashlib.sha256(raw.encode()).hexdigest(),
        )
    except ValueError as error:
        raise FlashSafetyError("flash_geometry_invalid", str(error)) from error


def _save(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


class FlashSession:
    """One remote lock and private recovery bundle, retained on uncertain mutation."""

    def __init__(
        self,
        transport: FlashSshTransport,
        decision: FlashDecision,
        fit: bytes,
        directory: Path,
    ) -> None:
        self.transport = transport
        self.decision = decision
        self.fit = fit
        self.directory = directory
        self.token = uuid.uuid4().hex
        self.before: dict[int, bytes] = {}
        self.locked = False
        self.dispatched = False
        self.verified = False

    def _run(self, script: bytes, timeout_s: float = 120) -> str:
        return self.transport.run(FLASH_COMMAND, stdin=script, timeout_s=timeout_s)

    def _owns_lock(self) -> bytes:
        return f'test "$(cat {_LOCK}/owner)" = {self.token}\n'.encode()

    def prepare(self) -> None:
        # The parent is an existing private receipt/evidence directory.
        parent = self.directory.parent
        if parent.is_symlink() or (
            parent.exists()
            and (parent.stat().st_uid != os.geteuid() or parent.stat().st_mode & 0o022)
        ):
            raise FlashSafetyError("flash_backup_unavailable", "unsafe recovery evidence directory")
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=False)
        os.chmod(self.directory, 0o700)
        self._run(
            f"set -eu\numask 077\nmkdir {_LOCK}\nprintf '%s' {self.token} >{_LOCK}/owner\n".encode()
        )
        self.locked = True
        fresh = validate_flash(observe_flash(self.transport), self.fit)
        require_same_flash(self.decision, fresh)
        self.before = self._protected()
        # Reviewed U-Boot import stops at the double NUL; CRC covers all bytes.
        # fw_setenv may retain old bytes in the inactive tail. Back up all of it.
        decode_environment(self.before[1], opaque_padding=True)
        if hashlib.sha256(self.before[0]).hexdigest() != fresh.observation.boot_sha256:
            raise FlashSafetyError("flash_observation_changed", "boot changed during backup")
        for index, data in self.before.items():
            _save(self.directory / f"mtd{index}.bin", data)
        # Retain an exact rollback FIT when the current FIT is within the safe
        # reader range. No upper-bank reads to manufacture legacy provenance.
        header = self._read(3, 8)
        old_size = int.from_bytes(header[4:8], "big")
        firmware = next(p for p in fresh.observation.partitions if p.index == 3)
        if (
            header[:4] != b"\xd0\x0d\xfe\xed"
            or old_size < 40
            or firmware.start + old_size > min(LEGACY_ADDRESS_LIMIT, firmware.end)
        ):
            raise FlashSafetyError(
                "flash_backup_unavailable", "current rollback FIT is not safely readable"
            )
        rollback = self._read(3, old_size)
        from pluto_plus.firmware import _validate_fit

        _validate_fit(rollback)
        _save(self.directory / "rollback.fit", rollback)
        _save(
            self.directory / "manifest.json",
            json.dumps(
                {
                    "decision": asdict(fresh),
                    "lock_token": self.token,
                    "rollback_sha256": hashlib.sha256(rollback).hexdigest(),
                    "protected_sha256": {
                        str(i): hashlib.sha256(b).hexdigest() for i, b in self.before.items()
                    },
                },
                sort_keys=True,
                indent=2,
            ).encode(),
        )

    def _read(self, index: int, size: int) -> bytes:
        partition = next(
            (p for p in self.decision.observation.partitions if p.index == index), None
        )
        if (
            partition is None
            or not 0 < size <= partition.size
            or partition.start + size > self.decision.address_limit
        ):
            raise FlashSafetyError("protected_verification_unavailable", "invalid read range")
        raw = self._run(
            f"set -- {size} /dev/mtd{index} {_LOCK} {self.token}\n".encode() + FLASH_READ_SCRIPT
        )
        if len(raw) > size * 2 + 128:
            raise FlashSafetyError("protected_verification_unavailable", "oversized flash read")
        try:
            data = base64.b64decode("".join(raw.split()), validate=True)
        except ValueError as error:
            raise FlashSafetyError(
                "protected_verification_unavailable", "invalid read encoding"
            ) from error
        if len(data) != size:
            raise FlashSafetyError("protected_verification_unavailable", "short flash read")
        return data

    def _protected(self) -> dict[int, bytes]:
        return {
            p.index: self._read(p.index, p.size)
            for p in self.decision.observation.partitions
            if p.index != 3
        }

    def invoke(self, staged_path: str, frm_sha256: str) -> str:
        if not re.fullmatch(r"[0-9a-f]{64}", frm_sha256):
            raise FlashSafetyError("flash_observation_invalid", "invalid staged digest")
        if staged_path not in (
            "/tmp/pluto-plus-utils/pluto.frm",
            "/root/.pluto-plus-ip-firmware/pluto.frm",
        ):
            raise FlashSafetyError("flash_observation_invalid", "unapproved stage path")
        require_same_flash(self.decision, validate_flash(observe_flash(self.transport), self.fit))
        # Compare the actual fresh report and staged file under the same remote
        # lock immediately before update. No caller-supplied shell fragments.
        script = (
            b"set -eu\n"
            + self._owns_lock()
            + b"observe() {\n"
            + OBSERVE_SCRIPT
            + b"}\n"
            + f"observe >{_LOCK}/observation\n".encode()
            + (
                f"test \"$(sha256sum {_LOCK}/observation | awk '{{print $1}}')\""
                f" = {self.decision.observation.report_sha256}\n"
                f"test \"$(sha256sum {shlex.quote(staged_path)} | awk '{{print $1}}')\""
                f" = {frm_sha256}\n"
                f"/sbin/update_frm.sh {shlex.quote(staged_path)}\n"
            ).encode()
        )
        # Persist uncertainty before command dispatch, including a lost response.
        _save(self.directory / "mutation-dispatched", b"unknown until verified\n")
        self.dispatched = True
        return self._run(script, timeout_s=180)

    def verify(self) -> None:
        self._run(b"set -eu\n" + self._owns_lock() + b"sync\n")
        written = self._read(3, len(self.fit))
        if written != self.fit:
            raise FlashSafetyError("flash_fit_changed", "FIT readback mismatch; do not reboot")
        after = self._protected()
        _save(
            self.directory / "integrity-observed.json",
            json.dumps(
                {
                    "protected_sha256": {
                        str(i): hashlib.sha256(b).hexdigest() for i, b in after.items()
                    },
                },
                sort_keys=True,
            ).encode(),
        )
        verify_protected(self.before, after, len(self.fit), opaque_padding=True)
        _save(
            self.directory / "integrity-verified.json",
            json.dumps(
                {
                    "fit_sha256": hashlib.sha256(written).hexdigest(),
                    "protected_sha256": {
                        str(i): hashlib.sha256(b).hexdigest() for i, b in after.items()
                    },
                },
                sort_keys=True,
            ).encode(),
        )
        self.verified = True

    def close(self) -> None:
        # Retain the remote lock after every uncertain mutation. A future process
        # cannot retry merely because the original process or SSH connection died.
        if self.locked and not self.dispatched:
            self._run(
                b"set -eu\n"
                + self._owns_lock()
                + f"rm -f {_LOCK}/owner {_LOCK}/observation\nrmdir {_LOCK}\n".encode()
            )
            self.locked = False
