"""Exact-radio SSH implementation of canonical Pluto+ setup.

The transport is deliberately narrower than a general remote shell: callers can
only request the fixed inspection, mute, backup, canonical environment write, and
reboot sequences defined in this module.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import subprocess
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Protocol, cast

from pluto_plus.doctor import CANONICAL_POLICY, CANONICAL_UBOOT
from pluto_plus.setup import (
    SetupExecutionResult,
    SetupExecutorFailure,
    SetupIdentity,
    SetupObservation,
    SetupPlan,
    SetupUnavailableError,
)

_SERIAL_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_INTERFACE_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,32}$")
_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class SetupHelperError(SetupUnavailableError):
    """The fixed helper could not safely inspect or provision the selected radio."""


class SetupTransport(Protocol):
    def run(
        self,
        command: str,
        *,
        stdin: bytes | None = None,
        timeout_s: float = 15,
    ) -> str: ...


class BoundSshTransport:
    """Password-authenticated OpenSSH bound to one USB network interface."""

    def __init__(
        self,
        *,
        host: str,
        interface: str | None,
        password: str,
        known_hosts_file: Path,
        username: str = "root",
        ssh_binary: str = "ssh",
    ) -> None:
        if interface is not None and not _INTERFACE_PATTERN.fullmatch(interface):
            raise ValueError("invalid USB network interface")
        try:
            address = ipaddress.ip_address(host)
        except ValueError as error:
            raise ValueError("SSH host must be a literal IP address") from error
        if address.version != 4 or not address.is_private:
            raise ValueError("SSH host must be a private IPv4 address")
        if username != "root":
            raise ValueError("canonical setup requires the radio root account")
        if not password:
            raise ValueError("radio SSH password cannot be empty")
        try:
            known_hosts_mode = known_hosts_file.stat().st_mode
        except OSError as error:
            raise ValueError("setup known-hosts file is not readable") from error
        if not known_hosts_file.is_file() or known_hosts_file.is_symlink():
            raise ValueError("setup known-hosts path must be a regular non-symlink file")
        if known_hosts_mode & 0o077:
            raise ValueError("setup known-hosts file must not be group/other accessible")
        self.host = host
        self.interface = interface
        self._password = password
        self._username = username
        self._ssh_binary = ssh_binary
        self._known_hosts_file = known_hosts_file

    def run(
        self,
        command: str,
        *,
        stdin: bytes | None = None,
        timeout_s: float = 15,
    ) -> str:
        if "\x00" in command or "\n" in command:
            raise SetupHelperError("invalid fixed SSH command")
        try:
            import pexpect
        except ImportError as error:  # pragma: no cover - composition guard
            raise SetupHelperError("Bound SSH setup requires pexpect") from error
        arguments = [
            "-o",
            "BatchMode=no",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={self._known_hosts_file}",
            f"{self._username}@{self.host}",
            command,
        ]
        if self.interface is not None:
            arguments[0:0] = ["-B", self.interface]
        child = pexpect.spawn(
            self._ssh_binary,
            arguments,
            encoding=None,
            timeout=timeout_s,
        )
        transcript = bytearray()
        try:
            while True:
                matched = child.expect(
                    [b"[Pp]assword:", pexpect.EOF, pexpect.TIMEOUT], timeout=timeout_s
                )
                transcript.extend(cast(bytes, child.before or b""))
                if matched == 0:
                    child.sendline(self._password.encode())
                    if stdin is not None:
                        child.send(stdin)
                        child.sendeof()
                        stdin = None
                    continue
                if matched == 1:
                    break
                raise SetupHelperError("radio SSH operation timed out")
        finally:
            child.close(force=True)
        exit_status = child.exitstatus
        signal_status = child.signalstatus
        output = bytes(transcript).decode(errors="replace").replace("\r", "")
        # A reboot intentionally tears down SSH before it can return a status.
        rebooting = "device_reboot reset" in command
        if not rebooting and (exit_status not in {0, None} or signal_status is not None):
            raise SetupHelperError(
                f"radio SSH operation failed ({exit_status=}, {signal_status=}): {output[-500:]}"
            )
        return output


class FixedSshSetupExecutor:
    """Inspect and apply the one immutable AD9361/2R2T policy."""

    def __init__(
        self,
        *,
        identity: SetupIdentity,
        transport: SetupTransport,
        state_root: Path,
        reenumeration_timeout_s: float = 45,
        poll_interval_s: float = 0.25,
    ) -> None:
        if not _SERIAL_PATTERN.fullmatch(identity.serial):
            raise ValueError("invalid radio serial")
        if reenumeration_timeout_s <= 0 or poll_interval_s <= 0:
            raise ValueError("timeouts must be positive")
        self.identity = identity
        self.transport = transport
        self.state_root = state_root
        self._reenumeration_timeout_s = reenumeration_timeout_s
        self._poll_interval_s = poll_interval_s

    def canonical_batch(self, changes: Mapping[str, str]) -> bytes:
        if not changes:
            raise SetupHelperError("canonical setup has no changes")
        if not set(changes).issubset(CANONICAL_UBOOT):
            raise SetupHelperError("setup requested an unsupported U-Boot key")
        ordered: list[str] = []
        for key, expected in CANONICAL_UBOOT.items():
            if key not in changes:
                continue
            if changes[key] != expected:
                raise SetupHelperError("setup requested a non-canonical U-Boot value")
            ordered.append(f"{key} {expected}\n")
        return "".join(ordered).encode()

    def inspect(self, identity: SetupIdentity | None = None) -> SetupObservation:
        expected = identity or self.identity
        if expected != self.identity:
            raise SetupHelperError("helper is bound to a different radio identity")
        self._attest_local_usb()
        command = f"sh -s -- {self.identity.serial} {CANONICAL_POLICY.fit_body_size}"
        output = self.transport.run(command, stdin=_INSPECT_SCRIPT, timeout_s=45)
        fields = _parse_report(output)
        if fields.get("serial") != self.identity.serial:
            raise SetupHelperError("remote gadget serial did not match selected radio")
        firmware = _required(fields, "firmware")
        observed_identity = SetupIdentity(
            serial=self.identity.serial,
            usb_sysfs_path=self.identity.usb_sysfs_path,
            observed_firmware=firmware,
        )
        uboot = {key: _nullable(fields.get(f"uboot_{key}")) for key in CANONICAL_UBOOT}
        scan_channels = tuple(
            sorted(item for item in fields.get("rx_scan_channels", "").split(",") if item)
        )
        tx_safe = _tx_safe(fields)
        qspi_digest = _required_digest(fields, "qspi_sha256")
        provenance = (
            "qspi_image_verified" if qspi_digest == CANONICAL_POLICY.fit_body_sha256 else "unknown"
        )
        return SetupObservation(
            identity=observed_identity,
            board_model=_required(fields, "board_model"),
            live_phy_model=_required(fields, "phy_model"),
            uboot=uboot,
            environment_sha256=_required_digest(fields, "environment_sha256"),
            versions_sha256=_required_digest(fields, "versions_sha256"),
            qspi_firmware_sha256=qspi_digest,
            boot_provenance=provenance,
            rx_scan_channels=scan_channels,
            tx_safe=tx_safe,
        )

    def provision(self, plan: SetupPlan) -> SetupExecutionResult:
        if plan.identity != self.identity:
            raise SetupHelperError("setup plan is bound to a different radio")
        if plan.profile_id != CANONICAL_POLICY.profile_id:
            raise SetupHelperError("setup plan selected an unsupported profile")
        before = self.inspect(plan.identity)
        if before != plan.before or before.environment_sha256 != plan.environment_sha256:
            raise SetupHelperError("radio state changed after setup planning")
        backup_path, backup_digest = self._write_backup(plan, before)
        completed_phases = ["preflight", "backup"]
        failure_phase = "tx_safety"
        mutation_attempted = False
        try:
            if not before.tx_safe:
                self._mute_transmit()
                muted = self.inspect(plan.identity)
                if not muted.tx_safe:
                    raise SetupHelperError("transmit path did not reach fail-closed state")
                if muted.environment_sha256 != plan.environment_sha256:
                    raise SetupHelperError("persistent environment changed while muting transmit")
            completed_phases.append("tx_safe")
            batch = self.canonical_batch(plan.changes)
            command = (
                "set -eu; "
                f'test "$(cat /sys/kernel/config/usb_gadget/composite_gadget/strings/0x409/'
                f'serialnumber)" = "{self.identity.serial}"; '
                "current=$(/usr/sbin/fw_printenv 2>/dev/null | LC_ALL=C sort | "
                "sha256sum | awk '{print $1}'); "
                f'test "$current" = "{plan.environment_sha256}"; '
                "/usr/sbin/fw_setenv --script -; /bin/sync; "
                "/usr/sbin/device_reboot reset"
            )
            failure_phase = "environment_write"
            mutation_attempted = True
            self.transport.run(command, stdin=batch, timeout_s=20)
            completed_phases.append("mutation_dispatched")
            failure_phase = "reboot_reenumeration"
            self._wait_for_reenumeration()
            completed_phases.append("reboot_observed")
            failure_phase = "post_reboot_attestation"
            deadline = time.monotonic() + self._reenumeration_timeout_s
            last_error: BaseException | None = None
            while time.monotonic() < deadline:
                try:
                    after = self.inspect(plan.identity)
                    after = after.model_copy(update={"boot_provenance": "qspi_reboot_verified"})
                    if not after.tx_safe:
                        self._mute_transmit()
                        after = self.inspect(plan.identity).model_copy(
                            update={"boot_provenance": "qspi_reboot_verified"}
                        )
                    return SetupExecutionResult(
                        observation=after,
                        backup_path=str(backup_path),
                        backup_sha256=backup_digest,
                        completed_phases=(*completed_phases, "post_reboot_attestation"),
                    )
                except BaseException as error:
                    last_error = error
                    time.sleep(self._poll_interval_s)
            raise SetupHelperError(f"radio did not become ready after reboot: {last_error}")
        except BaseException as error:
            raise SetupExecutorFailure(
                str(error),
                backup_path=str(backup_path),
                backup_sha256=backup_digest,
                failure_phase=failure_phase,
                completed_phases=tuple(completed_phases),
                reconciliation_required=mutation_attempted,
            ) from error

    def _mute_transmit(self) -> None:
        command = f"sh -s -- {self.identity.serial}"
        self.transport.run(command, stdin=_MUTE_SCRIPT, timeout_s=20)

    def _write_backup(self, plan: SetupPlan, observation: SetupObservation) -> tuple[Path, str]:
        command = f"sh -s -- {self.identity.serial}"
        report = _parse_report(self.transport.run(command, stdin=_BACKUP_SCRIPT, timeout_s=30))
        if report.get("serial") != self.identity.serial:
            raise SetupHelperError("backup source serial did not match selected radio")
        environment_hex = _required_hex(report, "environment_hex", maximum_bytes=256 * 1024)
        versions_hex = _required_hex(report, "versions_hex", maximum_bytes=64 * 1024)
        mtd1_sha256 = _required_digest(report, "mtd1_sha256")
        document = {
            "schema_version": 1,
            "plan_id": plan.plan_id,
            "identity": self.identity.model_dump(mode="json"),
            "observation": observation.model_dump(mode="json"),
            "environment": bytes.fromhex(environment_hex).decode(errors="replace"),
            "versions": bytes.fromhex(versions_hex).decode(errors="replace"),
            "mtd1_sha256": mtd1_sha256,
        }
        payload = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
        digest = hashlib.sha256(payload).hexdigest()
        directory = self.state_root / "setup" / "backups" / self.identity.serial
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(directory, 0o700)
        destination = directory / f"{plan.plan_id}.json"
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            destination.unlink(missing_ok=True)
            raise
        directory_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return destination, digest

    def _attest_local_usb(self) -> None:
        path = Path(self.identity.usb_sysfs_path)
        try:
            vendor = (path / "idVendor").read_text().strip().lower()
            product = (path / "idProduct").read_text().strip().lower()
            serial = (path / "serial").read_text().strip()
        except OSError as error:
            raise SetupHelperError("selected USB device is not attached") from error
        if (vendor, product, serial) != ("0456", "b673", self.identity.serial):
            raise SetupHelperError("selected USB path identity changed")

    def _wait_for_reenumeration(self) -> None:
        path = Path(self.identity.usb_sysfs_path)
        deadline = time.monotonic() + self._reenumeration_timeout_s
        disappeared = False
        while time.monotonic() < deadline:
            exists = path.exists()
            if not exists:
                disappeared = True
            elif disappeared:
                self._attest_local_usb()
                return
            time.sleep(self._poll_interval_s)
        raise SetupHelperError("selected USB path did not disappear and reappear after reboot")


def _parse_report(output: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in output.splitlines():
        if not line.startswith("PPU\t"):
            continue
        parts = line.split("\t", 2)
        if len(parts) != 3 or not parts[1] or parts[1] in fields:
            raise SetupHelperError("malformed or duplicate helper report field")
        fields[parts[1]] = parts[2]
    return fields


def _required(fields: Mapping[str, str], key: str) -> str:
    value = fields.get(key, "")
    if not value:
        raise SetupHelperError(f"helper report omitted {key}")
    return value


def _required_digest(fields: Mapping[str, str], key: str) -> str:
    value = _required(fields, key)
    if not _DIGEST_PATTERN.fullmatch(value):
        raise SetupHelperError(f"helper report contained an invalid {key}")
    return value


def _required_hex(fields: Mapping[str, str], key: str, *, maximum_bytes: int) -> str:
    value = fields.get(key, "")
    if len(value) % 2 or len(value) > maximum_bytes * 2 or not re.fullmatch(r"[0-9a-f]*", value):
        raise SetupHelperError(f"helper report contained an invalid {key}")
    return value


def _nullable(value: str | None) -> str | None:
    return value or None


def _csv_numbers(value: str) -> tuple[float, ...]:
    try:
        return tuple(float(item) for item in value.split(",") if item != "")
    except ValueError as error:
        raise SetupHelperError("invalid numeric TX safety report") from error


def _tx_safe(fields: Mapping[str, str]) -> bool:
    raws = _csv_numbers(_required(fields, "tx_dds_raw"))
    scales = _csv_numbers(_required(fields, "tx_dds_scale"))
    gains = _csv_numbers(_required(fields, "tx_hardwaregain_db"))
    buffers = _csv_numbers(_required(fields, "tx_buffer_enable"))
    available = _csv_numbers(_required(fields, "tx_data_available"))
    scans = _csv_numbers(_required(fields, "tx_scan_enable"))
    return (
        len(raws) == 8
        and all(value == 0 for value in raws)
        and len(scales) == 8
        and all(value == 0 for value in scales)
        and len(gains) == 2
        and all(value <= -80 for value in gains)
        and buffers == (0,)
        and available == (0,)
        and len(scans) == 4
        and all(value == 0 for value in scans)
    )


_INSPECT_SCRIPT = rb"""set -eu
serial_expected="$1"
fit_size="$2"
serial=$(cat /sys/kernel/config/usb_gadget/composite_gadget/strings/0x409/serialnumber)
[ "$serial" = "$serial_expected" ]
emit() { printf 'PPU\t%s\t%s\n' "$1" "$2"; }
emit serial "$serial"
emit board_model "$(tr '\000' '\n' </proc/device-tree/model | head -n1)"
emit firmware "$(awk '$1 == "device-fw" {print $2; exit}' /opt/VERSIONS)"
emit versions_sha256 "$(sha256sum /opt/VERSIONS | awk '{print $1}')"
env_sorted=$(mktemp)
trap 'rm -f "$env_sorted"' EXIT
/usr/sbin/fw_printenv 2>/dev/null | LC_ALL=C sort >"$env_sorted"
emit environment_sha256 "$(sha256sum "$env_sorted" | awk '{print $1}')"
for key in attr_name attr_val compatible mode; do
  value=$(/usr/sbin/fw_printenv -n "$key" 2>/dev/null || true)
  emit "uboot_$key" "$value"
done
qspi_sha=$(dd if=/dev/mtd3 bs="$fit_size" count=1 2>/dev/null | sha256sum)
emit qspi_sha256 "${qspi_sha%% *}"
compatible_path=/proc/device-tree/amba/spi@e0006000/ad9361-phy@0/compatible
compatible=$(tr '\000' '\n' <"$compatible_path" 2>/dev/null | head -n1 || true)
emit phy_model "${compatible#adi,}"
rx=''
for d in /sys/bus/iio/devices/iio:device*; do
  [ "$(cat "$d/name" 2>/dev/null || true)" = cf-ad9361-lpc ] || continue
  for f in "$d"/scan_elements/in_voltage[0-3]_en; do
    [ -e "$f" ] || continue
    channel=$(basename "$f" | sed -n 's/^in_\(voltage[0-3]\)_en$/\1/p')
    case ",$rx," in *,$channel,*) ;; *) rx="${rx}${rx:+,}$channel";; esac
  done
done
emit rx_scan_channels "$rx"
dds=''; scales=''; buffers=''; available=''; scans=''
for d in /sys/bus/iio/devices/iio:device*; do
  [ "$(cat "$d/name" 2>/dev/null || true)" = cf-ad9361-dds-core-lpc ] || continue
  for f in "$d"/out_altvoltage*_raw; do [ -e "$f" ] && dds="${dds}${dds:+,}$(cat "$f")"; done
  for f in "$d"/out_altvoltage*_scale; do
    [ -e "$f" ] && scales="${scales}${scales:+,}$(cat "$f")"
  done
  buffers="$(cat "$d/buffer/enable")"
  available="$(cat "$d/buffer/data_available")"
  for f in "$d"/scan_elements/out_voltage[0-3]_en; do
    [ -e "$f" ] && scans="${scans}${scans:+,}$(cat "$f")"
  done
done
gains=''
for f in /sys/bus/iio/devices/iio:device*/out_voltage[01]_hardwaregain; do
  [ -e "$f" ] && gains="${gains}${gains:+,}$(cat "$f" | awk '{print $1}')"
done
emit tx_dds_raw "$dds"
emit tx_dds_scale "$scales"
emit tx_hardwaregain_db "$gains"
emit tx_buffer_enable "$buffers"
emit tx_data_available "$available"
emit tx_scan_enable "$scans"
"""

_MUTE_SCRIPT = rb"""set -eu
serial_expected="$1"
serial=$(cat /sys/kernel/config/usb_gadget/composite_gadget/strings/0x409/serialnumber)
[ "$serial" = "$serial_expected" ]
phy=''; dds=''
for d in /sys/bus/iio/devices/iio:device*; do
  case "$(cat "$d/name" 2>/dev/null || true)" in
    ad9361-phy) phy="$d" ;;
    cf-ad9361-dds-core-lpc) dds="$d" ;;
  esac
done
[ -n "$phy" ] && [ -n "$dds" ]
printf '%s\n' -80 >"$phy/out_voltage0_hardwaregain"
printf '%s\n' -80 >"$phy/out_voltage1_hardwaregain"
printf '%s\n' 0 >"$dds/buffer/enable"
for f in "$dds"/scan_elements/out_voltage[0-3]_en; do
  [ -e "$f" ] && printf '%s\n' 0 >"$f"
done
for f in "$dds"/out_altvoltage*_scale; do printf '%s\n' 0 >"$f"; done
for f in "$dds"/out_altvoltage*_raw; do printf '%s\n' 0 >"$f"; done
/bin/sync
"""

_BACKUP_SCRIPT = rb"""set -eu
serial_expected="$1"
serial=$(cat /sys/kernel/config/usb_gadget/composite_gadget/strings/0x409/serialnumber)
[ "$serial" = "$serial_expected" ]
emit() { printf 'PPU\t%s\t%s\n' "$1" "$2"; }
emit serial "$serial"
emit environment_hex "$(/usr/sbin/fw_printenv 2>/dev/null | od -An -tx1 -v | tr -d ' \n')"
emit versions_hex "$(od -An -tx1 -v /opt/VERSIONS | tr -d ' \n')"
emit mtd1_sha256 "$(sha256sum /dev/mtd1 | awk '{print $1}')"
"""


def validate_bound_interface(
    interface: str,
    usb_sysfs_path: str,
    *,
    net_root: Path = Path("/sys/class/net"),
) -> None:
    """Prove that the selected network interface belongs to the selected USB device."""

    if not _INTERFACE_PATTERN.fullmatch(interface):
        raise SetupHelperError("invalid USB network interface")
    try:
        device = (net_root / interface / "device").resolve(strict=True)
        usb = Path(usb_sysfs_path).resolve(strict=True)
    except OSError as error:
        raise SetupHelperError("USB network interface is not attached") from error
    if usb != device and usb not in device.parents:
        raise SetupHelperError("USB network interface does not belong to selected radio")


def remote_ssh_available() -> bool:
    return (
        subprocess.run(
            ["ssh", "-V"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False
        ).returncode
        == 0
    )
