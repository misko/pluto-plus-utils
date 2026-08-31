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
import stat
import subprocess
import tempfile
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Protocol, cast

from pluto_plus.doctor import (
    CANONICAL_POLICY,
    CANONICAL_UBOOT,
    require_setup_inspection_policy,
    require_setup_repair_policy,
)
from pluto_plus.ip_firmware import (
    UsbSshRouteAmbiguous,
    require_unambiguous_usb_ssh_route,
)
from pluto_plus.models import FirmwarePolicy
from pluto_plus.setup import (
    SetupExecutionResult,
    SetupExecutorFailure,
    SetupHostKeyRotation,
    SetupIdentity,
    SetupObservation,
    SetupPlan,
    SetupUnavailableError,
    observation_functional_probe_available,
    observation_functionally_qualified,
)
from pluto_plus.setup_profiles import (
    RX_LO_5G8_HZ,
    SETUP_ENVIRONMENT_PROFILES,
    SetupEnvironmentProfile,
    environment_profile_for_uboot,
    environment_profiles_for_firmware,
)

_SERIAL_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_INTERFACE_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,32}$")
_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class SetupHelperError(SetupUnavailableError):
    """The fixed helper could not safely inspect or provision the selected radio."""


class SetupSshHostKeyChangedError(SetupHelperError):
    """Pinned SSH trust changed; callers must use an independent trust anchor."""


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
        route_preflight: Callable[[], None] | None = None,
        usb_identity_checker: Callable[[str, Path], None] | None = None,
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
        selected_route_preflight = route_preflight or (
            (lambda: _require_usb_ssh_route(interface, host))
            if interface is not None
            else (lambda: None)
        )
        try:
            selected_route_preflight()
        except SetupHelperError as error:
            raise ValueError(str(error)) from error
        self.host = host
        self.interface = interface
        self._password = password
        self._username = username
        self._ssh_binary = ssh_binary
        self._known_hosts_file = known_hosts_file
        self._route_preflight = selected_route_preflight
        self._usb_identity_checker = usb_identity_checker or _attest_usb_identity
        self._known_hosts_sha256 = _private_known_hosts_sha256(known_hosts_file)

    def run(
        self,
        command: str,
        *,
        stdin: bytes | None = None,
        timeout_s: float = 15,
    ) -> str:
        self._route_preflight()
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
            "PasswordAuthentication=yes",
            "-o",
            "PubkeyAuthentication=no",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={self._known_hosts_file}",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
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
        if "REMOTE HOST IDENTIFICATION HAS CHANGED" in output:
            raise SetupSshHostKeyChangedError("pinned radio SSH host key changed after reboot")
        # A reboot intentionally tears down SSH before it can return a status.
        rebooting = "/usr/sbin/device_reboot " in command
        if not rebooting and (exit_status not in {0, None} or signal_status is not None):
            raise SetupHelperError(
                f"radio SSH operation failed ({exit_status=}, {signal_status=}): {output[-500:]}"
            )
        return output

    def reenroll_after_attested_usb_reboot(
        self,
        *,
        serial: str,
        usb_sysfs_path: Path,
        timeout_s: float = 15,
    ) -> SetupHostKeyRotation:
        """Replace a rotated key only through the exact USB-bound endpoint.

        This is deliberately unavailable for LAN-routed setup. The caller must
        first have observed the selected USB topology disappear and return; this
        method then repeats local serial/path and route attestation before using
        accept-new against only that physically bound USB interface.
        """

        if self.host != "192.168.2.1" or self.interface is None:
            raise SetupHelperError(
                "automatic post-reboot SSH key enrollment requires the exact USB endpoint"
            )
        self._route_preflight()
        self._usb_identity_checker(serial, usb_sysfs_path)
        previous = _private_known_hosts_bytes(self._known_hosts_file)
        previous_sha256 = hashlib.sha256(previous).hexdigest()
        if previous_sha256 != self._known_hosts_sha256:
            raise SetupHelperError("setup known-hosts changed after transport creation")
        previous_fingerprint = _known_hosts_fingerprint(self._known_hosts_file)

        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{self._known_hosts_file.name}.replacement.",
            dir=self._known_hosts_file.parent,
        )
        os.close(descriptor)
        temporary = Path(temporary_name)
        temporary.chmod(0o600)
        try:
            output = self._enroll_replacement_key(
                temporary,
                serial=serial,
                timeout_s=timeout_s,
            )
            serials = [
                line.removeprefix("serial=").strip()
                for line in output.splitlines()
                if line.startswith("serial=")
            ]
            if serials != [serial]:
                observed = serials[0] if len(serials) == 1 else None
                raise SetupHelperError(
                    "USB-bound replacement SSH key attested serial "
                    f"{observed!r}, expected {serial!r}"
                )
            replacement = _private_known_hosts_bytes(temporary)
            replacement_sha256 = hashlib.sha256(replacement).hexdigest()
            if replacement_sha256 == previous_sha256:
                raise SetupHelperError("post-reboot SSH host key did not change")
            replacement_fingerprint = _known_hosts_fingerprint(temporary)
            backup = self._known_hosts_file.with_name(
                f"{self._known_hosts_file.name}.pre-reboot-{previous_sha256[:12]}"
            )
            _write_private_exclusive(backup, previous)
            temporary.replace(self._known_hosts_file)
            _fsync_directory(self._known_hosts_file.parent)
            self._known_hosts_sha256 = replacement_sha256
            return SetupHostKeyRotation(
                previous_known_hosts_sha256=previous_sha256,
                replacement_known_hosts_sha256=replacement_sha256,
                previous_fingerprint=previous_fingerprint,
                replacement_fingerprint=replacement_fingerprint,
                previous_known_hosts_backup=str(backup),
            )
        finally:
            temporary.unlink(missing_ok=True)

    def _enroll_replacement_key(
        self,
        known_hosts_file: Path,
        *,
        serial: str,
        timeout_s: float,
    ) -> str:
        try:
            import pexpect
        except ImportError as error:  # pragma: no cover - composition guard
            raise SetupHelperError("Bound SSH setup requires pexpect") from error
        command = (
            "printf 'serial=%s\\n' \"$(cat /sys/kernel/config/usb_gadget/"
            'composite_gadget/strings/0x409/serialnumber)"'
        )
        arguments = [
            "-B",
            cast(str, self.interface),
            "-o",
            "BatchMode=no",
            "-o",
            "PasswordAuthentication=yes",
            "-o",
            "PubkeyAuthentication=no",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            f"UserKnownHostsFile={known_hosts_file}",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            f"{self._username}@{self.host}",
            command,
        ]
        child = pexpect.spawn(
            self._ssh_binary,
            arguments,
            encoding=None,
            timeout=timeout_s,
        )
        transcript = bytearray()
        password_sent = False
        try:
            while True:
                matched = child.expect(
                    [b"[Pp]assword:", pexpect.EOF, pexpect.TIMEOUT], timeout=timeout_s
                )
                transcript.extend(cast(bytes, child.before or b""))
                if matched == 0:
                    if password_sent:
                        raise SetupHelperError("replacement SSH key authentication failed")
                    child.sendline(self._password.encode())
                    password_sent = True
                    continue
                if matched == 1:
                    break
                raise SetupHelperError("replacement SSH key enrollment timed out")
        finally:
            child.close(force=True)
        output = bytes(transcript).decode(errors="replace").replace("\r", "")
        if child.exitstatus != 0 or child.signalstatus is not None:
            raise SetupHelperError(
                "replacement SSH key enrollment failed "
                f"({child.exitstatus=}, {child.signalstatus=}): {output[-500:]}"
            )
        return output


def _require_usb_ssh_route(interface: str, host: str) -> None:
    try:
        require_unambiguous_usb_ssh_route(interface, host)
    except UsbSshRouteAmbiguous as error:
        raise SetupHelperError(str(error)) from error


class FixedSshSetupExecutor:
    """Inspect and apply the one immutable AD9361/2R2T policy."""

    def __init__(
        self,
        *,
        identity: SetupIdentity,
        transport: SetupTransport,
        state_root: Path,
        policy: FirmwarePolicy = CANONICAL_POLICY,
        mutation_allowed: bool = True,
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
        self._policy = (
            require_setup_repair_policy(policy)
            if mutation_allowed
            else require_setup_inspection_policy(policy)
        )
        self._mutation_allowed = mutation_allowed
        self._reenumeration_timeout_s = reenumeration_timeout_s
        self._poll_interval_s = poll_interval_s

    def canonical_batch(self, changes: Mapping[str, str | None]) -> bytes:
        """Encode a subset of exactly one shipped environment profile."""

        if not changes:
            raise SetupHelperError("setup environment profile has no changes")
        if not set(changes).issubset(CANONICAL_UBOOT):
            raise SetupHelperError("setup requested an unsupported U-Boot key")
        matching_profiles = tuple(
            profile
            for profile in SETUP_ENVIRONMENT_PROFILES
            if all(profile.uboot[key] == expected for key, expected in changes.items())
        )
        if not matching_profiles:
            raise SetupHelperError("setup requested values outside the bounded profiles")
        ordered: list[str] = []
        for key, expected in CANONICAL_UBOOT.items():
            if key not in changes:
                continue
            expected = changes[key]
            # fw_setenv --script deletes a variable when the line carries no value.
            ordered.append(f"{key}\n" if expected is None else f"{key} {expected}\n")
        return "".join(ordered).encode()

    def inspect(self, identity: SetupIdentity | None = None) -> SetupObservation:
        expected = identity or self.identity
        if expected != self.identity:
            raise SetupHelperError("helper is bound to a different radio identity")
        self._attest_local_usb()
        command = f"sh -s -- {self.identity.serial} {self._policy.fit_body_size}"
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
            "qspi_image_verified" if qspi_digest == self._policy.fit_body_sha256 else "unknown"
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
            tx_hardwaregain_db=_csv_numbers(fields.get("tx_hardwaregain_db", "")),
            rx_lo_5g8_accepted=_optional_bool(fields.get("rx_lo_5g8_accepted")),
            rx_lo_5g8_readback_hz=_optional_int(fields.get("rx_lo_5g8_readback_hz")),
            rx_lo_restored=_optional_bool(fields.get("rx_lo_restored")),
            rx_buffer_active=_optional_bool(fields.get("rx_buffer_active")),
            rx_lo_probe_tx_safe=_optional_bool(fields.get("rx_lo_probe_tx_safe")),
            rx_lo_probe_gain_count=_optional_nonnegative_int(
                fields.get("rx_lo_probe_gain_count")
            ),
            rx_lo_probe_dds_count=_optional_nonnegative_int(
                fields.get("rx_lo_probe_dds_count")
            ),
            rx_lo_probe_gains_safe=_optional_bool(fields.get("rx_lo_probe_gains_safe")),
            rx_lo_probe_dds_safe=_optional_bool(fields.get("rx_lo_probe_dds_safe")),
        )

    def provision(self, plan: SetupPlan) -> SetupExecutionResult:
        if not self._mutation_allowed:
            raise SetupHelperError("read-only setup inspection cannot provision U-Boot")
        if plan.identity != self.identity:
            raise SetupHelperError("setup plan is bound to a different radio")
        if plan.profile_id != self._policy.profile_id:
            raise SetupHelperError("setup plan selected an unsupported profile")
        before = self.inspect(plan.identity)
        if before != plan.before or before.environment_sha256 != plan.environment_sha256:
            raise SetupHelperError("radio state changed after setup planning")
        backup_path, backup_digest = self._write_backup(plan, before)
        completed_phases = ["preflight", "backup"]
        failure_phase = "tx_safety"
        mutation_attempted = False
        host_key_rotation: SetupHostKeyRotation | None = None
        last_observation: SetupObservation | None = before
        try:
            current = before
            if not before.tx_safe:
                self._mute_transmit()
                muted = self.inspect(plan.identity)
                if not muted.tx_safe:
                    raise SetupHelperError("transmit path did not reach fail-closed state")
                if muted.environment_sha256 != plan.environment_sha256:
                    raise SetupHelperError("persistent environment changed while muting transmit")
                current = muted
            completed_phases.append("tx_safe")
            candidates = self._environment_candidates(plan)
            for attempt, profile in enumerate(candidates, start=1):
                changes = {
                    key: expected
                    for key, expected in profile.uboot.items()
                    if current.uboot.get(key) != expected
                }
                if attempt == 1 and changes != plan.changes:
                    raise SetupHelperError("setup plan does not match its primary profile")
                if not changes:
                    continue
                batch = self.canonical_batch(changes)
                command = (
                    "set -eu; "
                    f'test "$(cat /sys/kernel/config/usb_gadget/composite_gadget/strings/0x409/'
                    f'serialnumber)" = "{self.identity.serial}"; '
                    "current=$(/usr/sbin/fw_printenv 2>/dev/null | LC_ALL=C sort | "
                    "sha256sum | awk '{print $1}'); "
                    f'test "$current" = "{current.environment_sha256}"; '
                    "/usr/sbin/fw_setenv --script -; /bin/sync; "
                    "/usr/sbin/device_reboot reset"
                )
                failure_phase = f"environment_write:{profile.profile_id}"
                mutation_attempted = True
                self.transport.run(command, stdin=batch, timeout_s=20)
                completed_phases.append(f"mutation_dispatched:{profile.profile_id}")
                failure_phase = f"reboot_reenumeration:{profile.profile_id}"
                self._wait_for_reenumeration()
                completed_phases.append(f"reboot_observed:{profile.profile_id}")
                failure_phase = f"post_reboot_attestation:{profile.profile_id}"
                deadline = time.monotonic() + self._reenumeration_timeout_s
                last_error: BaseException | None = None
                after: SetupObservation | None = None
                while time.monotonic() < deadline:
                    try:
                        observed = self.inspect(plan.identity).model_copy(
                            update={"boot_provenance": "qspi_reboot_verified"}
                        )
                        if not observed.tx_safe:
                            self._mute_transmit()
                            observed = self.inspect(plan.identity).model_copy(
                                update={"boot_provenance": "qspi_reboot_verified"}
                            )
                        last_observation = observed
                        if not observation_functional_probe_available(observed):
                            last_error = SetupHelperError(
                                "5.8 GHz RX LO probe remained unavailable while waiting "
                                "for an idle radio"
                            )
                            time.sleep(self._poll_interval_s)
                            continue
                        after = observed
                        break
                    except SetupSshHostKeyChangedError as error:
                        last_error = error
                        reenroll = getattr(
                            self.transport,
                            "reenroll_after_attested_usb_reboot",
                            None,
                        )
                        if not callable(reenroll):
                            break
                        host_key_rotation = reenroll(
                            serial=self.identity.serial,
                            usb_sysfs_path=Path(self.identity.usb_sysfs_path),
                            timeout_s=self._reenumeration_timeout_s,
                        )
                        completed_phases.append("ssh_host_key_reenrolled")
                    except BaseException as error:
                        last_error = error
                        time.sleep(self._poll_interval_s)
                if after is None:
                    raise SetupHelperError(
                        f"radio did not become ready after reboot: {last_error}"
                    )
                current = after
                last_observation = after
                completed_phases.append(f"post_reboot_attestation:{profile.profile_id}")
                if (
                    environment_profile_for_uboot(after.uboot) is not None
                    and observation_functionally_qualified(after)
                ):
                    return SetupExecutionResult(
                        observation=after,
                        backup_path=str(backup_path),
                        backup_sha256=backup_digest,
                        completed_phases=tuple(completed_phases),
                        host_key_rotation=host_key_rotation,
                    )
                completed_phases.append(f"functional_probe_failed:{profile.profile_id}")
            raise SetupHelperError(
                "neither bounded U-Boot profile returned dual RX with an accepted and "
                f"restored {RX_LO_5G8_HZ} Hz RX LO"
            )
        except BaseException as error:
            raise SetupExecutorFailure(
                str(error),
                backup_path=str(backup_path),
                backup_sha256=backup_digest,
                failure_phase=failure_phase,
                completed_phases=tuple(completed_phases),
                reconciliation_required=mutation_attempted,
                host_key_rotation=host_key_rotation,
                after=last_observation,
            ) from error

    @staticmethod
    def _environment_candidates(
        plan: SetupPlan,
    ) -> tuple[SetupEnvironmentProfile, SetupEnvironmentProfile]:
        primary_values = dict(plan.before.uboot)
        primary_values.update(plan.changes)
        primary = environment_profile_for_uboot(primary_values)
        if primary is None:
            raise SetupHelperError("setup plan does not produce a bounded environment profile")
        ordered = environment_profiles_for_firmware(plan.identity.observed_firmware)
        secondary = next(profile for profile in ordered if profile != primary)
        return primary, secondary

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


def _optional_bool(value: str | None) -> bool | None:
    if value in {None, ""}:
        return None
    if value not in {"0", "1"}:
        raise SetupHelperError("helper report contained an invalid boolean")
    return value == "1"


def _optional_int(value: str | None) -> int | None:
    if value in {None, ""}:
        return None
    try:
        parsed = int(value)
    except ValueError as error:
        raise SetupHelperError("helper report contained an invalid integer") from error
    if parsed <= 0:
        raise SetupHelperError("helper report contained a non-positive integer")
    return parsed


def _optional_nonnegative_int(value: str | None) -> int | None:
    if value in {None, ""}:
        return None
    try:
        parsed = int(value)
    except ValueError as error:
        raise SetupHelperError("helper report contained an invalid integer") from error
    if parsed < 0:
        raise SetupHelperError("helper report contained a negative integer")
    return parsed


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
    # A 1R1T radio reports exactly half of every 2R2T count, and canonical
    # setup runs on a 1R1T radio by definition -- so requiring the 2R2T shape
    # here makes the fail-closed check unsatisfiable on the only hardware that
    # needs the procedure. Accept either shape, keyed on the number of
    # transmitters actually present, and keep every present value strictly
    # muted. The post-conversion call lands on the 2R2T row because the radio
    # really does have two transmitters by then.
    tx_shapes = {1: (4, 4, 2), 2: (8, 8, 4)}  # transmitters -> raw, scale, scan
    expected = tx_shapes.get(len(gains))
    return (
        expected is not None
        and (len(raws), len(scales), len(scans)) == expected
        and all(value == 0 for value in raws)
        and all(value == 0 for value in scales)
        and all(value <= -80 for value in gains)
        and buffers == (0,)
        and available == (0,)
        and all(value == 0 for value in scans)
    )


def _private_known_hosts_bytes(path: Path) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise SetupHelperError("setup known-hosts file is not readable") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise SetupHelperError("setup known-hosts must be a regular non-symlink file")
    if metadata.st_mode & 0o077:
        raise SetupHelperError("setup known-hosts file must be private")
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise SetupHelperError("setup known-hosts file is not readable") from error
    if not payload or len(payload) > 1024 * 1024:
        raise SetupHelperError("setup known-hosts file is empty or too large")
    return payload


def _private_known_hosts_sha256(path: Path) -> str:
    return hashlib.sha256(_private_known_hosts_bytes(path)).hexdigest()


def _known_hosts_fingerprint(path: Path) -> str:
    try:
        completed = subprocess.run(
            ("ssh-keygen", "-lf", str(path), "-E", "sha256"),
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SetupHelperError(f"cannot fingerprint setup SSH host key: {error}") from error
    fingerprint = completed.stdout.strip()
    if completed.returncode != 0 or not fingerprint:
        raise SetupHelperError("setup known-hosts does not contain a valid SSH host key")
    return fingerprint


def _attest_usb_identity(serial: str, usb_sysfs_path: Path) -> None:
    if not _SERIAL_PATTERN.fullmatch(serial):
        raise SetupHelperError("invalid expected USB serial")
    if not re.fullmatch(r"/sys/bus/usb/devices/[^/]+", str(usb_sysfs_path)):
        raise SetupHelperError("invalid expected USB sysfs path")
    try:
        vendor = (usb_sysfs_path / "idVendor").read_text().strip().lower()
        product = (usb_sysfs_path / "idProduct").read_text().strip().lower()
        observed_serial = (usb_sysfs_path / "serial").read_text().strip()
    except OSError as error:
        raise SetupHelperError("selected USB device is not attached") from error
    if (vendor, product, observed_serial) != ("0456", "b673", serial):
        raise SetupHelperError("selected USB path identity changed")


def _write_private_exclusive(path: Path, payload: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


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
phy=''; rx=''; rx_buffer_active=0
for d in /sys/bus/iio/devices/iio:device*; do
  case "$(cat "$d/name" 2>/dev/null || true)" in
    ad9361-phy) phy="$d" ;;
    cf-ad9361-lpc)
      [ "$(cat "$d/buffer/enable" 2>/dev/null || printf 1)" = 0 ] || rx_buffer_active=1
      for f in "$d"/scan_elements/in_voltage[0-3]_en; do
        [ -e "$f" ] || continue
        channel=$(basename "$f" | sed -n 's/^in_\(voltage[0-3]\)_en$/\1/p')
        case ",$rx," in *,$channel,*) ;; *) rx="${rx}${rx:+,}$channel";; esac
      done
      ;;
  esac
done
emit rx_scan_channels "$rx"
lo_target=5800000000
lo_readback=''; lo_accepted=''; lo_restored=''
tx_safe_for_lo=1; gain_count=0; dds_count=0; gains_safe=1; dds_safe=1
if [ -n "$phy" ]; then
  for f in "$phy"/out_voltage[0-9]_hardwaregain; do
    [ -e "$f" ] || continue
    gain_count=$((gain_count + 1))
    if ! awk -v value="$(awk '{print $1}' "$f")" 'BEGIN { exit !(value <= -80) }'; then
      tx_safe_for_lo=0; gains_safe=0
    fi
  done
else
  tx_safe_for_lo=0; gains_safe=0
fi
for d in /sys/bus/iio/devices/iio:device*; do
  [ "$(cat "$d/name" 2>/dev/null || true)" = cf-ad9361-dds-core-lpc ] || continue
  dds_count=$((dds_count + 1))
  if [ "$(cat "$d/buffer/enable" 2>/dev/null || printf 1)" != 0 ]; then
    tx_safe_for_lo=0; dds_safe=0
  fi
  for f in "$d"/out_altvoltage*_raw "$d"/out_altvoltage*_scale \
      "$d"/scan_elements/out_voltage[0-3]_en; do
    [ -e "$f" ] || continue
    if ! awk -v value="$(cat "$f")" 'BEGIN { exit !(value == 0) }'; then
      tx_safe_for_lo=0; dds_safe=0
    fi
  done
done
[ "$gain_count" -gt 0 ] || { tx_safe_for_lo=0; gains_safe=0; }
[ "$dds_count" -gt 0 ] || { tx_safe_for_lo=0; dds_safe=0; }
emit rx_buffer_active "$rx_buffer_active"
emit rx_lo_probe_tx_safe "$tx_safe_for_lo"
emit rx_lo_probe_gain_count "$gain_count"
emit rx_lo_probe_dds_count "$dds_count"
emit rx_lo_probe_gains_safe "$gains_safe"
emit rx_lo_probe_dds_safe "$dds_safe"
if [ "$rx_buffer_active" = 0 ] && [ "$tx_safe_for_lo" = 1 ] && [ -n "$phy" ]; then
  lo_path="$phy/out_altvoltage0_RX_LO_frequency"
  if [ -e "$lo_path" ]; then
    lo_original=$(cat "$lo_path")
    lo_accepted=0
    if printf '%s\n' "$lo_target" >"$lo_path" 2>/dev/null; then
      lo_readback=$(cat "$lo_path")
      [ "$lo_readback" = "$lo_target" ] && lo_accepted=1
    fi
    delta=0; restored=0
    while [ "$delta" -le 32 ] && [ "$restored" = 0 ]; do
      if [ "$delta" = 0 ]; then
        candidates="$lo_original"
      else
        candidates="$((lo_original + delta)) $((lo_original - delta))"
      fi
      for candidate in $candidates; do
        printf '%s\n' "$candidate" >"$lo_path" 2>/dev/null || continue
        if [ "$(cat "$lo_path")" = "$lo_original" ]; then restored=1; break; fi
      done
      delta=$((delta + 1))
    done
    [ "$restored" = 1 ]
    lo_restored=1
  fi
fi
emit rx_lo_5g8_target_hz "$lo_target"
emit rx_lo_5g8_readback_hz "$lo_readback"
emit rx_lo_5g8_accepted "$lo_accepted"
emit rx_lo_restored "$lo_restored"
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
for f in "$phy"/out_voltage[0-9]_hardwaregain; do
  [ -e "$f" ] || continue
  printf '%s\n' -80 >"$f"
done
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
