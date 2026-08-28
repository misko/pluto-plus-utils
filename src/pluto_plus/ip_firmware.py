"""Fail-closed persistent Pluto firmware updates over pinned SSH.

The public transport is intentionally an operation API, not a remote-shell API.
Only the concrete implementation in this module owns command strings, and every
remote path and mutating program is fixed.  In particular, callers cannot select
an MTD device or substitute an updater command.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import os
import re
import stat
import subprocess
import tempfile
import time
import uuid
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Protocol

from pluto_plus.firmware import (
    FIT_MAGIC,
    FirmwareError,
    FirmwareExecutorFailure,
    RadioFirmwareIdentity,
    validate_frm,
)
from pluto_plus.network_config import (
    NETWORK_KEYS,
    NetworkConfigExecutionResult,
    NetworkConfigIdentity,
    NetworkConfigObservation,
    NetworkConfigPlan,
    persistent_environment_sha256,
)

_SERIAL_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_FINGERPRINT_RE = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_REMOTE_STAGE = "/root/.pluto-plus-ip-firmware/pluto.frm"
_FAILED_RE = re.compile(r"\bFailed\b")
_DONE_RE = re.compile(r"(?m)^Done$")


class IpFirmwareError(FirmwareError):
    """The fixed IP firmware boundary rejected or could not complete an operation."""


class IpFirmwareHostKeyChanged(IpFirmwareError):
    """The enrolled SSH host key no longer authenticates the endpoint."""


class UsbSshRouteAmbiguous(IpFirmwareError):
    """The host cannot prove that a USB-bound SSH endpoint uses one interface."""


@dataclass(frozen=True, slots=True)
class UsbSshRouteObservation:
    """Minimal read-only host routing facts used by the USB SSH safety gate."""

    interface_addresses: tuple[tuple[str, tuple[str, ...]], ...]
    destination_routes: tuple[tuple[str, str], ...]


IpJsonReader = Callable[[Sequence[str]], str]


def require_unambiguous_usb_ssh_route(
    interface: str,
    endpoint: str,
    *,
    ip_json_reader: IpJsonReader | None = None,
) -> UsbSshRouteObservation:
    """Refuse USB-bound SSH unless one interface uniquely owns the path.

    OpenSSH ``BindInterface`` selects a local interface/address, but that is not
    physical endpoint isolation when multiple USB gadgets expose identical host
    addresses and destination subnets.  This read-only gate intentionally does
    not alter policy routing or network namespaces.
    """

    if not interface or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", interface):
        raise UsbSshRouteAmbiguous("USB-bound SSH requires one valid interface name")
    try:
        target = ipaddress.ip_address(endpoint)
    except ValueError as error:
        raise UsbSshRouteAmbiguous("USB-bound SSH endpoint must be a literal IP address") from error
    if target.version != 4:
        raise UsbSshRouteAmbiguous("USB-bound SSH route isolation currently requires IPv4")

    reader = ip_json_reader or _read_ip_json
    try:
        addresses_document = json.loads(reader(("ip", "-j", "-4", "address", "show")))
        routes_document = json.loads(
            reader(("ip", "-j", "-4", "route", "show", "table", "all"))
        )
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        raise UsbSshRouteAmbiguous(
            f"cannot verify USB-bound SSH routing for {interface}: {error}"
        ) from error
    if not isinstance(addresses_document, list) or not isinstance(routes_document, list):
        raise UsbSshRouteAmbiguous("cannot verify USB-bound SSH routing: malformed ip JSON")

    interface_addresses: list[tuple[str, tuple[str, ...]]] = []
    addresses_by_interface: dict[str, tuple[str, ...]] = {}
    for item in addresses_document:
        if not isinstance(item, dict) or not isinstance(item.get("ifname"), str):
            continue
        values = tuple(
            str(info["local"])
            for info in item.get("addr_info", ())
            if isinstance(info, dict)
            and info.get("family") == "inet"
            and isinstance(info.get("local"), str)
        )
        addresses_by_interface[item["ifname"]] = values
        interface_addresses.append((item["ifname"], values))

    selected_addresses = addresses_by_interface.get(interface, ())
    if not selected_addresses:
        raise UsbSshRouteAmbiguous(
            f"USB-bound SSH interface {interface!r} has no observed IPv4 address"
        )
    duplicates = sorted(
        (name, address)
        for name, values in addresses_by_interface.items()
        if name != interface
        for address in set(selected_addresses).intersection(values)
    )
    if duplicates:
        detail = ", ".join(f"{address} on {name}" for name, address in duplicates)
        raise UsbSshRouteAmbiguous(
            f"USB-bound SSH interface {interface!r} is ambiguous: its source address is also "
            f"configured as {detail}. Disconnect the other Pluto USB network interfaces or "
            "assign unique USB host/radio addresses; BindInterface alone is not endpoint isolation."
        )

    destination_routes: list[tuple[str, str]] = []
    covering: list[tuple[str, ipaddress.IPv4Network]] = []
    selected_prefixlen: int | None = None
    for item in routes_document:
        if not isinstance(item, dict) or not isinstance(item.get("dev"), str):
            continue
        raw_destination = item.get("dst")
        if not isinstance(raw_destination, str) or raw_destination == "default":
            continue
        try:
            network = ipaddress.ip_network(raw_destination, strict=False)
        except ValueError:
            continue
        if not isinstance(network, ipaddress.IPv4Network):
            continue
        if target not in network:
            continue
        destination_routes.append((item["dev"], str(network)))
        covering.append((item["dev"], network))
        if item["dev"] == interface:
            selected_prefixlen = (
                network.prefixlen
                if selected_prefixlen is None
                else max(selected_prefixlen, network.prefixlen)
            )
    if selected_prefixlen is None:
        raise UsbSshRouteAmbiguous(
            f"USB-bound SSH endpoint {endpoint} has no observed route through {interface!r}"
        )

    # Linux selects a route by longest-prefix match, so a route that is strictly
    # less specific than the bound interface's own route can never carry this
    # destination and is therefore not a competitor.  Only an equally or more
    # specific route on another interface can win -- that is the case this gate
    # exists for (two USB gadgets exposing identical host addresses and
    # destination subnets), and it is still refused below.
    competing = [
        (name, str(network))
        for name, network in covering
        if name != interface and network.prefixlen >= selected_prefixlen
    ]
    if competing:
        detail = ", ".join(f"{network} via {name}" for name, network in sorted(competing))
        raise UsbSshRouteAmbiguous(
            f"USB-bound SSH endpoint {endpoint} is covered by competing routes ({detail}) "
            f"at least as specific as the /{selected_prefixlen} route through {interface!r}. "
            "Disconnect or readdress the overlapping interface; refusing enrollment or mutation."
        )
    return UsbSshRouteObservation(
        interface_addresses=tuple(sorted(interface_addresses)),
        destination_routes=tuple(sorted(destination_routes)),
    )


def _read_ip_json(argv: Sequence[str]) -> str:
    completed = subprocess.run(  # noqa: S603
        argv,
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    return completed.stdout


@dataclass(frozen=True, slots=True)
class IpFirmwareEnrollment:
    """Immutable trust and initial-state record for one IP-attached radio."""

    endpoint: str
    serial: str
    board_model: str
    observed_firmware: str
    host_key_fingerprint: str

    def __post_init__(self) -> None:
        try:
            normalized = str(ipaddress.ip_address(self.endpoint))
        except ValueError as error:
            raise ValueError("firmware endpoint must be a literal IP address") from error
        if normalized != self.endpoint:
            raise ValueError("firmware endpoint must use canonical IP notation")
        if not _SERIAL_RE.fullmatch(self.serial):
            raise ValueError("invalid firmware enrollment serial")
        if not self.board_model.strip() or "\x00" in self.board_model:
            raise ValueError("firmware enrollment board model cannot be empty")
        if not self.observed_firmware.strip() or "\x00" in self.observed_firmware:
            raise ValueError("firmware enrollment version cannot be empty")
        if not _FINGERPRINT_RE.fullmatch(self.host_key_fingerprint):
            raise ValueError("host key fingerprint must be an SHA256 OpenSSH fingerprint")


@dataclass(frozen=True, slots=True)
class IpFirmwareAttestation:
    serial: str
    board_model: str
    active_firmware: str
    boot_id: str | None
    endpoint: str
    host_key_fingerprint: str

    def as_radio_identity(self) -> RadioFirmwareIdentity:
        return RadioFirmwareIdentity(
            serial=self.serial,
            usb_sysfs_path=None,
            observed_firmware=self.active_firmware,
            endpoint=self.endpoint,
            host_key_fingerprint=self.host_key_fingerprint,
        )


@dataclass(frozen=True, slots=True)
class IpFirmwareStagedFile:
    sha256: str
    size: int


@dataclass(frozen=True, slots=True)
class IpFirmwareQspiEvidence:
    fit_sha256: str
    fit_size: int
    header_hex: str


@dataclass(frozen=True, slots=True)
class IpFirmwareEvidence:
    schema_version: int
    attempt_id: str
    started_at: datetime
    finished_at: datetime | None
    enrollment: IpFirmwareEnrollment
    frm_sha256: str
    frm_size: int
    fit_sha256: str
    fit_size: int
    outcome: Literal["in_progress", "verified", "failed", "unknown"]
    completed_phases: tuple[str, ...]
    failure_phase: str | None
    mutation_dispatched: bool
    reconciliation_required: bool
    key_reconciliation_required: bool
    before: IpFirmwareAttestation | None
    staged: IpFirmwareStagedFile | None
    qspi: IpFirmwareQspiEvidence | None
    after: IpFirmwareAttestation | None
    updater_output: str | None
    error: str | None


class IpFirmwareTransport(Protocol):
    """Fixed remote operations; deliberately has no arbitrary ``run`` method."""

    endpoint: str
    host_key_fingerprint: str

    def attest(self) -> IpFirmwareAttestation: ...

    def ensure_tx_safe(self, serial: str) -> None: ...

    def stage_frm(self, data: bytes) -> IpFirmwareStagedFile: ...

    def invoke_update_frm(self) -> str: ...

    def inspect_mtd3(self, fit_size: int) -> IpFirmwareQspiEvidence: ...

    def cleanup_stage(self) -> None: ...

    def sync(self) -> None: ...

    def reset(self) -> None: ...


@dataclass(frozen=True, slots=True)
class SshCommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes


class SshCommandRunner(Protocol):
    def run(
        self, argv: Sequence[str], *, stdin: bytes | None, timeout_s: float
    ) -> SshCommandResult: ...


class SubprocessSshCommandRunner:
    def run(
        self, argv: Sequence[str], *, stdin: bytes | None, timeout_s: float
    ) -> SshCommandResult:
        completed = subprocess.run(  # noqa: S603
            argv,
            input=stdin,
            capture_output=True,
            check=False,
            timeout=timeout_s,
        )
        return SshCommandResult(completed.returncode, completed.stdout, completed.stderr)


class NetworkConfigCommandRunner(Protocol):
    """Narrow adapter used by the fixed network-configuration operation set."""

    def __call__(self, command: str, *, stdin: bytes | None = None, timeout_s: float) -> str: ...


_ATTEST_COMMAND = r"""set -eu
emit() { printf 'PPU\t%s\t%s\n' "$1" "$2"; }
test "$(id -u)" = 0
serial=$(cat /sys/kernel/config/usb_gadget/composite_gadget/strings/0x409/serialnumber)
board=$(tr '\000' ' ' </proc/device-tree/model)
firmware=$(awk '$1 == "device-fw" {print $2; exit}' /opt/VERSIONS)
boot_id=$(cat /proc/sys/kernel/random/boot_id)
test -n "$serial" && test -n "$board" && test -n "$firmware" && test -n "$boot_id"
emit serial "$serial"
emit board_model "$board"
emit active_firmware "$firmware"
emit boot_id "$boot_id"
"""

_TX_SAFE_COMMAND = r"""set -eu
serial_expected="$1"
serial=$(cat /sys/kernel/config/usb_gadget/composite_gadget/strings/0x409/serialnumber)
test "$serial" = "$serial_expected"
phy=''; dds=''
for d in /sys/bus/iio/devices/iio:device*; do
  case "$(cat "$d/name" 2>/dev/null || true)" in
    ad9361-phy) phy="$d" ;;
    cf-ad9361-dds-core-lpc) dds="$d" ;;
  esac
done
test -n "$phy" && test -n "$dds"
printf '%s\n' -80 >"$phy/out_voltage0_hardwaregain"
printf '%s\n' -80 >"$phy/out_voltage1_hardwaregain"
printf '%s\n' 0 >"$dds/buffer/enable"
for f in "$dds"/scan_elements/out_voltage[0-3]_en; do
  test -e "$f" && printf '%s\n' 0 >"$f"
done
for f in "$dds"/out_altvoltage*_scale; do printf '%s\n' 0 >"$f"; done
for f in "$dds"/out_altvoltage*_raw; do printf '%s\n' 0 >"$f"; done
test "$(cat "$phy/out_voltage0_hardwaregain" | awk '{print $1}')" = -80.000000
test "$(cat "$phy/out_voltage1_hardwaregain" | awk '{print $1}')" = -80.000000
test "$(cat "$dds/buffer/enable")" = 0
for f in "$dds"/scan_elements/out_voltage[0-3]_en "$dds"/out_altvoltage*_raw; do
  test ! -e "$f" || test "$(cat "$f")" = 0
done
for f in "$dds"/out_altvoltage*_scale; do
  test ! -e "$f" || awk -v value="$(cat "$f")" 'BEGIN { exit !(value == 0) }'
done
printf 'PPU\ttx_safe\t1\n'
"""

_STAGE_COMMAND = rf"""set -eu
test "$(id -u)" = 0
umask 077
mkdir -p /root/.pluto-plus-ip-firmware
test -d /root/.pluto-plus-ip-firmware
test ! -L /root/.pluto-plus-ip-firmware
chmod 700 /root/.pluto-plus-ip-firmware
rm -f {_REMOTE_STAGE}.incoming
cat >{_REMOTE_STAGE}.incoming
chmod 600 {_REMOTE_STAGE}.incoming
mv -f {_REMOTE_STAGE}.incoming {_REMOTE_STAGE}
printf 'PPU\tstage_sha256\t%s\n' "$(sha256sum {_REMOTE_STAGE} | awk '{{print $1}}')"
printf 'PPU\tstage_size\t%s\n' "$(wc -c <{_REMOTE_STAGE} | tr -d ' ')"
"""

_UPDATE_COMMAND = f"/sbin/update_frm.sh {_REMOTE_STAGE}"
_CLEANUP_COMMAND = f"rm -f {_REMOTE_STAGE} {_REMOTE_STAGE}.incoming"
_SYNC_COMMAND = "/bin/sync"
_RESET_COMMAND = (
    "printf 'PPU\\treset_dispatched\\t1\\n'; "
    "/usr/sbin/device_reboot reset"
)
_QSPI_COMMAND = "/bin/sh -s --"
_QSPI_SCRIPT = rb"""set -eu
fit_size="$1"
case "$fit_size" in *[!0-9]*|'') exit 2;; esac
header=$(dd if=/dev/mtd3 bs=1 count=8 2>/dev/null | od -An -tx1 -v | tr -d ' \n')
actual=$(dd if=/dev/mtd3 bs="$fit_size" count=1 2>/dev/null | wc -c | tr -d ' ')
digest=$(dd if=/dev/mtd3 bs="$fit_size" count=1 2>/dev/null | sha256sum | awk '{print $1}')
printf 'PPU\theader_hex\t%s\n' "$header"
printf 'PPU\tfit_size\t%s\n' "$actual"
printf 'PPU\tfit_sha256\t%s\n' "$digest"
"""

_NETWORK_INSPECT_SCRIPT = rb"""set -eu
serial_expected="$1"
emit() { printf 'PPU\t%s\t%s\n' "$1" "$2"; }
read_env() { fw_printenv -n "$1" 2>/dev/null || true; }
serial=$(cat /sys/kernel/config/usb_gadget/composite_gadget/strings/0x409/serialnumber)
test "$serial" = "$serial_expected"
test -f /opt/config.txt && test ! -L /opt/config.txt
hostname=$(read_env hostname)
test -n "$hostname" || hostname=$(cat /etc/hostname)
ipaddr=$(read_env ipaddr); test -n "$ipaddr" || ipaddr=192.168.2.1
ipaddr_host=$(read_env ipaddr_host); test -n "$ipaddr_host" || ipaddr_host=192.168.2.10
netmask=$(read_env netmask); test -n "$netmask" || netmask=255.255.255.0
ipaddr_eth=$(read_env ipaddr_eth)
netmask_eth=$(read_env netmask_eth); test -n "$netmask_eth" || netmask_eth=255.255.255.0
ethernet_runtime_address=$(
  ip -4 addr show dev eth0 2>/dev/null |
  awk '/^[[:space:]]*inet[[:space:]]/ { split($2, address, "/"); print address[1]; exit }'
)
env_sha=$({
  printf 'ipaddr=%s\n' "$ipaddr"
  printf 'ipaddr_host=%s\n' "$ipaddr_host"
  printf 'netmask=%s\n' "$netmask"
  printf 'ipaddr_eth=%s\n' "$ipaddr_eth"
  printf 'netmask_eth=%s\n' "$netmask_eth"
} | sha256sum | awk '{print $1}')
config_sha=$(sha256sum /opt/config.txt | awk '{print $1}')
config_redacted=$(
  sed -e 's/^\([[:space:]]*pwd_wlan[[:space:]]*=[[:space:]]*\).*$/\1<redacted>/' \
    /opt/config.txt |
  base64 |
  tr -d '\n'
)
emit serial "$serial"
emit hostname "$hostname"
emit ipaddr "$ipaddr"
emit ipaddr_host "$ipaddr_host"
emit netmask "$netmask"
emit ipaddr_eth "$ipaddr_eth"
emit netmask_eth "$netmask_eth"
emit ethernet_runtime_address "$ethernet_runtime_address"
emit environment_sha256 "$env_sha"
emit config_txt_sha256 "$config_sha"
emit config_txt_redacted_b64 "$config_redacted"
"""

_NETWORK_APPLY_SCRIPT = rb"""set -eu
serial_expected="$1"; expected_digest="$2"; plan_id="$3"; shift 3
emit() { printf 'PPU\t%s\t%s\n' "$1" "$2"; }
read_env() { fw_printenv -n "$1" 2>/dev/null || true; }
serial=$(cat /sys/kernel/config/usb_gadget/composite_gadget/strings/0x409/serialnumber)
test "$serial" = "$serial_expected"
ipaddr=$(read_env ipaddr); test -n "$ipaddr" || ipaddr=192.168.2.1
ipaddr_host=$(read_env ipaddr_host); test -n "$ipaddr_host" || ipaddr_host=192.168.2.10
netmask=$(read_env netmask); test -n "$netmask" || netmask=255.255.255.0
ipaddr_eth=$(read_env ipaddr_eth)
netmask_eth=$(read_env netmask_eth); test -n "$netmask_eth" || netmask_eth=255.255.255.0
current_digest=$({
  printf 'ipaddr=%s\n' "$ipaddr"
  printf 'ipaddr_host=%s\n' "$ipaddr_host"
  printf 'netmask=%s\n' "$netmask"
  printf 'ipaddr_eth=%s\n' "$ipaddr_eth"
  printf 'netmask_eth=%s\n' "$netmask_eth"
} | sha256sum | awk '{print $1}')
test "$current_digest" = "$expected_digest"
umask 077
backup_dir=/root/.pluto-plus-network-config
mkdir -p "$backup_dir"; test -d "$backup_dir"; test ! -L "$backup_dir"; chmod 700 "$backup_dir"
backup="$backup_dir/$plan_id.env"
test ! -e "$backup"
fw_printenv >"$backup"
chmod 600 "$backup"
sync
backup_sha=$(sha256sum "$backup" | awk '{print $1}')
backup_b64=$(base64 "$backup" | tr -d '\n')
batch="$backup_dir/$plan_id.batch"
: >"$batch"; chmod 600 "$batch"
count=0
while [ "$#" -gt 0 ]; do
  test "$#" -ge 2
  key="$1"; value="$2"; shift 2
  case "$key" in ipaddr|ipaddr_host|netmask|ipaddr_eth|netmask_eth) ;; *) exit 12 ;; esac
  case "$value" in
    __DELETE__) printf '%s\n' "$key" >>"$batch" ;;
    *[!0-9.]*) exit 13 ;;
    *) printf '%s %s\n' "$key" "$value" >>"$batch" ;;
  esac
  count=$((count + 1))
done
test "$count" -ge 1 && test "$count" -le 3
fw_setenv -s "$batch"
rm -f "$batch"
sync
ipaddr=$(read_env ipaddr); test -n "$ipaddr" || ipaddr=192.168.2.1
ipaddr_host=$(read_env ipaddr_host); test -n "$ipaddr_host" || ipaddr_host=192.168.2.10
netmask=$(read_env netmask); test -n "$netmask" || netmask=255.255.255.0
ipaddr_eth=$(read_env ipaddr_eth)
netmask_eth=$(read_env netmask_eth); test -n "$netmask_eth" || netmask_eth=255.255.255.0
after_digest=$({
  printf 'ipaddr=%s\n' "$ipaddr"
  printf 'ipaddr_host=%s\n' "$ipaddr_host"
  printf 'netmask=%s\n' "$netmask"
  printf 'ipaddr_eth=%s\n' "$ipaddr_eth"
  printf 'netmask_eth=%s\n' "$netmask_eth"
} | sha256sum | awk '{print $1}')
emit serial "$serial"
emit backup_path "$backup"
emit backup_sha256 "$backup_sha"
emit backup_b64 "$backup_b64"
emit environment_sha256 "$after_digest"
emit mutation_completed 1
"""


class SshNetworkConfigBackend:
    """Fixed network-config operations over an already pinned SSH runner.

    Authentication and route binding remain the caller's responsibility.  This
    class owns the complete remote operation set so key-authenticated daemon
    enrollments and password-authenticated exact-USB bootstrap use identical
    inspection, mutation, backup, and readback semantics.
    """

    def __init__(
        self,
        *,
        endpoint: str,
        host_key_fingerprint: str,
        command_runner: NetworkConfigCommandRunner,
    ) -> None:
        try:
            normalized = str(ipaddress.ip_address(endpoint))
        except ValueError as error:
            raise ValueError("network-config endpoint must be a literal IP address") from error
        if normalized != endpoint:
            raise ValueError("network-config endpoint must use canonical IP notation")
        if not _FINGERPRINT_RE.fullmatch(host_key_fingerprint):
            raise ValueError("network-config host-key fingerprint is malformed")
        self.endpoint = endpoint
        self.host_key_fingerprint = host_key_fingerprint
        self._run = command_runner

    @property
    def identity_endpoint(self) -> str:
        return self.endpoint

    def inspect_network_config(self, serial: str) -> NetworkConfigObservation:
        """Read the generated config safely, redacting the Wi-Fi password."""

        if not _SERIAL_RE.fullmatch(serial):
            raise IpFirmwareError("invalid serial for network-config inspection")
        fields = _parse_report(
            self._run(
                "/bin/sh -s -- " + serial,
                stdin=_NETWORK_INSPECT_SCRIPT,
                timeout_s=20,
            )
        )
        if _required(fields, "serial") != serial:
            raise IpFirmwareError("network-config inspection returned another serial")
        if "config_txt_redacted_b64" not in fields:
            raise IpFirmwareError("remote report omitted config_txt_redacted_b64")
        encoded = fields["config_txt_redacted_b64"]
        try:
            config_bytes = base64.b64decode(encoded, validate=True)
            config_text = config_bytes.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError) as error:
            raise IpFirmwareError("redacted config.txt report is malformed") from error
        if (
            len(config_bytes) > 65_536
            or "pwd_wlan" in config_text
            and not all(
                "<redacted>" in line
                for line in config_text.splitlines()
                if line.lstrip().startswith("pwd_wlan")
            )
        ):
            raise IpFirmwareError("config.txt redaction did not pass validation")
        values = {key: fields.get(key, "") for key in NETWORK_KEYS}
        if not hmac.compare_digest(
            persistent_environment_sha256(values),
            _required_digest(fields, "environment_sha256"),
        ):
            raise IpFirmwareError("network environment digest report is inconsistent")
        return NetworkConfigObservation(
            identity=NetworkConfigIdentity(
                serial=serial,
                endpoint=self.endpoint,
                host_key_fingerprint=self.host_key_fingerprint,
            ),
            config_txt_sha256=_required_digest(fields, "config_txt_sha256"),
            environment_sha256=_required_digest(fields, "environment_sha256"),
            config_txt_redacted=config_text,
            hostname=_required(fields, "hostname"),
            usb_radio_address=_required(fields, "ipaddr"),
            usb_host_address=_required(fields, "ipaddr_host"),
            usb_netmask=_required(fields, "netmask"),
            ethernet_address=fields.get("ipaddr_eth") or None,
            ethernet_runtime_address=fields.get("ethernet_runtime_address") or None,
            ethernet_netmask=_required(fields, "netmask_eth"),
        )

    def apply_network_config(self, plan: NetworkConfigPlan) -> NetworkConfigExecutionResult:
        """Persist one validated plan without restarting or changing live addresses."""

        if plan.identity != NetworkConfigIdentity(
            serial=plan.identity.serial,
            endpoint=self.endpoint,
            host_key_fingerprint=self.host_key_fingerprint,
        ):
            raise IpFirmwareError("network-config plan identity does not match enrollment")
        if not re.fullmatch(r"[0-9a-f]{32}", plan.plan_id):
            raise IpFirmwareError("network-config plan identifier is malformed")
        arguments: list[str] = [
            plan.identity.serial,
            plan.before.environment_sha256,
            plan.plan_id,
        ]
        for key, value in plan.changes_items:
            if key not in NETWORK_KEYS or (value and not re.fullmatch(r"[0-9.]{7,15}", value)):
                raise IpFirmwareError("network-config plan contains an invalid change")
            arguments.extend((key, value or "__DELETE__"))
        command = "/bin/sh -s -- " + " ".join(arguments)
        fields = _parse_report(self._run(command, stdin=_NETWORK_APPLY_SCRIPT, timeout_s=45))
        if fields.get("mutation_completed") != "1" or fields.get("serial") != plan.identity.serial:
            raise IpFirmwareError("network-config persistent write was not acknowledged")
        after = self.inspect_network_config(plan.identity.serial)
        if not hmac.compare_digest(
            after.environment_sha256,
            _required_digest(fields, "environment_sha256"),
        ):
            raise IpFirmwareError("network-config post-write digest changed during readback")
        return NetworkConfigExecutionResult(
            observation=after,
            backup_path=_required(fields, "backup_path"),
            backup_sha256=_required_digest(fields, "backup_sha256"),
            backup_content=_decode_bounded_base64(
                _required(fields, "backup_b64"),
                label="network environment backup",
                maximum_bytes=131_072,
            ),
            completed_phases=(
                "identity_attested",
                "environment_revalidated",
                "backup_persisted",
                "environment_written",
                "persistent_readback_verified",
            ),
        )


class PinnedSshFirmwareTransport:
    """Key-only OpenSSH transport pinned to one literal endpoint and host key."""

    def __init__(
        self,
        *,
        endpoint: str,
        known_hosts_file: Path,
        private_key_file: Path,
        port: int = 22,
        ssh_binary: str = "ssh",
        command_runner: SshCommandRunner | None = None,
    ) -> None:
        try:
            normalized = str(ipaddress.ip_address(endpoint))
        except ValueError as error:
            raise ValueError("SSH firmware endpoint must be a literal IP address") from error
        if normalized != endpoint:
            raise ValueError("SSH firmware endpoint must use canonical IP notation")
        if not 1 <= port <= 65535:
            raise ValueError("SSH port is outside 1..65535")
        _validate_private_file(private_key_file, "SSH private key")
        _validate_private_file(known_hosts_file, "SSH known-hosts")
        fingerprint, algorithm = _pinned_host_key(known_hosts_file, endpoint, port)
        self.endpoint = endpoint
        self.host_key_fingerprint = fingerprint
        self._runner = command_runner or SubprocessSshCommandRunner()
        self._private_key_file = private_key_file
        self._known_hosts_file = known_hosts_file
        self._private_key_digest = _file_sha256(private_key_file, "SSH private key")
        self._known_hosts_digest = _file_sha256(known_hosts_file, "SSH known-hosts")
        self._base_argv = (
            ssh_binary,
            "-T",
            "-p",
            str(port),
            "-i",
            str(private_key_file),
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={known_hosts_file}",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            f"HostKeyAlgorithms={algorithm}",
            "-o",
            "ConnectTimeout=5",
            f"root@{endpoint}",
        )
        self._network_config_backend = SshNetworkConfigBackend(
            endpoint=self.endpoint,
            host_key_fingerprint=self.host_key_fingerprint,
            command_runner=self._run,
        )

    def attest(self) -> IpFirmwareAttestation:
        fields = _parse_report(self._run(_ATTEST_COMMAND, timeout_s=15))
        return IpFirmwareAttestation(
            serial=_required(fields, "serial"),
            board_model=_required(fields, "board_model"),
            active_firmware=_required(fields, "active_firmware"),
            boot_id=_required(fields, "boot_id"),
            endpoint=self.endpoint,
            host_key_fingerprint=self.host_key_fingerprint,
        )

    def ensure_tx_safe(self, serial: str) -> None:
        if not _SERIAL_RE.fullmatch(serial):
            raise IpFirmwareError("invalid serial for fixed TX-safe operation")
        fields = _parse_report(
            self._run("/bin/sh -s -- " + serial, stdin=_TX_SAFE_COMMAND.encode(), timeout_s=20)
        )
        if fields.get("tx_safe") != "1":
            raise IpFirmwareError("remote TX-safe readback was not affirmative")

    def stage_frm(self, data: bytes) -> IpFirmwareStagedFile:
        fields = _parse_report(self._run(_STAGE_COMMAND, stdin=data, timeout_s=90))
        return IpFirmwareStagedFile(
            sha256=_required_digest(fields, "stage_sha256"),
            size=_required_positive_int(fields, "stage_size"),
        )

    def invoke_update_frm(self) -> str:
        result = self._raw_run(_UPDATE_COMMAND, timeout_s=180)
        if result.returncode != 0:
            self._raise_result(result)
        return (result.stdout + result.stderr).decode(errors="replace").replace("\r", "")

    def inspect_mtd3(self, fit_size: int) -> IpFirmwareQspiEvidence:
        if fit_size <= 0 or fit_size > 128 * 1024 * 1024:
            raise IpFirmwareError("FIT size is outside the fixed verification limit")
        fields = _parse_report(
            self._run(
                f"{_QSPI_COMMAND} {fit_size}",
                stdin=_QSPI_SCRIPT,
                timeout_s=90,
            )
        )
        header = _required(fields, "header_hex")
        if not re.fullmatch(r"[0-9a-f]{16}", header):
            raise IpFirmwareError("remote MTD3 header report is malformed")
        declared = int.from_bytes(bytes.fromhex(header)[4:8], "big")
        reported = _required_positive_int(fields, "fit_size")
        if bytes.fromhex(header)[:4] != FIT_MAGIC or declared != reported:
            raise IpFirmwareError("remote MTD3 FIT header size does not match readback")
        return IpFirmwareQspiEvidence(
            fit_sha256=_required_digest(fields, "fit_sha256"),
            fit_size=reported,
            header_hex=header,
        )

    def cleanup_stage(self) -> None:
        self._run(_CLEANUP_COMMAND, timeout_s=15)

    def sync(self) -> None:
        self._run(_SYNC_COMMAND, timeout_s=30)

    def reset(self) -> None:
        result = self._raw_run(_RESET_COMMAND, timeout_s=15)
        combined = result.stdout + result.stderr
        if b"PPU\treset_dispatched\t1" not in combined:
            self._raise_result(result)

    def inspect_network_config(self, serial: str) -> NetworkConfigObservation:
        return self._network_config_backend.inspect_network_config(serial)

    def apply_network_config(self, plan: NetworkConfigPlan) -> NetworkConfigExecutionResult:
        return self._network_config_backend.apply_network_config(plan)

    def _run(
        self, command: str, *, stdin: bytes | None = None, timeout_s: float
    ) -> str:
        result = self._raw_run(command, stdin=stdin, timeout_s=timeout_s)
        if result.returncode != 0:
            self._raise_result(result)
        return result.stdout.decode(errors="replace").replace("\r", "")

    def _raw_run(
        self, command: str, *, stdin: bytes | None = None, timeout_s: float
    ) -> SshCommandResult:
        _validate_fixed_command(command)
        _validate_private_file(self._private_key_file, "SSH private key")
        _validate_private_file(self._known_hosts_file, "SSH known-hosts")
        if not hmac.compare_digest(
            _file_sha256(self._private_key_file, "SSH private key"),
            self._private_key_digest,
        ) or not hmac.compare_digest(
            _file_sha256(self._known_hosts_file, "SSH known-hosts"),
            self._known_hosts_digest,
        ):
            raise IpFirmwareError("pinned SSH credential files changed after enrollment")
        try:
            return self._runner.run(
                (*self._base_argv, command), stdin=stdin, timeout_s=timeout_s
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise IpFirmwareError(f"SSH transport failed: {error}") from error

    @staticmethod
    def _raise_result(result: SshCommandResult) -> None:
        output = result.stderr + result.stdout
        # Classify against the complete captured output before bounding the
        # diagnostic. Long known_hosts paths can otherwise push OpenSSH's
        # leading host-key-change marker out of the retained error tail.
        if b"REMOTE HOST IDENTIFICATION HAS CHANGED" in output:
            raise IpFirmwareHostKeyChanged("pinned radio SSH host key changed")
        detail = output[-1000:].decode(errors="replace").strip()
        raise IpFirmwareError(f"radio SSH command failed ({result.returncode}): {detail}")


class IpFirmwareExecutor:
    """Persistent-FRM executor bound to exactly one enrolled IP radio."""

    def __init__(
        self,
        *,
        enrollment: IpFirmwareEnrollment,
        transport: IpFirmwareTransport,
        evidence_directory: Path,
        expected_firmware: str | None = None,
        post_reset_probe: Callable[[str], RadioFirmwareIdentity] | None = None,
        post_reset_tx_guard: Callable[[str], bool] | None = None,
        return_timeout_s: float = 180,
        poll_interval_s: float = 1,
        clock: Callable[[], datetime] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if transport.endpoint != enrollment.endpoint:
            raise ValueError("SSH transport endpoint does not match enrollment")
        if not hmac.compare_digest(
            transport.host_key_fingerprint, enrollment.host_key_fingerprint
        ):
            raise ValueError("SSH transport host key does not match enrollment")
        if not evidence_directory.is_absolute() or evidence_directory == Path("/"):
            raise ValueError("firmware evidence directory must be an explicit absolute path")
        if return_timeout_s <= 0 or poll_interval_s <= 0:
            raise ValueError("firmware return timeout and poll interval must be positive")
        if expected_firmware is not None and not expected_firmware.strip():
            raise ValueError("expected firmware cannot be empty")
        self.enrollment = enrollment
        self.transport = transport
        self.evidence_directory = evidence_directory
        self.expected_firmware = expected_firmware
        self._post_reset_probe = post_reset_probe
        self._post_reset_tx_guard = post_reset_tx_guard
        self._return_timeout = return_timeout_s
        self._poll_interval = poll_interval_s
        self._clock = clock or (lambda: datetime.now(UTC))
        self._monotonic = monotonic
        self._sleep = sleep
        self._last_evidence: IpFirmwareEvidence | None = None
        self._key_reconciliation_required = False

    @property
    def serial(self) -> str:
        return self.enrollment.serial

    @property
    def endpoint(self) -> str:
        return self.enrollment.endpoint

    @property
    def host_key_fingerprint(self) -> str:
        return self.enrollment.host_key_fingerprint

    @property
    def last_evidence(self) -> IpFirmwareEvidence | None:
        return self._last_evidence

    @property
    def key_reconciliation_required(self) -> bool:
        return self._key_reconciliation_required

    def authorize_execution(self) -> None:
        if self._key_reconciliation_required:
            raise IpFirmwareError("SSH enrollment is stale and must be reconciled out of band")

    def effective_uid(self) -> int:
        # Local root is neither required nor claimed; privilege is remote and key-authenticated.
        return os.geteuid()

    def attest(self, serial: str | None = None) -> IpFirmwareAttestation:
        if serial is not None and serial != self.enrollment.serial:
            raise IpFirmwareError("IP firmware executor is bound to another serial")
        attestation = self.transport.attest()
        self._validate_stable_attestation(attestation)
        return attestation

    def identity_probe(self, serial: str) -> RadioFirmwareIdentity:
        return self.attest(serial).as_radio_identity()

    def load_volatile_dfu(self, radio: RadioFirmwareIdentity, image: Path) -> None:
        del radio, image
        raise FirmwareExecutorFailure(
            "SSH firmware transport does not permit volatile DFU loading",
            outcome="failed",
            failure_phase="mode_validation",
            reconciliation_required=False,
        )

    def flash_persistent_qspi(
        self, radio: RadioFirmwareIdentity, image: Path, *, target_name: str
    ) -> None:
        try:
            evidence = self._start_evidence(image)
        except BaseException as error:
            raise FirmwareExecutorFailure(
                f"firmware evidence journal unavailable: {error}",
                outcome="failed",
                failure_phase="evidence_initialization",
                reconciliation_required=False,
            ) from error
        phase = "local_validation"
        try:
            self.authorize_execution()
            if target_name != "pluto.frm" or Path(target_name).name != target_name:
                raise IpFirmwareError("SSH updater target must be exactly pluto.frm")
            if (
                not image.is_absolute()
                or image.name != "pluto.frm"
                or image.is_symlink()
                or not image.is_file()
            ):
                raise IpFirmwareError(
                    "SSH firmware source must be an absolute regular pluto.frm staging file"
                )
            if image.stat().st_size > 128 * 1024 * 1024:
                raise IpFirmwareError("SSH firmware source exceeds the fixed size limit")
            data = image.read_bytes()
            fit = validate_frm(data)
            frm_sha256 = hashlib.sha256(data).hexdigest()
            fit_sha256 = hashlib.sha256(fit).hexdigest()
            evidence = self._record(
                replace(
                    evidence,
                    frm_sha256=frm_sha256,
                    frm_size=len(data),
                    fit_sha256=fit_sha256,
                    fit_size=len(fit),
                    completed_phases=("local_validation",),
                )
            )

            phase = "remote_preflight"
            before = self.attest(radio.serial)
            self._validate_radio_binding(radio, before)
            if before.boot_id is None:
                raise IpFirmwareError("SSH preflight omitted the kernel boot identity")
            evidence = self._record(
                replace(
                    evidence,
                    before=before,
                    completed_phases=(*evidence.completed_phases, "remote_preflight"),
                )
            )

            phase = "tx_safe_before_update"
            self.transport.ensure_tx_safe(self.enrollment.serial)
            evidence = self._record(
                replace(
                    evidence,
                    completed_phases=(*evidence.completed_phases, "tx_safe_before_update"),
                )
            )

            phase = "remote_stage"
            staged = self.transport.stage_frm(data)
            evidence = self._record(
                replace(
                    evidence,
                    staged=staged,
                    completed_phases=(
                        *evidence.completed_phases,
                        "remote_stage_uploaded",
                    ),
                )
            )
            if staged.size != len(data) or not hmac.compare_digest(
                staged.sha256, frm_sha256
            ):
                raise IpFirmwareError("remote staged FRM hash or size mismatch")
            evidence = self._record(
                replace(
                    evidence,
                    completed_phases=(*evidence.completed_phases, "remote_stage_verified"),
                )
            )

            phase = "update_frm"
            evidence = self._record(replace(evidence, mutation_dispatched=True))
            output = self.transport.invoke_update_frm()
            evidence = self._record(
                replace(evidence, updater_output=_bounded_text(output))
            )
            if _FAILED_RE.search(output):
                raise IpFirmwareError("/sbin/update_frm.sh reported Failed")
            if not _DONE_RE.search(output.replace("\r", "")):
                raise IpFirmwareError("/sbin/update_frm.sh omitted standalone Done marker")
            evidence = self._record(
                replace(
                    evidence,
                    completed_phases=(*evidence.completed_phases, "update_frm_completed"),
                )
            )

            phase = "qspi_verification"
            qspi = self.transport.inspect_mtd3(len(fit))
            if qspi.fit_size != len(fit) or not hmac.compare_digest(
                qspi.fit_sha256, fit_sha256
            ):
                raise IpFirmwareError("MTD3 FIT body hash or size mismatch after updater")
            evidence = self._record(
                replace(
                    evidence,
                    qspi=qspi,
                    completed_phases=(*evidence.completed_phases, "qspi_fit_verified"),
                )
            )

            phase = "stage_cleanup"
            self.transport.cleanup_stage()
            evidence = self._record(
                replace(
                    evidence,
                    completed_phases=(*evidence.completed_phases, "remote_stage_cleaned"),
                )
            )
            phase = "sync"
            self.transport.sync()
            evidence = self._record(
                replace(
                    evidence,
                    completed_phases=(*evidence.completed_phases, "sync_completed"),
                )
            )
            phase = "reset"
            self.transport.reset()
            evidence = self._record(
                replace(
                    evidence,
                    completed_phases=(*evidence.completed_phases, "reset_dispatched"),
                )
            )

            phase = "post_reset_attestation"
            after, key_changed = self._wait_for_return(before.boot_id)
            if self.expected_firmware is not None and (
                after.active_firmware != self.expected_firmware
            ):
                raise IpFirmwareError(
                    f"post-reset firmware is {after.active_firmware!r}, "
                    f"expected {self.expected_firmware!r}"
                )
            if not key_changed and after.boot_id == before.boot_id:
                raise IpFirmwareError("radio returned without a new boot identity")
            evidence = self._record(
                replace(
                    evidence,
                    after=after,
                    key_reconciliation_required=key_changed,
                    completed_phases=(
                        *evidence.completed_phases,
                        "post_reset_attestation",
                    ),
                )
            )

            phase = "tx_safe_after_reset"
            self._ensure_post_reset_tx_safe(key_changed)
            completed = (*evidence.completed_phases, "tx_safe_after_reset")
            if key_changed:
                completed = (*completed, "ssh_reenrollment_required")
                self._key_reconciliation_required = True
                evidence = self._record(
                    replace(
                        evidence,
                        completed_phases=completed,
                        reconciliation_required=True,
                        key_reconciliation_required=True,
                    )
                )
                phase = "ssh_reenrollment_required"
                raise IpFirmwareHostKeyChanged(
                    "the pinned SSH host key changed after reset; the independently "
                    "observed return is not authenticated completion"
                )
            evidence = self._record(
                replace(
                    evidence,
                    finished_at=self._now(),
                    outcome="verified",
                    completed_phases=completed,
                    reconciliation_required=key_changed,
                    key_reconciliation_required=key_changed,
                )
            )
        except BaseException as error:
            if (
                (
                    phase == "remote_stage"
                    or "remote_stage_uploaded" in evidence.completed_phases
                )
                and "remote_stage_cleaned" not in evidence.completed_phases
            ):
                try:
                    self.transport.cleanup_stage()
                    evidence = self._record(
                        replace(
                            evidence,
                            completed_phases=(
                                *evidence.completed_phases,
                                "remote_stage_cleaned_after_failure",
                            ),
                        )
                    )
                except BaseException as cleanup_error:
                    error = IpFirmwareError(
                        f"{error}; remote stage cleanup failed: {cleanup_error}"
                    )
            self._finish_failure(evidence, phase, error)

    def reconcile_persistent_qspi(
        self,
        radio: RadioFirmwareIdentity,
        *,
        expected_firmware: str | None,
        expected_fit_sha256: str,
        expected_fit_size: int,
    ) -> tuple[str, ...]:
        if not _DIGEST_RE.fullmatch(expected_fit_sha256) or expected_fit_size <= 0:
            raise FirmwareExecutorFailure(
                "invalid FIT evidence for reconciliation",
                outcome="failed",
                failure_phase="reconciliation_input",
                reconciliation_required=False,
            )
        try:
            attestation = self.attest(radio.serial)
            self._validate_stable_attestation(attestation)
            if expected_firmware is not None and (
                attestation.active_firmware != expected_firmware
            ):
                raise IpFirmwareError("reconciled active firmware does not match expectation")
            self.transport.ensure_tx_safe(self.enrollment.serial)
            qspi = self.transport.inspect_mtd3(expected_fit_size)
            if qspi.fit_size != expected_fit_size or not hmac.compare_digest(
                qspi.fit_sha256, expected_fit_sha256
            ):
                raise IpFirmwareError("reconciled MTD3 FIT does not match expected image")
            self._key_reconciliation_required = False
            return (
                "reconciled_remote_attestation",
                "reconciled_tx_safe",
                "reconciled_qspi_fit_verified",
            )
        except BaseException as error:
            if isinstance(error, FirmwareExecutorFailure):
                raise
            raise FirmwareExecutorFailure(
                str(error),
                outcome="unknown",
                failure_phase="reconciliation",
                reconciliation_required=True,
            ) from error

    def _wait_for_return(self, previous_boot_id: str) -> tuple[IpFirmwareAttestation, bool]:
        deadline = self._monotonic() + self._return_timeout
        last_error: BaseException | None = None
        key_changed = False
        while self._monotonic() < deadline:
            try:
                attestation = self.attest()
                if attestation.boot_id != previous_boot_id:
                    return attestation, False
            except IpFirmwareHostKeyChanged as error:
                key_changed = True
                self._key_reconciliation_required = True
                last_error = error
                break
            except BaseException as error:
                last_error = error
            self._sleep(self._poll_interval)
        if key_changed and self._post_reset_probe is not None:
            identity = self._post_reset_probe(self.enrollment.serial)
            if (
                identity.serial != self.enrollment.serial
                or identity.endpoint != self.enrollment.endpoint
                or identity.usb_sysfs_path is not None
            ):
                raise IpFirmwareError("independent post-reset identity did not match enrollment")
            return (
                IpFirmwareAttestation(
                    serial=identity.serial,
                    board_model=self.enrollment.board_model,
                    active_firmware=identity.observed_firmware,
                    boot_id=None,
                    endpoint=self.enrollment.endpoint,
                    host_key_fingerprint="unverified:host-key-changed",
                ),
                True,
            )
        raise IpFirmwareError(f"radio did not return through enrolled SSH identity: {last_error}")

    def _ensure_post_reset_tx_safe(self, key_changed: bool) -> None:
        if key_changed:
            if self._post_reset_tx_guard is None or not self._post_reset_tx_guard(
                self.enrollment.serial
            ):
                raise IpFirmwareError(
                    "pinned SSH key changed and no independent strict TX-safe readback passed"
                )
            return
        self.transport.ensure_tx_safe(self.enrollment.serial)

    def _validate_stable_attestation(self, attestation: IpFirmwareAttestation) -> None:
        if (
            attestation.serial != self.enrollment.serial
            or attestation.endpoint != self.enrollment.endpoint
            or attestation.board_model != self.enrollment.board_model
            or not hmac.compare_digest(
                attestation.host_key_fingerprint, self.enrollment.host_key_fingerprint
            )
        ):
            raise IpFirmwareError("remote radio identity does not match SSH enrollment")

    def _validate_radio_binding(
        self, radio: RadioFirmwareIdentity, attestation: IpFirmwareAttestation
    ) -> None:
        if radio.usb_sysfs_path is not None:
            raise IpFirmwareError("SSH firmware identity must not contain a USB sysfs path")
        if (
            radio.serial != attestation.serial
            or radio.endpoint != attestation.endpoint
            or radio.host_key_fingerprint != attestation.host_key_fingerprint
            or radio.observed_firmware != attestation.active_firmware
        ):
            raise IpFirmwareError("radio state changed after IP firmware planning")

    def _start_evidence(self, image: Path) -> IpFirmwareEvidence:
        now = self._now()
        evidence = IpFirmwareEvidence(
            schema_version=1,
            attempt_id=uuid.uuid4().hex,
            started_at=now,
            finished_at=None,
            enrollment=self.enrollment,
            frm_sha256="",
            frm_size=0,
            fit_sha256="",
            fit_size=0,
            outcome="in_progress",
            completed_phases=(),
            failure_phase=None,
            mutation_dispatched=False,
            reconciliation_required=False,
            key_reconciliation_required=False,
            before=None,
            staged=None,
            qspi=None,
            after=None,
            updater_output=None,
            error=None,
        )
        del image
        return self._record(evidence)

    def _finish_failure(
        self, evidence: IpFirmwareEvidence, phase: str, error: BaseException
    ) -> None:
        after_dispatch = evidence.mutation_dispatched
        key_changed = self._key_reconciliation_required or isinstance(
            error, IpFirmwareHostKeyChanged
        ) or (
            "host key changed" in str(error).lower()
        )
        if key_changed:
            self._key_reconciliation_required = True
        final = replace(
            evidence,
            finished_at=self._now(),
            outcome="unknown" if after_dispatch else "failed",
            failure_phase=phase,
            reconciliation_required=after_dispatch,
            key_reconciliation_required=(
                evidence.key_reconciliation_required or key_changed
            ),
            error=f"{type(error).__name__}: {error}",
        )
        try:
            final = self._record(final)
        except BaseException as journal_error:
            error = IpFirmwareError(f"{error}; evidence journal failed: {journal_error}")
        failure = FirmwareExecutorFailure(
            str(error),
            outcome="unknown" if after_dispatch else "failed",
            completed_phases=final.completed_phases,
            failure_phase=phase,
            reconciliation_required=after_dispatch,
            evidence_reference=final.attempt_id,
        )
        failure.evidence = final
        raise failure from error

    def _record(self, evidence: IpFirmwareEvidence) -> IpFirmwareEvidence:
        self.evidence_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        details = self.evidence_directory.lstat()
        if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
            raise IpFirmwareError("firmware evidence directory must be a real directory")
        os.chmod(self.evidence_directory, 0o700)
        payload = asdict(evidence)
        payload["started_at"] = evidence.started_at.isoformat()
        payload["finished_at"] = (
            evidence.finished_at.isoformat() if evidence.finished_at is not None else None
        )
        encoded = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
        destination = self.evidence_directory / f"{evidence.attempt_id}.json"
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{evidence.attempt_id}.", dir=self.evidence_directory
        )
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, destination)
            directory_fd = os.open(self.evidence_directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
        self._last_evidence = evidence
        return evidence

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise ValueError("IP firmware clock must return a timezone-aware datetime")
        return value.astimezone(UTC)


def _validate_private_file(path: Path, label: str) -> None:
    try:
        details = path.lstat()
    except OSError as error:
        raise ValueError(f"{label} is not readable") from error
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode):
        raise ValueError(f"{label} must be a regular non-symlink file")
    if details.st_mode & 0o077:
        raise ValueError(f"{label} must not be group/other accessible")


def _file_sha256(path: Path, label: str) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise ValueError(f"{label} is not readable") from error


def _validate_fixed_command(command: str) -> None:
    if "\x00" in command:
        raise IpFirmwareError("invalid fixed SSH command")
    if command in {
        _ATTEST_COMMAND,
        _STAGE_COMMAND,
        _UPDATE_COMMAND,
        _CLEANUP_COMMAND,
        _SYNC_COMMAND,
        _RESET_COMMAND,
    }:
        return
    if re.fullmatch(r"/bin/sh -s -- [A-Za-z0-9._:-]{1,128}", command):
        return
    if re.fullmatch(
        r"/bin/sh -s -- [A-Za-z0-9._:-]{1,128} [0-9a-f]{64} [0-9a-f]{32}"
        r"(?: (?:ipaddr|ipaddr_host|netmask|ipaddr_eth|netmask_eth)"
        r" (?:[0-9.]{7,15}|__DELETE__)){1,3}",
        command,
    ):
        return
    raise IpFirmwareError("SSH command is outside the fixed firmware operation set")


def pinned_ssh_host_key_fingerprint(
    known_hosts_file: Path, endpoint: str, *, port: int = 22
) -> str:
    """Return one exact endpoint's fingerprint from a private pinned key file."""

    try:
        normalized = str(ipaddress.ip_address(endpoint))
    except ValueError as error:
        raise ValueError("SSH endpoint must be a literal IP address") from error
    if normalized != endpoint:
        raise ValueError("SSH endpoint must use canonical IP notation")
    if not 1 <= port <= 65535:
        raise ValueError("SSH port is outside 1..65535")
    _validate_private_file(known_hosts_file, "SSH known-hosts")
    fingerprint, _algorithm = _pinned_host_key(known_hosts_file, endpoint, port)
    return fingerprint


def _pinned_host_key(path: Path, endpoint: str, port: int) -> tuple[str, str]:
    expected_host = endpoint if port == 22 else f"[{endpoint}]:{port}"
    matches: list[tuple[str, str]] = []
    try:
        lines = path.read_text().splitlines()
    except (OSError, UnicodeError) as error:
        raise ValueError("SSH known-hosts file is not readable text") from error
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("@"):
            continue
        fields = stripped.split()
        if len(fields) < 3 or not any(
            _known_host_pattern_matches(pattern, expected_host)
            for pattern in fields[0].split(",")
        ):
            continue
        algorithm, encoded = fields[1], fields[2]
        if not re.fullmatch(
            r"(?:ssh-ed25519|ssh-rsa|rsa-sha2-(?:256|512)|"
            r"ecdsa-sha2-nistp(?:256|384|521))",
            algorithm,
        ):
            raise ValueError("SSH known-hosts contains an unsupported host-key algorithm")
        try:
            key = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as error:
            raise ValueError("SSH known-hosts contains an invalid public key") from error
        digest = base64.b64encode(hashlib.sha256(key).digest()).decode().rstrip("=")
        matches.append((f"SHA256:{digest}", algorithm))
    if len(matches) != 1:
        raise ValueError(
            "SSH known-hosts must contain exactly one pinned key for the endpoint"
        )
    return matches[0]


def _known_host_pattern_matches(pattern: str, expected_host: str) -> bool:
    if pattern == expected_host:
        return True
    parts = pattern.split("|")
    if len(parts) != 4 or parts[:2] != ["", "1"]:
        return False
    try:
        salt = base64.b64decode(parts[2], validate=True)
        expected_digest = base64.b64decode(parts[3], validate=True)
    except (ValueError, binascii.Error):
        return False
    if not salt or len(expected_digest) != hashlib.sha1().digest_size:  # noqa: S324
        return False
    observed_digest = hmac.new(
        salt,
        expected_host.encode(),
        digestmod=hashlib.sha1,  # noqa: S324 - OpenSSH known_hosts format is fixed to HMAC-SHA1.
    ).digest()
    return hmac.compare_digest(observed_digest, expected_digest)


def _parse_report(output: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in output.splitlines():
        if not line.startswith("PPU\t"):
            continue
        parts = line.split("\t", 2)
        if len(parts) != 3 or not parts[1] or parts[1] in fields:
            raise IpFirmwareError("malformed or duplicate remote report field")
        fields[parts[1]] = parts[2]
    return fields


def _required(fields: dict[str, str], key: str) -> str:
    value = fields.get(key, "")
    if not value:
        raise IpFirmwareError(f"remote report omitted {key}")
    return value


def _required_digest(fields: dict[str, str], key: str) -> str:
    value = _required(fields, key)
    if not _DIGEST_RE.fullmatch(value):
        raise IpFirmwareError(f"remote report contained invalid {key}")
    return value


def _required_positive_int(fields: dict[str, str], key: str) -> int:
    value = _required(fields, key)
    if not value.isascii() or not value.isdigit() or int(value) <= 0:
        raise IpFirmwareError(f"remote report contained invalid {key}")
    return int(value)


def _bounded_text(value: str, limit: int = 4096) -> str:
    cleaned = value.replace("\x00", "�")
    return cleaned if len(cleaned) <= limit else cleaned[-limit:]


def _decode_bounded_base64(value: str, *, label: str, maximum_bytes: int) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except binascii.Error as error:
        raise IpFirmwareError(f"{label} is not valid base64") from error
    if not decoded or len(decoded) > maximum_bytes:
        raise IpFirmwareError(f"{label} is empty or exceeds its size limit")
    return decoded
