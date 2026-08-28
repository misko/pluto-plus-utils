"""Guarded Pluto ``config.txt`` inspection and structured network changes.

The radio's ``/opt/config.txt`` is generated from persistent U-Boot variables at
boot.  This module deliberately exposes a redacted read view and a narrow plan
for the documented network variables; it is not a generic file or environment
editor.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import uuid
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from ipaddress import IPv4Address, IPv4Network, ip_address
from pathlib import Path
from typing import Literal, Protocol

from pydantic import Field, field_validator

from pluto_plus.models import ApiModel

NETWORK_KEYS = (
    "ipaddr",
    "ipaddr_host",
    "netmask",
    "ipaddr_eth",
    "netmask_eth",
)


class NetworkConfigError(RuntimeError):
    """Base class for guarded network-configuration failures."""


class NetworkConfigUnavailableError(NetworkConfigError):
    """The selected radio has no explicit administrative enrollment."""


class NetworkConfigPreconditionError(NetworkConfigError):
    """Identity or persistent configuration changed after planning."""


class NetworkConfigAuthorizationError(NetworkConfigError):
    """A confirmation, token, or plan binding is invalid."""


class NetworkConfigPlanNotFoundError(NetworkConfigError):
    """The requested in-memory plan is unknown."""


class NetworkConfigExecutionError(NetworkConfigError):
    def __init__(self, message: str, receipt: NetworkConfigReceipt) -> None:
        super().__init__(message)
        self.receipt = receipt


class NetworkInterface(StrEnum):
    ETHERNET = "ethernet"
    USB_GADGET = "usb_gadget"


class NetworkAddressMode(StrEnum):
    STATIC = "static"
    DHCP = "dhcp"


class NetworkConfigIdentity(ApiModel):
    serial: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    endpoint: str = Field(min_length=1, max_length=64)
    host_key_fingerprint: str = Field(pattern=r"^SHA256:[A-Za-z0-9+/]{43}$")

    @field_validator("endpoint")
    @classmethod
    def validate_endpoint(cls, value: str) -> str:
        address = ip_address(value)
        if not isinstance(address, IPv4Address) or str(address) != value:
            raise ValueError("network-config endpoint must be canonical IPv4")
        return value


class NetworkConfigObservation(ApiModel):
    identity: NetworkConfigIdentity
    config_txt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    environment_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    config_txt_redacted: str = Field(max_length=65_536)
    hostname: str = Field(min_length=1, max_length=255)
    usb_radio_address: str
    usb_host_address: str
    usb_netmask: str
    ethernet_address: str | None
    ethernet_runtime_address: str | None = None
    ethernet_netmask: str

    @field_validator(
        "usb_radio_address",
        "usb_host_address",
        "usb_netmask",
        "ethernet_netmask",
    )
    @classmethod
    def validate_required_ipv4(cls, value: str) -> str:
        _ipv4(value, label="observed network value")
        return value

    @field_validator("ethernet_address", "ethernet_runtime_address")
    @classmethod
    def validate_optional_ipv4(cls, value: str | None) -> str | None:
        if value is not None:
            _ipv4(value, label="observed Ethernet address")
        return value

    @property
    def ethernet_mode(self) -> NetworkAddressMode:
        return (
            NetworkAddressMode.STATIC
            if self.ethernet_address is not None
            else NetworkAddressMode.DHCP
        )


class NetworkConfigExecutionResult(ApiModel):
    observation: NetworkConfigObservation
    backup_path: str = Field(min_length=1, max_length=1024)
    backup_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    backup_content: bytes = Field(exclude=True, max_length=131_072)
    completed_phases: tuple[str, ...]


class NetworkConfigBackend(Protocol):
    def inspect_network_config(self, serial: str) -> NetworkConfigObservation: ...

    def apply_network_config(
        self, plan: NetworkConfigPlan
    ) -> NetworkConfigExecutionResult: ...


@dataclass(frozen=True, slots=True)
class NetworkConfigPlan:
    plan_id: str
    created_at: datetime
    expires_at: datetime
    identity: NetworkConfigIdentity
    before: NetworkConfigObservation
    interface: NetworkInterface
    mode: NetworkAddressMode
    address: str | None
    netmask: str | None
    host_address: str | None
    changes_items: tuple[tuple[str, str], ...]
    confirmation: str
    endpoint_after_restart: str | None
    restart_required: bool = True

    @property
    def changes(self) -> dict[str, str]:
        return dict(self.changes_items)


@dataclass(frozen=True, slots=True)
class PlannedNetworkConfig:
    plan: NetworkConfigPlan
    confirmation_token: str


@dataclass(frozen=True, slots=True)
class NetworkConfigReceipt:
    schema_version: int
    receipt_id: str
    plan_id: str
    started_at: datetime
    finished_at: datetime
    identity: NetworkConfigIdentity
    interface: NetworkInterface
    mode: NetworkAddressMode
    changes_items: tuple[tuple[str, str], ...]
    before_environment_sha256: str
    after_environment_sha256: str | None
    backup_path: str | None
    backup_sha256: str | None
    endpoint_after_restart: str | None
    restart_required: bool
    outcome: Literal["persisted_restart_required", "unknown"]
    completed_phases: tuple[str, ...]
    success: bool
    error: str | None

    @property
    def changes(self) -> dict[str, str]:
        return dict(self.changes_items)


@dataclass(slots=True)
class _TokenRecord:
    digest: bytes
    plan: NetworkConfigPlan
    expires_at: datetime
    used: bool = False


class NetworkConfigManager:
    """Inspect and plan exact, validated changes to Pluto network variables."""

    def __init__(
        self,
        *,
        identity: NetworkConfigIdentity,
        backend: NetworkConfigBackend,
        receipt_directory: Path,
        clock: Callable[[], datetime] | None = None,
        confirmation_ttl: timedelta = timedelta(minutes=5),
    ) -> None:
        if confirmation_ttl <= timedelta(0):
            raise ValueError("network-config confirmation TTL must be positive")
        self.identity = identity
        self._backend = backend
        self._receipt_directory = receipt_directory
        self._clock = clock or (lambda: datetime.now(UTC))
        self._ttl = confirmation_ttl
        self._tokens: dict[str, _TokenRecord] = {}
        self._receipts: dict[str, NetworkConfigReceipt] = {}
        self._lock = threading.Lock()
        self._load_receipts()

    def inspect(self) -> NetworkConfigObservation:
        observation = self._backend.inspect_network_config(self.identity.serial)
        if observation.identity != self.identity:
            raise NetworkConfigPreconditionError(
                "network-config backend returned a different enrolled identity"
            )
        return observation

    def create_plan(
        self,
        *,
        interface: NetworkInterface,
        mode: NetworkAddressMode,
        address: str | None,
        netmask: str | None,
        host_address: str | None,
    ) -> PlannedNetworkConfig:
        before = self.inspect()
        normalized_address, normalized_netmask, normalized_host = _validate_request(
            interface=interface,
            mode=mode,
            address=address,
            netmask=netmask,
            host_address=host_address,
        )
        _validate_nonoverlapping_interfaces(
            before,
            interface=interface,
            address=normalized_address,
            netmask=normalized_netmask,
        )
        if interface is NetworkInterface.ETHERNET:
            changes = {
                "ipaddr_eth": "" if normalized_address is None else normalized_address,
            }
            if normalized_netmask is not None:
                changes["netmask_eth"] = normalized_netmask
            confirmation = (
                f"SET DHCP {self.identity.serial}"
                if mode is NetworkAddressMode.DHCP
                else f"SET STATIC IP {self.identity.serial} {normalized_address}"
            )
            endpoint_after_restart = normalized_address
        else:
            assert normalized_address is not None
            assert normalized_netmask is not None
            assert normalized_host is not None
            changes = {
                "ipaddr": normalized_address,
                "ipaddr_host": normalized_host,
                "netmask": normalized_netmask,
            }
            confirmation = f"SET USB IP {self.identity.serial} {normalized_address}"
            endpoint_after_restart = self.identity.endpoint
        current = _persistent_values(before)
        changed = tuple(
            (key, value) for key, value in changes.items() if current.get(key) != value
        )
        if not changed:
            raise NetworkConfigPreconditionError(
                "requested network configuration is already persistent"
            )
        now = self._now()
        plan = NetworkConfigPlan(
            plan_id=uuid.uuid4().hex,
            created_at=now,
            expires_at=now + self._ttl,
            identity=self.identity,
            before=before,
            interface=interface,
            mode=mode,
            address=normalized_address,
            netmask=normalized_netmask,
            host_address=normalized_host,
            changes_items=changed,
            confirmation=confirmation,
            endpoint_after_restart=endpoint_after_restart,
        )
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._tokens[plan.plan_id] = _TokenRecord(
                digest=hashlib.sha256(token.encode()).digest(),
                plan=plan,
                expires_at=plan.expires_at,
            )
        return PlannedNetworkConfig(plan, token)

    def execute(
        self,
        plan: NetworkConfigPlan,
        confirmation_token: str,
        operator_confirmation: str,
        *,
        before_mutation: Callable[[], None] | None = None,
        after_mutation: Callable[[], None] | None = None,
    ) -> NetworkConfigReceipt:
        if operator_confirmation != plan.confirmation:
            raise NetworkConfigAuthorizationError(
                f"confirmation must exactly match {plan.confirmation!r}"
            )
        now = self._now()
        self._authorize(plan, confirmation_token, now, consume=False)
        current = self.inspect()
        if current.environment_sha256 != plan.before.environment_sha256:
            raise NetworkConfigPreconditionError(
                "persistent network configuration changed after plan creation"
            )
        self._authorize(plan, confirmation_token, now, consume=True)
        started = self._now()
        result: NetworkConfigExecutionResult | None = None
        local_backup_path: str | None = None
        error: str | None = None
        prepared = False
        try:
            if before_mutation is not None:
                before_mutation()
                prepared = True
            result = self._backend.apply_network_config(plan)
            local_backup_path = result.backup_path
            self._validate_result(plan, result)
            local_backup_path = self._persist_backup(plan, result)
        except BaseException as caught:
            error = f"{type(caught).__name__}: {caught}"
        finally:
            if prepared and after_mutation is not None:
                try:
                    after_mutation()
                except BaseException as caught:
                    recovery = f"{type(caught).__name__}: {caught}"
                    error = recovery if error is None else f"{error}; recovery failed: {recovery}"
        receipt = NetworkConfigReceipt(
            schema_version=1,
            receipt_id=uuid.uuid4().hex,
            plan_id=plan.plan_id,
            started_at=started,
            finished_at=self._now(),
            identity=plan.identity,
            interface=plan.interface,
            mode=plan.mode,
            changes_items=plan.changes_items,
            before_environment_sha256=plan.before.environment_sha256,
            after_environment_sha256=(
                None if result is None else result.observation.environment_sha256
            ),
            backup_path=local_backup_path,
            backup_sha256=None if result is None else result.backup_sha256,
            endpoint_after_restart=plan.endpoint_after_restart,
            restart_required=True,
            outcome=("persisted_restart_required" if error is None else "unknown"),
            completed_phases=(
                () if result is None else result.completed_phases
            ),
            success=error is None,
            error=error,
        )
        self._write_receipt(receipt)
        with self._lock:
            self._receipts[receipt.receipt_id] = receipt
        if error is not None:
            raise NetworkConfigExecutionError(error, receipt)
        return receipt

    def list_receipts(self) -> list[NetworkConfigReceipt]:
        with self._lock:
            return sorted(
                self._receipts.values(), key=lambda item: item.started_at, reverse=True
            )

    def _validate_result(
        self, plan: NetworkConfigPlan, result: NetworkConfigExecutionResult
    ) -> None:
        if result.observation.identity != plan.identity:
            raise NetworkConfigPreconditionError("post-write identity changed")
        values = _persistent_values(result.observation)
        if any(values.get(key) != expected for key, expected in plan.changes_items):
            raise NetworkConfigPreconditionError(
                "persistent network readback does not match the plan"
            )
        if result.observation.environment_sha256 == plan.before.environment_sha256:
            raise NetworkConfigPreconditionError("persistent environment digest did not change")

    def _authorize(
        self,
        plan: NetworkConfigPlan,
        token: str,
        now: datetime,
        *,
        consume: bool,
    ) -> None:
        presented = hashlib.sha256(token.encode()).digest()
        with self._lock:
            record = self._tokens.get(plan.plan_id)
            if record is None or not hmac.compare_digest(record.digest, presented):
                raise NetworkConfigAuthorizationError("confirmation token is invalid")
            if record.plan != plan:
                raise NetworkConfigAuthorizationError(
                    "confirmation token is bound to another plan"
                )
            if record.used:
                raise NetworkConfigAuthorizationError("confirmation token was already used")
            if now >= record.expires_at:
                raise NetworkConfigAuthorizationError("confirmation token has expired")
            if consume:
                record.used = True

    def _write_receipt(self, receipt: NetworkConfigReceipt) -> None:
        self._receipt_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self._receipt_directory, 0o700)
        payload = asdict(receipt)
        payload["started_at"] = receipt.started_at.isoformat()
        payload["finished_at"] = receipt.finished_at.isoformat()
        payload["identity"] = receipt.identity.model_dump(mode="json")
        payload["interface"] = receipt.interface.value
        payload["mode"] = receipt.mode.value
        destination = self._receipt_directory / f"{receipt.receipt_id}.json"
        encoded = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
        descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        directory_fd = os.open(self._receipt_directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    def _persist_backup(
        self, plan: NetworkConfigPlan, result: NetworkConfigExecutionResult
    ) -> str:
        if not hmac.compare_digest(
            hashlib.sha256(result.backup_content).hexdigest(), result.backup_sha256
        ):
            raise NetworkConfigPreconditionError(
                "persistent environment backup digest is inconsistent"
            )
        backup_directory = self._receipt_directory / "backups"
        backup_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(backup_directory, 0o700)
        destination = backup_directory / f"{plan.plan_id}.env"
        descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(result.backup_content)
            stream.flush()
            os.fsync(stream.fileno())
        directory_fd = os.open(backup_directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return str(destination)

    def _load_receipts(self) -> None:
        if not self._receipt_directory.exists():
            return
        for path in sorted(self._receipt_directory.glob("*.json")):
            try:
                document = json.loads(path.read_bytes())
                receipt = NetworkConfigReceipt(
                    schema_version=int(document["schema_version"]),
                    receipt_id=str(document["receipt_id"]),
                    plan_id=str(document["plan_id"]),
                    started_at=datetime.fromisoformat(document["started_at"]),
                    finished_at=datetime.fromisoformat(document["finished_at"]),
                    identity=NetworkConfigIdentity.model_validate(document["identity"]),
                    interface=NetworkInterface(document["interface"]),
                    mode=NetworkAddressMode(document["mode"]),
                    changes_items=tuple(tuple(item) for item in document["changes_items"]),
                    before_environment_sha256=str(document["before_environment_sha256"]),
                    after_environment_sha256=document["after_environment_sha256"],
                    backup_path=document["backup_path"],
                    backup_sha256=document["backup_sha256"],
                    endpoint_after_restart=document["endpoint_after_restart"],
                    restart_required=bool(document["restart_required"]),
                    outcome=document["outcome"],
                    completed_phases=tuple(document["completed_phases"]),
                    success=bool(document["success"]),
                    error=document["error"],
                )
            except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                continue
            self._receipts[receipt.receipt_id] = receipt

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise ValueError("network-config clock must be timezone-aware")
        return value.astimezone(UTC)


def _persistent_values(observation: NetworkConfigObservation) -> dict[str, str]:
    return {
        "ipaddr": observation.usb_radio_address,
        "ipaddr_host": observation.usb_host_address,
        "netmask": observation.usb_netmask,
        "ipaddr_eth": observation.ethernet_address or "",
        "netmask_eth": observation.ethernet_netmask,
    }


def persistent_environment_sha256(values: Mapping[str, str]) -> str:
    if set(values) != set(NETWORK_KEYS):
        raise ValueError("network environment digest requires the exact key set")
    canonical = "".join(f"{key}={values[key]}\n" for key in NETWORK_KEYS).encode()
    return hashlib.sha256(canonical).hexdigest()


def _validate_request(
    *,
    interface: NetworkInterface,
    mode: NetworkAddressMode,
    address: str | None,
    netmask: str | None,
    host_address: str | None,
) -> tuple[str | None, str | None, str | None]:
    if mode is NetworkAddressMode.DHCP:
        if interface is not NetworkInterface.ETHERNET:
            raise NetworkConfigPreconditionError("DHCP is supported only for Ethernet")
        if any(value is not None for value in (address, netmask, host_address)):
            raise NetworkConfigPreconditionError(
                "DHCP plans cannot include address, netmask, or host address"
            )
        return None, None, None
    if address is None or netmask is None:
        raise NetworkConfigPreconditionError(
            "static addressing requires an address and netmask"
        )
    normalized_address = _local_unicast(address, label="static address")
    normalized_mask = _netmask(netmask)
    network = IPv4Network((normalized_address, normalized_mask), strict=False)
    candidate = IPv4Address(normalized_address)
    if candidate in {network.network_address, network.broadcast_address}:
        raise NetworkConfigPreconditionError(
            "static address cannot be the subnet network or broadcast address"
        )
    if interface is NetworkInterface.ETHERNET:
        if host_address is not None:
            raise NetworkConfigPreconditionError(
                "Ethernet static plans do not accept a USB host address"
            )
        return normalized_address, normalized_mask, None
    if host_address is None:
        raise NetworkConfigPreconditionError(
            "USB gadget static plans require the paired host address"
        )
    normalized_host = _local_unicast(host_address, label="USB host address")
    host = IPv4Address(normalized_host)
    if host not in network or host in {
        network.network_address,
        network.broadcast_address,
        candidate,
    }:
        raise NetworkConfigPreconditionError(
            "USB host address must be a distinct usable address in the same subnet"
        )
    return normalized_address, normalized_mask, normalized_host


def _ipv4(value: str, *, label: str) -> IPv4Address:
    try:
        address = ip_address(value)
    except ValueError as error:
        raise ValueError(f"{label} must be IPv4") from error
    if not isinstance(address, IPv4Address) or str(address) != value:
        raise ValueError(f"{label} must use canonical IPv4 notation")
    return address


def _local_unicast(value: str, *, label: str) -> str:
    try:
        address = _ipv4(value, label=label)
    except ValueError as error:
        raise NetworkConfigPreconditionError(str(error)) from error
    if (
        not (address.is_private or address.is_link_local)
        or address.is_loopback
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
    ):
        raise NetworkConfigPreconditionError(
            f"{label} must be private or link-local unicast"
        )
    return str(address)


def _netmask(value: str) -> str:
    try:
        network = IPv4Network(f"0.0.0.0/{value}")
    except ValueError as error:
        raise NetworkConfigPreconditionError(
            "netmask must be a contiguous dotted-decimal IPv4 mask"
        ) from error
    if network.prefixlen in {0, 31, 32}:
        raise NetworkConfigPreconditionError("netmask must leave at least two usable hosts")
    return str(network.netmask)


def _validate_nonoverlapping_interfaces(
    before: NetworkConfigObservation,
    *,
    interface: NetworkInterface,
    address: str | None,
    netmask: str | None,
) -> None:
    if address is None or netmask is None:
        return
    proposed = IPv4Network((address, netmask), strict=False)
    if interface is NetworkInterface.ETHERNET:
        other = IPv4Network(
            (before.usb_radio_address, before.usb_netmask), strict=False
        )
        other_label = "USB gadget"
    elif before.ethernet_address is not None:
        other = IPv4Network(
            (before.ethernet_address, before.ethernet_netmask), strict=False
        )
        other_label = "Ethernet"
    else:
        return
    if proposed.overlaps(other):
        raise NetworkConfigPreconditionError(
            f"proposed subnet overlaps the existing {other_label} subnet"
        )
