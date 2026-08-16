from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from pluto_plus.network_config import (
    NetworkAddressMode,
    NetworkConfigAuthorizationError,
    NetworkConfigExecutionError,
    NetworkConfigExecutionResult,
    NetworkConfigIdentity,
    NetworkConfigManager,
    NetworkConfigObservation,
    NetworkConfigPlan,
    NetworkConfigPreconditionError,
    NetworkInterface,
    persistent_environment_sha256,
)


class Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 8, 16, 12, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.value


class Backend:
    def __init__(self, observation: NetworkConfigObservation) -> None:
        self.observation = observation
        self.apply_calls = 0
        self.failure: BaseException | None = None

    def inspect_network_config(self, serial: str) -> NetworkConfigObservation:
        assert serial == self.observation.identity.serial
        return self.observation

    def apply_network_config(
        self, plan: NetworkConfigPlan
    ) -> NetworkConfigExecutionResult:
        self.apply_calls += 1
        if self.failure is not None:
            raise self.failure
        values = {
            "ipaddr": self.observation.usb_radio_address,
            "ipaddr_host": self.observation.usb_host_address,
            "netmask": self.observation.usb_netmask,
            "ipaddr_eth": self.observation.ethernet_address or "",
            "netmask_eth": self.observation.ethernet_netmask,
        }
        values.update(plan.changes)
        self.observation = self.observation.model_copy(
            update={
                "environment_sha256": persistent_environment_sha256(values),
                "usb_radio_address": values["ipaddr"],
                "usb_host_address": values["ipaddr_host"],
                "usb_netmask": values["netmask"],
                "ethernet_address": values["ipaddr_eth"] or None,
                "ethernet_netmask": values["netmask_eth"],
            }
        )
        return NetworkConfigExecutionResult(
            observation=self.observation,
            backup_path="/root/.pluto-plus-network-config/plan.env",
            backup_sha256=hashlib.sha256(b"persistent environment\n").hexdigest(),
            backup_content=b"persistent environment\n",
            completed_phases=(
                "identity_attested",
                "environment_revalidated",
                "backup_persisted",
                "environment_written",
                "persistent_readback_verified",
            ),
        )


def _identity() -> NetworkConfigIdentity:
    return NetworkConfigIdentity(
        serial="SERIAL_A",
        endpoint="192.168.1.165",
        host_key_fingerprint="SHA256:" + "A" * 43,
    )


def _observation() -> NetworkConfigObservation:
    values = {
        "ipaddr": "192.168.2.1",
        "ipaddr_host": "192.168.2.10",
        "netmask": "255.255.255.0",
        "ipaddr_eth": "",
        "netmask_eth": "255.255.255.0",
    }
    return NetworkConfigObservation(
        identity=_identity(),
        config_txt_sha256="a" * 64,
        environment_sha256=persistent_environment_sha256(values),
        config_txt_redacted="[NETWORK]\r\nipaddr = 192.168.2.1\r\n",
        hostname="pluto",
        usb_radio_address=values["ipaddr"],
        usb_host_address=values["ipaddr_host"],
        usb_netmask=values["netmask"],
        ethernet_address=None,
        ethernet_netmask=values["netmask_eth"],
    )


def _manager(tmp_path: Path) -> tuple[NetworkConfigManager, Backend, Clock]:
    backend = Backend(_observation())
    clock = Clock()
    manager = NetworkConfigManager(
        identity=_identity(),
        backend=backend,
        receipt_directory=tmp_path / "receipts",
        clock=clock,
    )
    return manager, backend, clock


def test_inspect_returns_redacted_config_and_structured_addresses(tmp_path: Path) -> None:
    manager, _, _ = _manager(tmp_path)
    observed = manager.inspect()
    assert observed.config_txt_redacted.startswith("[NETWORK]")
    assert observed.ethernet_mode is NetworkAddressMode.DHCP
    assert observed.usb_radio_address == "192.168.2.1"


def test_static_ethernet_plan_is_exact_and_execution_requires_confirmation(
    tmp_path: Path,
) -> None:
    manager, backend, _ = _manager(tmp_path)
    planned = manager.create_plan(
        interface=NetworkInterface.ETHERNET,
        mode=NetworkAddressMode.STATIC,
        address="192.168.1.165",
        netmask="255.255.255.0",
        host_address=None,
    )
    assert planned.plan.changes == {
        "ipaddr_eth": "192.168.1.165",
    }
    assert planned.plan.confirmation == "SET STATIC IP SERIAL_A 192.168.1.165"
    with pytest.raises(NetworkConfigAuthorizationError, match="exactly match"):
        manager.execute(planned.plan, planned.confirmation_token, "SERIAL_A")
    receipt = manager.execute(
        planned.plan,
        planned.confirmation_token,
        planned.plan.confirmation,
    )
    assert backend.apply_calls == 1
    assert receipt.success is True
    assert receipt.outcome == "persisted_restart_required"
    assert receipt.endpoint_after_restart == "192.168.1.165"
    assert receipt.backup_sha256 == hashlib.sha256(
        b"persistent environment\n"
    ).hexdigest()
    assert receipt.backup_path is not None
    assert Path(receipt.backup_path).read_bytes() == b"persistent environment\n"


def test_dhcp_and_usb_static_plans_have_distinct_safe_contracts(tmp_path: Path) -> None:
    manager, backend, _ = _manager(tmp_path)
    backend.observation = backend.observation.model_copy(
        update={
            "ethernet_address": "192.168.1.165",
            "environment_sha256": persistent_environment_sha256(
                {
                    "ipaddr": "192.168.2.1",
                    "ipaddr_host": "192.168.2.10",
                    "netmask": "255.255.255.0",
                    "ipaddr_eth": "192.168.1.165",
                    "netmask_eth": "255.255.255.0",
                }
            ),
        }
    )
    dhcp = manager.create_plan(
        interface=NetworkInterface.ETHERNET,
        mode=NetworkAddressMode.DHCP,
        address=None,
        netmask=None,
        host_address=None,
    )
    assert dhcp.plan.changes == {"ipaddr_eth": ""}
    assert dhcp.plan.confirmation == "SET DHCP SERIAL_A"

    usb_manager, _, _ = _manager(tmp_path / "usb")
    usb = usb_manager.create_plan(
        interface=NetworkInterface.USB_GADGET,
        mode=NetworkAddressMode.STATIC,
        address="192.168.7.1",
        netmask="255.255.255.0",
        host_address="192.168.7.10",
    )
    assert usb.plan.changes == {
        "ipaddr": "192.168.7.1",
        "ipaddr_host": "192.168.7.10",
    }
    assert usb.plan.endpoint_after_restart == "192.168.1.165"


@pytest.mark.parametrize(
    ("interface", "mode", "address", "netmask", "host_address", "message"),
    [
        ("ethernet", "static", "8.8.8.8", "255.255.255.0", None, "private"),
        ("ethernet", "static", "100.64.0.1", "255.255.255.0", None, "private"),
        ("ethernet", "static", "192.168.1.0", "255.255.255.0", None, "network"),
        ("ethernet", "static", "192.168.1.10", "255.0.255.0", None, "contiguous"),
        ("usb_gadget", "dhcp", None, None, None, "only for Ethernet"),
        (
            "usb_gadget",
            "static",
            "192.168.7.1",
            "255.255.255.0",
            "192.168.8.10",
            "same subnet",
        ),
    ],
)
def test_invalid_or_unsafe_address_plans_are_rejected(
    tmp_path: Path,
    interface: str,
    mode: str,
    address: str | None,
    netmask: str | None,
    host_address: str | None,
    message: str,
) -> None:
    manager, backend, _ = _manager(tmp_path)
    with pytest.raises(NetworkConfigPreconditionError, match=message):
        manager.create_plan(
            interface=NetworkInterface(interface),
            mode=NetworkAddressMode(mode),
            address=address,
            netmask=netmask,
            host_address=host_address,
        )
    assert backend.apply_calls == 0


def test_environment_drift_and_expired_or_reused_tokens_fail_closed(
    tmp_path: Path,
) -> None:
    manager, backend, clock = _manager(tmp_path)
    planned = manager.create_plan(
        interface=NetworkInterface.ETHERNET,
        mode=NetworkAddressMode.STATIC,
        address="192.168.1.165",
        netmask="255.255.255.0",
        host_address=None,
    )
    backend.observation = backend.observation.model_copy(
        update={"environment_sha256": "c" * 64}
    )
    with pytest.raises(NetworkConfigPreconditionError, match="changed"):
        manager.execute(
            planned.plan, planned.confirmation_token, planned.plan.confirmation
        )
    assert backend.apply_calls == 0

    manager, _, clock = _manager(tmp_path / "expired")
    expired = manager.create_plan(
        interface=NetworkInterface.ETHERNET,
        mode=NetworkAddressMode.STATIC,
        address="192.168.1.165",
        netmask="255.255.255.0",
        host_address=None,
    )
    clock.value += timedelta(minutes=6)
    with pytest.raises(NetworkConfigAuthorizationError, match="expired"):
        manager.execute(expired.plan, expired.confirmation_token, expired.plan.confirmation)


def test_static_interfaces_must_not_create_overlapping_subnets(tmp_path: Path) -> None:
    manager, _, _ = _manager(tmp_path)
    with pytest.raises(NetworkConfigPreconditionError, match="USB gadget subnet"):
        manager.create_plan(
            interface=NetworkInterface.ETHERNET,
            mode=NetworkAddressMode.STATIC,
            address="192.168.2.165",
            netmask="255.255.255.0",
            host_address=None,
        )


def test_unknown_execution_is_durably_receipted(tmp_path: Path) -> None:
    manager, backend, _ = _manager(tmp_path)
    planned = manager.create_plan(
        interface=NetworkInterface.ETHERNET,
        mode=NetworkAddressMode.STATIC,
        address="192.168.1.165",
        netmask="255.255.255.0",
        host_address=None,
    )
    backend.failure = RuntimeError("connection dropped during fw_setenv")
    with pytest.raises(NetworkConfigExecutionError) as caught:
        manager.execute(
            planned.plan, planned.confirmation_token, planned.plan.confirmation
        )
    assert caught.value.receipt.outcome == "unknown"
    assert caught.value.receipt.success is False
    restarted = NetworkConfigManager(
        identity=_identity(),
        backend=backend,
        receipt_directory=tmp_path / "receipts",
    )
    assert restarted.list_receipts()[0].receipt_id == caught.value.receipt.receipt_id


def test_plan_is_bound_to_exact_observation_and_identity(tmp_path: Path) -> None:
    manager, _, _ = _manager(tmp_path)
    planned = manager.create_plan(
        interface=NetworkInterface.ETHERNET,
        mode=NetworkAddressMode.STATIC,
        address="192.168.1.165",
        netmask="255.255.255.0",
        host_address=None,
    )
    forged = replace(planned.plan, endpoint_after_restart="192.168.1.166")
    with pytest.raises(NetworkConfigAuthorizationError, match="another plan"):
        manager.execute(forged, planned.confirmation_token, forged.confirmation)
