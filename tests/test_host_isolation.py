from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

import pytest

from pluto_plus.host_isolation import (
    HostIsolationExecutionError,
    execute_usb_ssh_isolated,
    prepare_usb_ssh_isolation,
)


class FakeRunner:
    def __init__(self, *, restore: bool = True) -> None:
        self.addresses = {
            "enx_selected": ("192.168.2.10",),
            "enx_peer": ("192.168.2.10",),
            "eth0": ("192.168.1.10",),
        }
        self.routes = {
            ("enx_selected", "192.168.2.0/24"),
            ("enx_peer", "192.168.2.0/24"),
            ("eth0", "192.168.0.0/22"),
        }
        self.restore = restore
        self.commands: list[tuple[str, ...]] = []

    def run(self, argv: Sequence[str], *, timeout_s: float = 10) -> str:
        command = tuple(argv)
        self.commands.append(command)
        if command[:5] == ("ip", "-j", "-4", "address", "show"):
            return json.dumps(
                [
                    {
                        "ifname": name,
                        "addr_info": [
                            {"family": "inet", "local": address}
                            for address in values
                        ],
                    }
                    for name, values in self.addresses.items()
                ]
            )
        if command[:6] == ("ip", "-j", "-4", "route", "show", "table"):
            return json.dumps(
                [
                    {
                        "dev": interface,
                        "dst": destination,
                        "protocol": "kernel",
                        "scope": "link",
                        "prefsrc": (
                            "192.168.1.10" if interface == "eth0" else "192.168.2.10"
                        ),
                        "metric": 1024,
                    }
                    for interface, destination in sorted(self.routes)
                ]
            )
        if command[:5] == ("sudo", "-n", "ip", "route", "del"):
            destination = command[5]
            interface = command[7]
            self.routes.discard((interface, destination))
            return ""
        if command[:5] == ("sudo", "-n", "ip", "route", "replace"):
            destination = command[5]
            interface = command[command.index("dev") + 1]
            self.routes.add((interface, destination))
            return ""
        if command[:5] == ("sudo", "-n", "ip", "address", "flush"):
            self.addresses[command[-1]] = ()
            return ""
        if command[:4] == ("sudo", "-n", "networkctl", "reconfigure"):
            if self.restore:
                interface = command[-1]
                self.addresses[interface] = ("192.168.2.10",)
                self.routes.add((interface, "192.168.2.0/24"))
            return ""
        return ""


def _plan(runner: FakeRunner):
    return prepare_usb_ssh_isolation(
        "enx_selected",
        "192.168.2.1",
        pluto_interfaces=("enx_selected", "enx_peer"),
        command_runner=runner,
    )


def test_isolated_action_restores_peers_and_overlapping_route(tmp_path: Path) -> None:
    runner = FakeRunner()
    plan = _plan(runner)
    route_checks: list[tuple[str, str]] = []

    result, receipt = execute_usb_ssh_isolated(
        plan,
        confirmation=plan.confirmation_phrase,
        receipt_directory=tmp_path / "receipts",
        action=lambda: "done",
        pluto_interfaces=("enx_selected", "enx_peer"),
        command_runner=runner,
        route_checker=lambda interface, endpoint: route_checks.append((interface, endpoint)),
        restoration_timeout_s=0.02,
    )

    assert result == "done"
    assert receipt.outcome == "success"
    assert receipt.phases[-1] == "host_network_restored"
    assert route_checks == [("enx_selected", "192.168.2.1")]
    assert runner.addresses["enx_peer"] == ("192.168.2.10",)
    assert ("eth0", "192.168.0.0/22") in runner.routes
    assert ("enx_peer", "192.168.2.0/24") in runner.routes
    assert Path(receipt.receipt_path).stat().st_mode & 0o077 == 0


def test_action_failure_is_reported_only_after_successful_restoration(tmp_path: Path) -> None:
    runner = FakeRunner()
    plan = _plan(runner)

    with pytest.raises(HostIsolationExecutionError) as caught:
        execute_usb_ssh_isolated(
            plan,
            confirmation=plan.confirmation_phrase,
            receipt_directory=tmp_path / "receipts",
            action=lambda: (_ for _ in ()).throw(RuntimeError("radio failed")),
            pluto_interfaces=("enx_selected", "enx_peer"),
            command_runner=runner,
            route_checker=lambda interface, endpoint: None,
            restoration_timeout_s=0.02,
        )

    assert caught.value.receipt.outcome == "action_failed_restored"
    assert "radio failed" in (caught.value.receipt.action_error or "")
    assert caught.value.receipt.restoration_error is None
    assert runner.addresses["enx_peer"] == ("192.168.2.10",)


def test_restoration_uncertainty_dominates_action_success(tmp_path: Path) -> None:
    runner = FakeRunner(restore=False)
    plan = _plan(runner)

    with pytest.raises(HostIsolationExecutionError) as caught:
        execute_usb_ssh_isolated(
            plan,
            confirmation=plan.confirmation_phrase,
            receipt_directory=tmp_path / "receipts",
            action=lambda: "done",
            pluto_interfaces=("enx_selected", "enx_peer"),
            command_runner=runner,
            route_checker=lambda interface, endpoint: None,
            restoration_timeout_s=0.02,
        )

    assert caught.value.receipt.outcome == "restoration_unknown"
    assert "did not return" in (caught.value.receipt.restoration_error or "")
