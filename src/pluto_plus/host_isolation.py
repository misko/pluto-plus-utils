"""Receipt-backed reversible host isolation for one Pluto USB SSH route."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
import tempfile
import time
import uuid
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, TypeVar

from pluto_plus.ip_firmware import require_unambiguous_usb_ssh_route

_INTERFACE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
T = TypeVar("T")


class HostIsolationError(RuntimeError):
    """A host-isolation precondition, mutation, or restoration failed."""


class HostIsolationExecutionError(HostIsolationError):
    def __init__(self, message: str, receipt: HostIsolationReceipt) -> None:
        super().__init__(message)
        self.receipt = receipt


@dataclass(frozen=True, slots=True)
class HostRoute:
    destination: str
    interface: str
    gateway: str | None = None
    preferred_source: str | None = None
    metric: int | None = None
    protocol: str | None = None
    scope: str | None = None


@dataclass(frozen=True, slots=True)
class HostIsolationPlan:
    schema_version: int
    plan_id: str
    created_at: str
    selected_interface: str
    endpoint: str
    selected_addresses: tuple[str, ...]
    peer_interfaces: tuple[str, ...]
    peer_addresses: tuple[tuple[str, tuple[str, ...]], ...]
    competing_routes: tuple[HostRoute, ...]
    sudo_ready: bool
    confirmation_phrase: str


@dataclass(frozen=True, slots=True)
class HostIsolationReceipt:
    schema_version: int
    receipt_id: str
    plan: HostIsolationPlan
    outcome: str
    phases: tuple[str, ...]
    receipt_path: str
    action_error: str | None = None
    restoration_error: str | None = None


class HostCommandRunner(Protocol):
    def run(self, argv: Sequence[str], *, timeout_s: float = 10) -> str: ...


class SubprocessHostCommandRunner:
    def run(self, argv: Sequence[str], *, timeout_s: float = 10) -> str:
        try:
            result = subprocess.run(
                tuple(argv), check=False, capture_output=True, text=True, timeout=timeout_s
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise HostIsolationError(f"host command failed to run: {error}") from error
        if result.returncode != 0:
            output = (result.stdout + result.stderr).strip()[-1000:]
            raise HostIsolationError(
                f"host command {argv[0]!r} exited {result.returncode}: {output}"
            )
        return result.stdout


def prepare_usb_ssh_isolation(
    selected_interface: str,
    endpoint: str,
    *,
    pluto_interfaces: Sequence[str],
    command_runner: HostCommandRunner | None = None,
) -> HostIsolationPlan:
    """Plan the minimum reversible host changes needed for one USB SSH route."""

    _validate_interface(selected_interface)
    peers = tuple(sorted(set(pluto_interfaces) - {selected_interface}))
    for interface in peers:
        _validate_interface(interface)
    try:
        target = ipaddress.ip_address(endpoint)
    except ValueError as error:
        raise HostIsolationError("isolation endpoint must be a literal IPv4 address") from error
    if target.version != 4:
        raise HostIsolationError("isolation endpoint must be IPv4")
    runner = command_runner or SubprocessHostCommandRunner()
    addresses = _read_json(
        runner, ("ip", "-j", "-4", "address", "show"), "host IPv4 addresses"
    )
    routes = _read_json(
        runner,
        ("ip", "-j", "-4", "route", "show", "table", "main"),
        "host IPv4 routes",
    )
    by_interface = _addresses_by_interface(addresses)
    selected_addresses = by_interface.get(selected_interface, ())
    if not selected_addresses:
        raise HostIsolationError("selected USB interface has no IPv4 address")
    peer_addresses = tuple((name, by_interface.get(name, ())) for name in peers)
    duplicate_owners = {
        name
        for name, values in by_interface.items()
        if name != selected_interface and set(values).intersection(selected_addresses)
    }
    unexpected = duplicate_owners - set(peers)
    if unexpected:
        raise HostIsolationError(
            f"duplicate selected address is owned by non-Pluto interfaces {sorted(unexpected)}"
        )
    competing = tuple(
        route
        for route in (_parse_route(item) for item in routes if isinstance(item, dict))
        if route is not None
        and route.interface != selected_interface
        and target in ipaddress.ip_network(route.destination, strict=False)
    )
    selected_route = any(
        isinstance(item, dict)
        and item.get("dev") == selected_interface
        and _route_contains(item.get("dst"), target)
        for item in routes
    )
    if not selected_route:
        raise HostIsolationError("selected interface has no route to the USB SSH endpoint")
    sudo_ready = True
    try:
        runner.run(("sudo", "-n", "true"), timeout_s=5)
    except HostIsolationError:
        sudo_ready = False
    return HostIsolationPlan(
        schema_version=1,
        plan_id=uuid.uuid4().hex,
        created_at=datetime.now(UTC).isoformat(),
        selected_interface=selected_interface,
        endpoint=str(target),
        selected_addresses=selected_addresses,
        peer_interfaces=peers,
        peer_addresses=peer_addresses,
        competing_routes=competing,
        sudo_ready=sudo_ready,
        confirmation_phrase=f"ISOLATE USB SSH {selected_interface}",
    )


def execute_usb_ssh_isolated(
    plan: HostIsolationPlan,
    *,
    confirmation: str,
    receipt_directory: Path,
    action: Callable[[], T],
    pluto_interfaces: Sequence[str],
    command_runner: HostCommandRunner | None = None,
    route_checker: Callable[[str, str], object] = require_unambiguous_usb_ssh_route,
    restoration_timeout_s: float = 15,
) -> tuple[T, HostIsolationReceipt]:
    """Run one bounded action while peers/routes are isolated, then restore in finally."""

    if confirmation != plan.confirmation_phrase:
        raise HostIsolationError(f"confirmation must be exactly {plan.confirmation_phrase!r}")
    runner = command_runner or SubprocessHostCommandRunner()
    fresh = prepare_usb_ssh_isolation(
        plan.selected_interface,
        plan.endpoint,
        pluto_interfaces=pluto_interfaces,
        command_runner=runner,
    )
    if _stable_plan(fresh) != _stable_plan(plan):
        raise HostIsolationError("host isolation preconditions changed")
    if not fresh.sudo_ready:
        raise HostIsolationError("host isolation requires non-interactive sudo")
    receipt_id = uuid.uuid4().hex
    receipt_path = receipt_directory / f"{receipt_id}.json"
    phases = ["preflight_revalidated"]
    base: dict[str, Any] = {
        "schema_version": 1,
        "receipt_id": receipt_id,
        "plan": asdict(plan),
        "outcome": "started",
        "phases": phases,
        "action_error": None,
        "restoration_error": None,
    }
    _write_receipt(receipt_path, base)
    result: T | None = None
    action_error: BaseException | None = None
    restoration_error: BaseException | None = None
    try:
        for route in plan.competing_routes:
            _delete_route(runner, route)
        phases.append("competing_routes_removed")
        _write_receipt(receipt_path, base | {"phases": phases})
        for interface in plan.peer_interfaces:
            runner.run(("sudo", "-n", "networkctl", "down", interface))
            runner.run(("sudo", "-n", "ip", "address", "flush", "dev", interface))
        phases.append("peer_interfaces_isolated")
        _write_receipt(receipt_path, base | {"phases": phases})
        route_checker(plan.selected_interface, plan.endpoint)
        phases.append("selected_route_attested")
        _write_receipt(receipt_path, base | {"phases": phases})
        phases.append("bounded_action_started")
        _write_receipt(receipt_path, base | {"phases": phases})
        result = action()
        phases.append("bounded_action_completed")
        _write_receipt(receipt_path, base | {"phases": phases})
    except BaseException as error:
        action_error = error
    finally:
        try:
            for route in plan.competing_routes:
                if route.interface not in plan.peer_interfaces:
                    _restore_route(runner, route)
            for interface in plan.peer_interfaces:
                runner.run(("sudo", "-n", "networkctl", "up", interface))
                runner.run(("sudo", "-n", "networkctl", "reconfigure", interface))
            _wait_for_restoration(plan, runner, timeout_s=restoration_timeout_s)
            phases.append("host_network_restored")
        except BaseException as error:
            restoration_error = error
    outcome = (
        "success"
        if action_error is None and restoration_error is None
        else "restoration_unknown"
        if restoration_error is not None
        else "action_failed_restored"
    )
    receipt = HostIsolationReceipt(
        schema_version=1,
        receipt_id=receipt_id,
        plan=plan,
        outcome=outcome,
        phases=tuple(phases),
        receipt_path=str(receipt_path),
        action_error=(
            None if action_error is None else f"{type(action_error).__name__}: {action_error}"
        ),
        restoration_error=(
            None
            if restoration_error is None
            else f"{type(restoration_error).__name__}: {restoration_error}"
        ),
    )
    _write_receipt(receipt_path, base | asdict(receipt))
    if restoration_error is not None:
        raise HostIsolationExecutionError(
            f"host network restoration is uncertain: {restoration_error}", receipt
        ) from restoration_error
    if action_error is not None:
        raise HostIsolationExecutionError(
            f"isolated action failed after host restoration: {action_error}", receipt
        ) from action_error
    assert result is not None
    return result, receipt


def _stable_plan(plan: HostIsolationPlan) -> tuple[object, ...]:
    return (
        plan.selected_interface,
        plan.endpoint,
        plan.selected_addresses,
        plan.peer_interfaces,
        plan.peer_addresses,
        plan.competing_routes,
    )


def _wait_for_restoration(
    plan: HostIsolationPlan, runner: HostCommandRunner, *, timeout_s: float = 15
) -> None:
    deadline = time.monotonic() + timeout_s
    expected = dict(plan.peer_addresses)
    while time.monotonic() < deadline:
        addresses = _addresses_by_interface(
            _read_json(
                runner, ("ip", "-j", "-4", "address", "show"), "restored addresses"
            )
        )
        routes = _read_json(
            runner,
            ("ip", "-j", "-4", "route", "show", "table", "main"),
            "restored routes",
        )
        addresses_ok = all(
            set(values).issubset(addresses.get(name, ()))
            for name, values in expected.items()
        )
        routes_ok = all(_route_present(route, routes) for route in plan.competing_routes)
        if addresses_ok and routes_ok:
            return
        time.sleep(0.25)
    raise HostIsolationError("host addresses/routes did not return to their planned state")


def _delete_route(runner: HostCommandRunner, route: HostRoute) -> None:
    runner.run(("sudo", "-n", "ip", "route", "del", route.destination, "dev", route.interface))


def _restore_route(runner: HostCommandRunner, route: HostRoute) -> None:
    argv = ["sudo", "-n", "ip", "route", "replace", route.destination]
    if route.gateway is not None:
        argv.extend(("via", route.gateway))
    argv.extend(("dev", route.interface))
    if route.preferred_source is not None:
        argv.extend(("src", route.preferred_source))
    if route.metric is not None:
        argv.extend(("metric", str(route.metric)))
    if route.protocol is not None:
        argv.extend(("proto", route.protocol))
    if route.scope is not None:
        argv.extend(("scope", route.scope))
    runner.run(tuple(argv))


def _route_present(route: HostRoute, document: list[object]) -> bool:
    return any(
        isinstance(item, dict)
        and item.get("dev") == route.interface
        and item.get("dst") == route.destination
        for item in document
    )


def _parse_route(item: dict[str, object]) -> HostRoute | None:
    destination = item.get("dst")
    interface = item.get("dev")
    if (
        not isinstance(destination, str)
        or destination == "default"
        or not isinstance(interface, str)
    ):
        return None
    try:
        destination = str(ipaddress.ip_network(destination, strict=False))
    except ValueError:
        return None
    _validate_interface(interface)
    metric = item.get("metric")
    return HostRoute(
        destination=destination,
        interface=interface,
        gateway=_optional_ip(item.get("gateway")),
        preferred_source=_optional_ip(item.get("prefsrc")),
        metric=metric if isinstance(metric, int) and metric >= 0 else None,
        protocol=_optional_token(item.get("protocol")),
        scope=_optional_token(item.get("scope")),
    )


def _addresses_by_interface(document: list[object]) -> dict[str, tuple[str, ...]]:
    result: dict[str, tuple[str, ...]] = {}
    for item in document:
        if not isinstance(item, dict) or not isinstance(item.get("ifname"), str):
            continue
        name = item["ifname"]
        _validate_interface(name)
        values = tuple(
            str(info["local"])
            for info in item.get("addr_info", ())
            if isinstance(info, dict)
            and info.get("family") == "inet"
            and isinstance(info.get("local"), str)
        )
        result[name] = values
    return result


def _route_contains(
    raw: object, target: ipaddress.IPv4Address | ipaddress.IPv6Address
) -> bool:
    if not isinstance(raw, str) or raw == "default":
        return False
    try:
        return target in ipaddress.ip_network(raw, strict=False)
    except ValueError:
        return False


def _optional_ip(value: object) -> str | None:
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError as error:
        raise HostIsolationError("route contains an invalid IP address") from error


def _optional_token(value: object) -> str | None:
    if value is None:
        return None
    token = str(value)
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", token):
        raise HostIsolationError("route contains an invalid token")
    return token


def _validate_interface(interface: str) -> None:
    if not _INTERFACE.fullmatch(interface):
        raise HostIsolationError(f"invalid host interface {interface!r}")


def _read_json(runner: HostCommandRunner, argv: Sequence[str], label: str) -> list[object]:
    try:
        document = json.loads(runner.run(argv))
    except (json.JSONDecodeError, HostIsolationError) as error:
        raise HostIsolationError(f"cannot inspect {label}: {error}") from error
    if not isinstance(document, list):
        raise HostIsolationError(f"cannot inspect {label}: expected a JSON list")
    return document


def _write_receipt(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    descriptor, name = tempfile.mkstemp(prefix=".host-isolation-", dir=path.parent)
    temporary = Path(name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            json.dump(payload, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
