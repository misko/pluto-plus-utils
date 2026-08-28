from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from pluto_plus.inventory import HostNetworkInterface, LocalUsbPluto
from pluto_plus.lan_reboot import (
    LanRebootError,
    LanRebootExecutionError,
    execute_lan_reboot,
    prepare_lan_reboot,
)
from pluto_plus.local_reboot import LocalRebootAttestation, LocalRebootCapabilities

SERIAL = "104000b29905000e17000800065934759d"


def _attestation() -> LocalRebootAttestation:
    return LocalRebootAttestation(
        serial=SERIAL,
        firmware="candidate-v1",
        boot_id="11111111-1111-4111-8111-111111111111",
        capabilities=LocalRebootCapabilities(
            board_model="PlutoSDR+ Rev.C",
            phy_model="ad9361",
            rx_scan_channels=("voltage0", "voltage1", "voltage2", "voltage3"),
            tandem_agc=True,
        ),
    )


def _usb_radio() -> LocalUsbPluto:
    return LocalUsbPluto(
        usb_path="/sys/bus/usb/devices/3-11",
        bus_number=3,
        device_number=29,
        product="PlutoSDR+",
        serial=SERIAL,
        speed_mbps=480,
        interface_count=7,
        host_network_interfaces=(
            HostNetworkInterface(name="enx001", ipv4_addresses=("192.168.2.10",)),
        ),
    )


def _known_hosts(tmp_path: Path) -> Path:
    path = tmp_path / "known_hosts"
    path.write_text("192.168.1.183 ssh-ed25519 AAAATEST\n")
    path.chmod(0o600)
    return path


class _Transport:
    def __init__(self, *, reboot_error: BaseException | None = None) -> None:
        self.events: list[str] = []
        self.reboot_error = reboot_error

    def attest(self, serial: str) -> LocalRebootAttestation:
        self.events.append(f"attest:{serial}")
        return _attestation()

    def ensure_tx_safe(self, serial: str) -> None:
        self.events.append(f"tx-safe:{serial}")

    def reboot(self, serial: str) -> None:
        self.events.append(f"reboot:{serial}")
        if self.reboot_error is not None:
            raise self.reboot_error


def test_prepare_attests_unique_lan_and_requires_detached_usb(tmp_path: Path) -> None:
    transport = _Transport()

    plan = prepare_lan_reboot(
        SERIAL,
        ssh_host="192.168.1.183",
        known_hosts_file=_known_hosts(tmp_path),
        transport=transport,
        scanner=lambda: (),
    )

    assert plan.serial == SERIAL
    assert plan.before.firmware == "candidate-v1"
    assert plan.confirmation_phrase == f"REBOOT LAN {SERIAL}"
    assert transport.events == [f"attest:{SERIAL}"]


def test_prepare_rejects_usb_gadget_address_and_attached_serial(tmp_path: Path) -> None:
    known_hosts = _known_hosts(tmp_path)
    with pytest.raises(LanRebootError, match="unique LAN"):
        prepare_lan_reboot(
            SERIAL,
            ssh_host="192.168.2.1",
            known_hosts_file=known_hosts,
            transport=_Transport(),
            scanner=lambda: (),
        )
    with pytest.raises(LanRebootError, match="reboot-local"):
        prepare_lan_reboot(
            SERIAL,
            ssh_host="192.168.1.183",
            known_hosts_file=known_hosts,
            transport=_Transport(),
            scanner=lambda: (_usb_radio(),),
        )


def test_execute_mutes_reboots_and_receipts_exact_usb_return(tmp_path: Path) -> None:
    known_hosts = _known_hosts(tmp_path)
    transport = _Transport()
    plan = prepare_lan_reboot(
        SERIAL,
        ssh_host="192.168.1.183",
        known_hosts_file=known_hosts,
        transport=transport,
        scanner=lambda: (),
    )
    scans = iter(((), (), (_usb_radio(),)))

    receipt = execute_lan_reboot(
        plan,
        confirmation=plan.confirmation_phrase,
        transport=transport,
        known_hosts_file=known_hosts,
        receipt_directory=tmp_path / "receipts",
        scanner=lambda: next(scans),
        timeout_s=1,
        poll_interval_s=0.001,
    )

    assert receipt.outcome == "success"
    assert receipt.returned_usb_path == "/sys/bus/usb/devices/3-11"
    assert receipt.completed_phases[-1] == "exact_usb_serial_returned"
    assert transport.events[-3:] == [
        f"attest:{SERIAL}",
        f"tx-safe:{SERIAL}",
        f"reboot:{SERIAL}",
    ]
    receipt_path = Path(receipt.receipt_path)
    assert stat.S_IMODE(receipt_path.stat().st_mode) == 0o600
    assert json.loads(receipt_path.read_text())["outcome"] == "success"


def test_execute_accepts_disconnect_error_only_after_exact_usb_return(tmp_path: Path) -> None:
    known_hosts = _known_hosts(tmp_path)
    transport = _Transport(reboot_error=TimeoutError("SSH disconnected"))
    plan = prepare_lan_reboot(
        SERIAL,
        ssh_host="192.168.1.183",
        known_hosts_file=known_hosts,
        transport=transport,
        scanner=lambda: (),
    )
    scans = iter(((), (_usb_radio(),)))

    receipt = execute_lan_reboot(
        plan,
        confirmation=plan.confirmation_phrase,
        transport=transport,
        known_hosts_file=known_hosts,
        receipt_directory=tmp_path / "receipts",
        scanner=lambda: next(scans),
        timeout_s=1,
        poll_interval_s=0.001,
    )

    assert receipt.outcome == "success"
    assert receipt.dispatch_error == "TimeoutError: SSH disconnected"


def test_execute_timeout_after_dispatch_is_unknown_and_durable(tmp_path: Path) -> None:
    known_hosts = _known_hosts(tmp_path)
    transport = _Transport()
    plan = prepare_lan_reboot(
        SERIAL,
        ssh_host="192.168.1.183",
        known_hosts_file=known_hosts,
        transport=transport,
        scanner=lambda: (),
    )

    with pytest.raises(LanRebootExecutionError) as caught:
        execute_lan_reboot(
            plan,
            confirmation=plan.confirmation_phrase,
            transport=transport,
            known_hosts_file=known_hosts,
            receipt_directory=tmp_path / "receipts",
            scanner=lambda: (),
            timeout_s=0.01,
            poll_interval_s=0.001,
        )

    assert caught.value.receipt.outcome == "unknown"
    assert Path(caught.value.receipt.receipt_path).is_file()
