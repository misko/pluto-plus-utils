from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path

import pytest

from pluto_plus.inventory import HostNetworkInterface, LocalUsbPluto
from pluto_plus.lan_reboot import (
    LanRebootError,
    LanRebootExecutionError,
    execute_lan_network_reboot,
    execute_lan_reboot,
    prepare_lan_network_reboot,
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


def _returned_attestation() -> LocalRebootAttestation:
    before = _attestation()
    return LocalRebootAttestation(
        serial=before.serial,
        firmware=before.firmware,
        boot_id="22222222-2222-4222-8222-222222222222",
        capabilities=before.capabilities,
    )


def _iio_facts() -> dict[str, object]:
    return {
        "hw_serial": SERIAL,
        "fw_version": "candidate-v1",
        "hw_model": "PlutoSDR+ Rev.C",
        "ad9361-phy,model": "ad9361",
        "iio,buffer-metadata": "3",
        "device_names": ("ad9361-phy", "cf-ad9361-lpc", "tandem-agc"),
        "cf-ad9361-lpc,scan_channels": (
            "voltage0",
            "voltage1",
            "voltage2",
            "voltage3",
        ),
    }


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
    def __init__(
        self,
        *,
        attestation: LocalRebootAttestation | None = None,
        reboot_error: BaseException | None = None,
    ) -> None:
        self.events: list[str] = []
        self.attestation = attestation or _attestation()
        self.reboot_error = reboot_error

    def attest(self, serial: str) -> LocalRebootAttestation:
        self.events.append(f"attest:{serial}")
        return self.attestation

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


def test_prepare_network_reboot_binds_iio_identity_and_metadata(tmp_path: Path) -> None:
    plan = prepare_lan_network_reboot(
        SERIAL,
        ssh_host="192.168.1.183",
        known_hosts_file=_known_hosts(tmp_path),
        transport=_Transport(),
        scanner=lambda: (),
        iio_inspector=lambda _host: _iio_facts(),
    )

    assert plan.schema_version == 2
    assert plan.expected_metadata_abi == 3
    assert plan.before == _attestation()


def test_execute_network_reboot_proves_disappear_return_and_rotated_key(
    tmp_path: Path,
) -> None:
    known_hosts = _known_hosts(tmp_path)
    transport = _Transport(reboot_error=TimeoutError("SSH disconnected"))
    plan = prepare_lan_network_reboot(
        SERIAL,
        ssh_host="192.168.1.183",
        known_hosts_file=known_hosts,
        transport=transport,
        scanner=lambda: (),
        iio_inspector=lambda _host: _iio_facts(),
    )
    replacement = b"192.168.1.183 ssh-ed25519 AAAAREPLACEMENT\n"

    def rotate_key() -> dict[str, str]:
        previous_sha256 = plan.known_hosts_sha256
        known_hosts.write_bytes(replacement)
        known_hosts.chmod(0o600)
        return {
            "previous_known_hosts_sha256": previous_sha256,
            "replacement_known_hosts_sha256": hashlib.sha256(replacement).hexdigest(),
        }

    observations: list[object] = [
        _iio_facts(),
        OSError("IIOD stopped"),
        {"hw_serial": SERIAL},
        _iio_facts(),
    ]

    def inspect(_host: str) -> dict[str, object]:
        observation = observations.pop(0)
        if isinstance(observation, BaseException):
            raise observation
        assert isinstance(observation, dict)
        return observation

    returned = _Transport(attestation=_returned_attestation())
    receipt = execute_lan_network_reboot(
        plan,
        confirmation=plan.confirmation_phrase,
        transport=transport,
        returned_transport_factory=lambda: returned,
        host_key_rotator=rotate_key,
        known_hosts_file=known_hosts,
        receipt_directory=tmp_path / "receipts",
        scanner=lambda: (),
        iio_inspector=inspect,
        timeout_s=1,
        poll_interval_s=0.001,
    )

    assert receipt.outcome == "success"
    assert receipt.before == _attestation()
    assert receipt.after == _returned_attestation()
    assert receipt.dispatch_error == "TimeoutError: SSH disconnected"
    assert receipt.completed_phases[-5:] == (
        "lan_iio_disappeared",
        "lan_iio_reappeared",
        "lan_ssh_host_key_rotated",
        "post_reboot_identity_attested",
        "tx_safe_after_reboot",
    )
    assert returned.events == [f"attest:{SERIAL}", f"tx-safe:{SERIAL}"]
    assert stat.S_IMODE(Path(receipt.receipt_path).stat().st_mode) == 0o600


def test_execute_network_reboot_rejects_unbound_rotation_evidence(tmp_path: Path) -> None:
    known_hosts = _known_hosts(tmp_path)
    transport = _Transport()
    plan = prepare_lan_network_reboot(
        SERIAL,
        ssh_host="192.168.1.183",
        known_hosts_file=known_hosts,
        transport=transport,
        scanner=lambda: (),
        iio_inspector=lambda _host: _iio_facts(),
    )
    observations: list[object] = [
        _iio_facts(),
        OSError("IIOD stopped"),
        _iio_facts(),
    ]

    def inspect(_host: str) -> dict[str, object]:
        observation = observations.pop(0)
        if isinstance(observation, BaseException):
            raise observation
        assert isinstance(observation, dict)
        return observation

    with pytest.raises(LanRebootExecutionError, match="planned trust anchor") as caught:
        execute_lan_network_reboot(
            plan,
            confirmation=plan.confirmation_phrase,
            transport=transport,
            returned_transport_factory=lambda: _Transport(
                attestation=_returned_attestation()
            ),
            host_key_rotator=lambda: {
                "previous_known_hosts_sha256": "0" * 64,
                "replacement_known_hosts_sha256": "1" * 64,
            },
            known_hosts_file=known_hosts,
            receipt_directory=tmp_path / "receipts",
            scanner=lambda: (),
            iio_inspector=inspect,
            timeout_s=1,
            poll_interval_s=0.001,
        )

    assert caught.value.receipt.outcome == "unknown"
    assert "lan_ssh_host_key_rotated" not in caught.value.receipt.completed_phases
