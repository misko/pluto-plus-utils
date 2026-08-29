from __future__ import annotations

import json
import stat
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

import pytest

import pluto_plus.bootstrap_firmware as bootstrap
import pluto_plus.local_reboot as local_reboot
from pluto_plus.inventory import HostNetworkInterface, LocalUsbPluto
from pluto_plus.ip_firmware import UsbSshRouteObservation
from pluto_plus.local_reboot import (
    LocalRebootAttestation,
    LocalRebootCapabilities,
    LocalRebootError,
    LocalRebootExecutionError,
    LocalRebootPlan,
    execute_local_reboot,
    prepare_local_reboot,
)
from pluto_plus.setup_helper import SetupSshHostKeyChangedError

SERIAL = "104000b29905000e17000800065934759d"
PATH = Path("/sys/bus/usb/devices/3-8")
INTERFACE = "enx00e022698b24"


def _radio(*, serial: str = SERIAL, interface: str = INTERFACE) -> LocalUsbPluto:
    return LocalUsbPluto(
        usb_path=str(PATH),
        bus_number=3,
        device_number=11,
        product="PlutoSDR+",
        serial=serial,
        speed_mbps=480,
        interface_count=7,
        host_network_interfaces=(
            HostNetworkInterface(name=interface, ipv4_addresses=("192.168.2.10",)),
        ),
    )


ROUTE = UsbSshRouteObservation(
    interface_addresses=((INTERFACE, ("192.168.2.10",)),),
    destination_routes=((INTERFACE, "192.168.2.0/24"),),
)
CAPABILITIES = LocalRebootCapabilities(
    board_model="PlutoSDR+ Rev.C",
    phy_model="ad9361",
    rx_scan_channels=("voltage0", "voltage1", "voltage2", "voltage3"),
    tandem_agc=True,
)


class FakeTransport:
    def __init__(self, attestations: Sequence[LocalRebootAttestation | BaseException]) -> None:
        self.attestations = list(attestations)
        self.events: list[str] = []

    def attest(self, serial: str) -> LocalRebootAttestation:
        self.events.append(f"attest:{serial}")
        result = self.attestations.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result

    def ensure_tx_safe(self, serial: str) -> None:
        self.events.append(f"tx-safe:{serial}")

    def reboot(self, serial: str) -> None:
        self.events.append(f"reboot:{serial}")


class UncertainRebootTransport(FakeTransport):
    def __init__(
        self,
        attestations: Sequence[LocalRebootAttestation | BaseException],
        receipt_directory: Path,
    ) -> None:
        super().__init__(attestations)
        self.receipt_directory = receipt_directory

    def reboot(self, serial: str) -> None:
        super().reboot(serial)
        receipts = tuple(self.receipt_directory.glob("*.json"))
        assert len(receipts) == 1
        durable = json.loads(receipts[0].read_text())
        assert durable["outcome"] == "started"
        assert durable["completed_phases"][-1] == "reboot_dispatch_attempted"
        raise TimeoutError("SSH disconnected during dispatch")


def _attestation(boot_id: str, *, firmware: str = "v6", serial: str = SERIAL):
    return LocalRebootAttestation(
        serial=serial,
        firmware=firmware,
        boot_id=boot_id,
        capabilities=CAPABILITIES,
    )


def _credentials(tmp_path: Path) -> Path:
    path = tmp_path / "known_hosts"
    path.write_text("192.168.2.1 ssh-ed25519 AAAATEST\n")
    path.chmod(0o600)
    return path


def _plan(tmp_path: Path, *, expected_return_firmware: str | None = None):
    return prepare_local_reboot(
        SERIAL,
        PATH,
        ssh_host="192.168.2.1",
        known_hosts_file=_credentials(tmp_path),
        expected_return_firmware=expected_return_firmware,
        scanner=lambda: (_radio(),),
        route_checker=lambda interface, host: ROUTE,
        interface_validator=lambda interface, path: None,
        usb_access_checker=lambda path: True,
    )


def test_prepare_binds_exact_serial_path_interface_route_and_private_trust(
    tmp_path: Path,
) -> None:
    plan = _plan(tmp_path)

    assert plan.serial == SERIAL
    assert plan.usb_sysfs_path == str(PATH)
    assert plan.usb_interface == INTERFACE
    assert plan.confirmation_phrase == f"REBOOT {SERIAL}"
    assert plan.expected_return_firmware is None
    assert len(plan.known_hosts_sha256) == 64


def test_prepare_binds_expected_return_firmware(tmp_path: Path) -> None:
    plan = _plan(tmp_path, expected_return_firmware="v0.42-qspi")

    assert plan.schema_version == 4
    assert plan.expected_return_firmware == "v0.42-qspi"


def test_prepare_unique_lan_host_keeps_usb_identity_but_does_not_bind_usb_route(
    tmp_path: Path,
) -> None:
    route_calls: list[tuple[str, str]] = []

    def route_checker(interface: str, host: str) -> UsbSshRouteObservation:
        route_calls.append((interface, host))
        raise AssertionError("LAN host must not be forced through the USB gadget interface")

    plan = prepare_local_reboot(
        SERIAL,
        PATH,
        ssh_host="192.168.1.15",
        known_hosts_file=_credentials(tmp_path),
        scanner=lambda: (_radio(),),
        route_checker=route_checker,
        interface_validator=lambda interface, path: None,
        usb_access_checker=lambda path: True,
    )

    assert plan.ssh_route_mode == "lan"
    assert plan.route_observation is None
    assert plan.usb_interface == INTERFACE
    assert route_calls == []


def test_prepare_refuses_duplicate_or_non_private_identity(tmp_path: Path) -> None:
    known_hosts = _credentials(tmp_path)
    known_hosts.chmod(0o644)
    with pytest.raises(LocalRebootError, match="private regular"):
        prepare_local_reboot(
            SERIAL,
            PATH,
            ssh_host="192.168.2.1",
            known_hosts_file=known_hosts,
            scanner=lambda: (_radio(),),
            route_checker=lambda interface, host: ROUTE,
            interface_validator=lambda interface, path: None,
            usb_access_checker=lambda path: True,
        )

    known_hosts.chmod(0o600)
    with pytest.raises(LocalRebootError, match="exactly one"):
        prepare_local_reboot(
            SERIAL,
            PATH,
            ssh_host="192.168.2.1",
            known_hosts_file=known_hosts,
            scanner=lambda: (_radio(), _radio()),
            route_checker=lambda interface, host: ROUTE,
            interface_validator=lambda interface, path: None,
            usb_access_checker=lambda path: True,
        )


def test_success_reboots_only_after_safe_state_and_attests_same_return(
    tmp_path: Path,
) -> None:
    plan = _plan(tmp_path)
    known_hosts = tmp_path / "known_hosts"
    transport = FakeTransport((_attestation("before"), _attestation("after")))
    scans = iter(((_radio(),), (), (_radio(serial=""),), (_radio(),)))

    receipt = execute_local_reboot(
        plan,
        confirmation=plan.confirmation_phrase,
        transport=transport,
        known_hosts_file=known_hosts,
        receipt_directory=tmp_path / "receipts",
        scanner=lambda: next(scans),
        route_checker=lambda interface, host: ROUTE,
        interface_validator=lambda interface, path: None,
        usb_access_checker=lambda path: True,
        timeout_s=0.2,
        poll_interval_s=0.001,
    )

    assert receipt.outcome == "success"
    assert transport.events == [
        f"attest:{SERIAL}",
        f"tx-safe:{SERIAL}",
        f"reboot:{SERIAL}",
        f"attest:{SERIAL}",
        f"tx-safe:{SERIAL}",
    ]
    assert receipt.before and receipt.before.boot_id == "before"
    assert receipt.after and receipt.after.boot_id == "after"
    assert stat.S_IMODE(Path(receipt.receipt_path).stat().st_mode) == 0o600
    document = json.loads(Path(receipt.receipt_path).read_text())
    assert document["outcome"] == "success"
    assert document["completed_phases"][-1] == "tx_safe_after_reboot"


def test_success_accepts_exact_expected_firmware_return(tmp_path: Path) -> None:
    plan = _plan(tmp_path, expected_return_firmware="v0.42-qspi")
    known_hosts = tmp_path / "known_hosts"
    transport = FakeTransport(
        (
            _attestation("before", firmware="v0.42-ram-candidate"),
            _attestation("after", firmware="v0.42-qspi"),
        )
    )
    scans = iter(((_radio(),), (), (_radio(),)))

    receipt = execute_local_reboot(
        plan,
        confirmation=plan.confirmation_phrase,
        transport=transport,
        known_hosts_file=known_hosts,
        receipt_directory=tmp_path / "receipts",
        scanner=lambda: next(scans),
        route_checker=lambda interface, host: ROUTE,
        interface_validator=lambda interface, path: None,
        usb_access_checker=lambda path: True,
        timeout_s=0.2,
        poll_interval_s=0.001,
    )

    assert receipt.outcome == "success"
    assert receipt.before and receipt.before.firmware == "v0.42-ram-candidate"
    assert receipt.after and receipt.after.firmware == "v0.42-qspi"


def test_refuses_confirmation_without_touching_transport(tmp_path: Path) -> None:
    plan = _plan(tmp_path)
    transport = FakeTransport((_attestation("before"),))

    with pytest.raises(LocalRebootError, match="confirmation"):
        execute_local_reboot(
            plan,
            confirmation="yes",
            transport=transport,
            known_hosts_file=tmp_path / "known_hosts",
            receipt_directory=tmp_path / "receipts",
        )
    assert transport.events == []


def test_unwritable_raw_usb_fails_before_radio_operation(tmp_path: Path) -> None:
    plan = replace(_plan(tmp_path), raw_usb_write_access=False)
    transport = FakeTransport((_attestation("before"),))

    with pytest.raises(LocalRebootExecutionError) as caught:
        execute_local_reboot(
            plan,
            confirmation=plan.confirmation_phrase,
            transport=transport,
            known_hosts_file=tmp_path / "known_hosts",
            receipt_directory=tmp_path / "receipts",
            scanner=lambda: (_radio(),),
            route_checker=lambda interface, host: ROUTE,
            interface_validator=lambda interface, path: None,
            usb_access_checker=lambda path: False,
        )

    assert caught.value.receipt.outcome == "failed_before_mutation"
    assert "not writable" in (caught.value.receipt.error or "")
    assert transport.events == []


def test_wrong_return_topology_is_unknown_and_receipted(tmp_path: Path) -> None:
    plan = _plan(tmp_path)
    transport = FakeTransport((_attestation("before"),))
    scans = [(_radio(),), (), (_radio(serial="WRONG"),)]

    with pytest.raises(LocalRebootExecutionError) as caught:
        execute_local_reboot(
            plan,
            confirmation=plan.confirmation_phrase,
            transport=transport,
            known_hosts_file=tmp_path / "known_hosts",
            receipt_directory=tmp_path / "receipts",
            scanner=lambda: scans.pop(0) if len(scans) > 1 else scans[0],
            route_checker=lambda interface, host: ROUTE,
            interface_validator=lambda interface, path: None,
            usb_access_checker=lambda path: True,
            timeout_s=0.2,
            poll_interval_s=0.001,
        )

    assert caught.value.receipt.outcome == "unknown"
    assert "different radio" in (caught.value.receipt.error or "")
    assert Path(caught.value.receipt.receipt_path).is_file()


def test_reboot_dispatch_error_is_unknown_not_safe_to_retry(tmp_path: Path) -> None:
    plan = _plan(tmp_path)
    receipt_directory = tmp_path / "receipts"
    transport = UncertainRebootTransport((_attestation("before"),), receipt_directory)

    with pytest.raises(LocalRebootExecutionError) as caught:
        execute_local_reboot(
            plan,
            confirmation=plan.confirmation_phrase,
            transport=transport,
            known_hosts_file=tmp_path / "known_hosts",
            receipt_directory=receipt_directory,
            scanner=lambda: (_radio(),),
            route_checker=lambda interface, host: ROUTE,
            interface_validator=lambda interface, path: None,
            usb_access_checker=lambda path: True,
        )

    assert caught.value.receipt.outcome == "unknown"
    assert "SSH disconnected" in (caught.value.receipt.error or "")


def test_changed_firmware_never_passes_post_return_attestation(tmp_path: Path) -> None:
    plan = _plan(tmp_path)
    transport = FakeTransport(
        (_attestation("before"), _attestation("after", firmware="unexpected"))
    )
    scans = iter(((_radio(),), (), (_radio(),)))

    with pytest.raises(LocalRebootExecutionError) as caught:
        execute_local_reboot(
            plan,
            confirmation=plan.confirmation_phrase,
            transport=transport,
            known_hosts_file=tmp_path / "known_hosts",
            receipt_directory=tmp_path / "receipts",
            scanner=lambda: next(scans),
            route_checker=lambda interface, host: ROUTE,
            interface_validator=lambda interface, path: None,
            usb_access_checker=lambda path: True,
            timeout_s=0.01,
            poll_interval_s=0.001,
        )

    assert caught.value.receipt.outcome == "unknown"
    assert "firmware changed" in (caught.value.receipt.error or "")
    assert f"tx-safe:{SERIAL}" not in transport.events[3:]


def test_rotated_ssh_key_is_not_trusted_and_exact_usb_verifier_can_reconcile(
    tmp_path: Path,
) -> None:
    plan = _plan(tmp_path)
    transport = FakeTransport((_attestation("before"), SetupSshHostKeyChangedError("rotated")))
    scans = iter(((_radio(),), (), (_radio(),)))
    verifier_calls: list[tuple[str, str | None]] = []

    def verify_usb(
        selected_plan: LocalRebootPlan, before: LocalRebootAttestation
    ) -> LocalRebootAttestation:
        assert selected_plan == plan
        verifier_calls.append((before.serial, before.boot_id))
        return LocalRebootAttestation(
            serial=SERIAL,
            firmware="v6",
            boot_id=None,
            capabilities=replace(
                CAPABILITIES,
                board_model="Analog Devices PlutoSDR Rev.C (Z7010-AD9361)",
            ),
        )

    receipt = execute_local_reboot(
        plan,
        confirmation=plan.confirmation_phrase,
        transport=transport,
        known_hosts_file=tmp_path / "known_hosts",
        receipt_directory=tmp_path / "receipts",
        scanner=lambda: next(scans),
        route_checker=lambda interface, host: ROUTE,
        interface_validator=lambda interface, path: None,
        usb_access_checker=lambda path: True,
        post_reboot_usb_verifier=verify_usb,
        timeout_s=0.2,
        poll_interval_s=0.001,
    )

    assert receipt.outcome == "success"
    assert "post_reboot_usb_iiod_attested" in receipt.completed_phases
    assert verifier_calls == [(SERIAL, "before")]
    # The verifier owns the independent TX mute/readback, so rotated SSH is
    # never used again after it fails host-key authentication.
    assert transport.events[-1] == f"attest:{SERIAL}"


def test_usb_return_accepts_equivalent_rev_c_models_from_ssh_and_iiod(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = _plan(tmp_path)
    before = LocalRebootAttestation(
        serial=SERIAL,
        firmware="v6",
        boot_id="before",
        capabilities=LocalRebootCapabilities(
            board_model="Analog Devices PlutoSDR Rev.C (Z7010/AD9363)",
            phy_model="ad9361",
            rx_scan_channels=("voltage0", "voltage1", "voltage2", "voltage3"),
            tandem_agc=True,
        ),
    )
    monkeypatch.setattr(
        bootstrap,
        "inspect_bound_iiod",
        lambda interface: {
            "hw_serial": SERIAL,
            "hw_model": "Analog Devices PlutoSDR Rev.C (Z7010-AD9361)",
            "fw_version": "v6",
            "ad9361-phy,model": "ad9361",
            "device_names": ("cf-ad9361-lpc", "tandem-agc"),
            "cf-ad9361-lpc,scan_channels": (
                "voltage0",
                "voltage1",
                "voltage2",
                "voltage3",
            ),
        },
    )
    muted: list[str] = []
    monkeypatch.setattr(bootstrap, "mute_returned_radio", muted.append)

    after = local_reboot.attest_and_mute_returned_usb(plan, before)

    assert after.capabilities.board_model.endswith("(Z7010-AD9361)")
    assert muted == [SERIAL]


def test_usb_return_accepts_exact_expected_firmware_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = _plan(tmp_path, expected_return_firmware="v0.42-qspi")
    before = _attestation("before", firmware="v0.42-ram-candidate")
    monkeypatch.setattr(
        bootstrap,
        "inspect_bound_iiod",
        lambda interface: {
            "hw_serial": SERIAL,
            "hw_model": "Analog Devices PlutoSDR Rev.C (Z7010-AD9361)",
            "fw_version": "v0.42-qspi",
            "ad9361-phy,model": "ad9361",
            "device_names": ("cf-ad9361-lpc", "tandem-agc"),
            "cf-ad9361-lpc,scan_channels": CAPABILITIES.rx_scan_channels,
        },
    )
    muted: list[str] = []
    monkeypatch.setattr(bootstrap, "mute_returned_radio", muted.append)

    after = local_reboot.attest_and_mute_returned_usb(plan, before)

    assert after.firmware == "v0.42-qspi"
    assert muted == [SERIAL]
