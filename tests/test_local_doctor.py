from __future__ import annotations

from pathlib import Path

import pytest

import pluto_plus.local_doctor as local_doctor
from pluto_plus.inventory import HostNetworkInterface, LocalUsbPluto


def _device(*, serial: str | None = "SERIAL_A") -> LocalUsbPluto:
    return LocalUsbPluto(
        usb_path="/sys/bus/usb/devices/3-11",
        bus_number=3,
        device_number=17,
        product="PlutoSDR+",
        serial=serial,
        speed_mbps=480,
        interface_count=7,
        host_network_interfaces=(
            HostNetworkInterface(name="enx001", ipv4_addresses=("192.168.2.10",)),
        ),
        terminal_devices=("/dev/ttyACM0",),
        storage_devices=("/dev/sdb1",),
    )


def test_local_doctor_reports_fresh_canonical_and_unknown_persistence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        local_doctor,
        "inspect_bound_iiod",
        lambda interface: {
            "hw_serial": "SERIAL_A",
            "hw_model": "Analog Devices PlutoSDR Rev.C",
            "fw_version": local_doctor.LOCAL_POLICY.device_firmware,
            "ad9361-phy,model": "ad9361",
            "iio,buffer-metadata": "1",
            "device_names": ("ad9361-phy", "cf-ad9361-lpc"),
        },
    )

    report = local_doctor.diagnose_local_usb_radios(devices=(_device(),))

    radio = report.radios[0]
    statuses = {check.code: check.status for check in radio.checks}
    assert statuses["identity.iio_serial"] == "pass"
    assert statuses["firmware.canonical_v5"] == "pass"
    assert statuses["rf.phy_model"] == "pass"
    assert statuses["firmware.qspi_boot_provenance"] == "unknown"
    assert radio.overall == "unknown"


def test_local_doctor_flags_blank_identity_old_firmware_and_wrong_phy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        local_doctor,
        "inspect_bound_iiod",
        lambda interface: {
            "hw_serial": "",
            "hw_model": "Analog Devices PlutoSDR Rev.C",
            "fw_version": "v0.32-dirty",
            "ad9361-phy,model": "ad9363a",
            "device_names": ("ad9361-phy", "cf-ad9361-lpc"),
        },
    )

    radio = local_doctor.diagnose_local_usb_radios(devices=(_device(serial=None),)).radios[0]
    statuses = {check.code: check.status for check in radio.checks}
    assert statuses["identity.usb_serial"] == "fail"
    assert statuses["firmware.canonical_v5"] == "fail"
    assert statuses["rf.phy_model"] == "fail"
    assert statuses["transport.buffer_metadata"] == "fail"
    assert radio.overall == "fail"


def test_local_doctor_exact_path_must_resolve_once() -> None:
    with pytest.raises(ValueError, match="found 0"):
        local_doctor.diagnose_local_usb_radios(
            Path("/sys/bus/usb/devices/9-9"),
            devices=(_device(),),
        )
