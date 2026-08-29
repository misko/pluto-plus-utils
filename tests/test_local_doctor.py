from __future__ import annotations

from pathlib import Path

import pytest

import pluto_plus.local_doctor as local_doctor
from pluto_plus.data_plane import DataPlaneProbe
from pluto_plus.hardware.preflight import IioEnvironmentReport, IioEnvironmentStatus
from pluto_plus.inventory import HostNetworkInterface, LocalUsbPluto, UsbLinkFaultSummary
from pluto_plus.setup_repair import SetupProbeOutcome, SetupRepairRecord


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
    assert statuses["firmware.diagnostic_profile"] == "pass"
    assert statuses["rf.phy_model"] == "pass"
    assert statuses["transport.rx_data_plane"] == "unknown"
    assert statuses["firmware.qspi_boot_provenance"] == "unknown"
    # The previously canonical v6 image is now a recognized older release, so
    # release currency is a binding failure even though persistence provenance
    # remains unknown.
    assert radio.overall == "fail"


def test_local_doctor_reports_explicit_bounded_data_plane_probe(
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

    radio = local_doctor.diagnose_local_usb_radios(
        devices=(_device(),),
        data_plane_probe=lambda device: DataPlaneProbe(
            status="fail",
            serial=device.serial or "missing",
            uri="usb:1",
            samples_per_channel=65_536,
            receiver_count=2,
            wire_bytes=524_288,
            elapsed_ms=5000,
            failure_kind="timeout",
            error="TimeoutError: [Errno 110]",
        ),
    ).radios[0]

    check = next(item for item in radio.checks if item.code == "transport.rx_data_plane")
    assert check.status == "fail"
    assert "TimeoutError" in check.summary
    assert radio.overall == "fail"


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
            "ad9361-phy,model": "unsupported-phy",
            "device_names": ("ad9361-phy", "cf-ad9361-lpc"),
        },
    )

    radio = local_doctor.diagnose_local_usb_radios(devices=(_device(serial=None),)).radios[0]
    statuses = {check.code: check.status for check in radio.checks}
    assert statuses["identity.usb_serial"] == "fail"
    assert statuses["firmware.diagnostic_profile"] == "fail"
    assert statuses["rf.phy_model"] == "fail"
    assert statuses["transport.buffer_metadata"] == "unknown"
    assert radio.overall == "fail"


def test_local_doctor_exact_path_must_resolve_once() -> None:
    with pytest.raises(ValueError, match="found 0"):
        local_doctor.diagnose_local_usb_radios(
            Path("/sys/bus/usb/devices/9-9"),
            devices=(_device(),),
        )


def test_local_doctor_surfaces_usb_power_lineage_and_recent_faults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(local_doctor, "inspect_bound_iiod", lambda interface: {})
    device = _device().model_copy(
        update={
            "advertised_max_power_ma": 500,
            "runtime_power_status": "active",
            "runtime_power_control": "on",
            "resolved_parent_path": "/sys/devices/pci0000:80/0000:82:00.0/usb5/5-1",
            "direct_to_root_hub": True,
            "intermediate_hub_count": 0,
            "root_controller_pci_address": "0000:82:00.0",
            "root_controller_vendor_id": "1b21",
            "root_controller_device_id": "3042",
            "link_faults": UsbLinkFaultSummary(
                observation_window="current boot",
                error_count=2,
                disconnect_count=1,
                port_power_cycle_count=1,
            ),
        }
    )

    radio = local_doctor.diagnose_local_usb_radios(devices=(device,)).radios[0]
    checks = {check.code: check for check in radio.checks}

    assert checks["usb.negotiated_speed"].status == "pass"
    assert checks["usb.controller_lineage"].status == "pass"
    assert checks["usb.power_budget"].status == "pass"
    assert "not measured" in checks["usb.power_budget"].summary
    assert checks["usb.recent_link_faults"].status == "fail"


def test_setup_probe_promotes_the_persistent_check_and_records_the_repair(
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
    repair = SetupRepairRecord(
        attempted=True,
        succeeded=True,
        changes=(("attr_name", None), ("attr_val", None), ("mode", "2r2t")),
        receipt_id="receipt-1",
    )
    probed = SetupProbeOutcome(
        status="pass",
        actual=(
            ("attr_name", None),
            ("attr_val", None),
            ("compatible", "ad9361"),
            ("mode", "2r2t"),
        ),
        summary="Persistent AD9361/2R2T U-Boot tuple was repaired and re-attested after reboot",
        repair=repair,
    )
    seen: list[str | None] = []

    def probe(device: LocalUsbPluto, firmware: str | None) -> SetupProbeOutcome:
        seen.append(firmware)
        return probed

    radio = local_doctor.diagnose_local_usb_radios(devices=(_device(),), setup_probe=probe).radios[
        0
    ]

    statuses = {check.code: check.status for check in radio.checks}
    assert statuses["setup.uboot_ad9361_2r2t"] == "pass"
    assert radio.setup_repair == repair
    assert seen == [local_doctor.LOCAL_POLICY.device_firmware]


def test_without_a_setup_probe_the_persistent_check_stays_unknown(
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

    radio = local_doctor.diagnose_local_usb_radios(devices=(_device(),)).radios[0]

    statuses = {check.code: check.status for check in radio.checks}
    assert statuses["setup.uboot_ad9361_2r2t"] == "unknown"
    assert radio.setup_repair is None


def _iiod_facts(fw: str) -> dict[str, object]:
    return {
        "hw_serial": "SERIAL_A",
        "hw_model": "Analog Devices PlutoSDR Rev.C",
        "fw_version": fw,
        "ad9361-phy,model": "ad9361",
        "iio,buffer-metadata": "1",
        "device_names": ("ad9361-phy", "cf-ad9361-lpc"),
    }


def _healthy_environment() -> IioEnvironmentReport:
    return IioEnvironmentReport(
        healthy=True,
        status=IioEnvironmentStatus.READY,
        message="ready",
        python_executable="/usr/bin/python3",
        libiio_version="0.25",
        backends=("usb",),
    )


@pytest.mark.parametrize(
    ("firmware", "expected"),
    [
        ("v0.38-plutoplus-spf-libiio-metadata-v5", "fail"),
        ("v0.39-plutoplus-spf-libiio-metadata-v6", "fail"),
        ("v0.40-plutoplus-spf-tandem-agc-v7", "fail"),
        ("v0.42-plutoplus-spf-ddr-burst-v1", "pass"),
        ("v0.32-dirty", "unknown"),
    ],
)
def test_release_currency_never_proposes_a_downgrade(
    monkeypatch: pytest.MonkeyPatch, firmware: str, expected: str
) -> None:
    monkeypatch.setattr(local_doctor, "inspect_bound_iiod", lambda interface: _iiod_facts(firmware))

    radio = local_doctor.diagnose_local_usb_radios(
        devices=(_device(),), environment_probe=_healthy_environment
    ).radios[0]

    statuses = {check.code: check.status for check in radio.checks}
    assert statuses["firmware.release_currency"] == expected


def test_report_carries_host_libiio_health(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        local_doctor,
        "inspect_bound_iiod",
        lambda interface: _iiod_facts(local_doctor.LOCAL_POLICY.device_firmware),
    )

    def broken() -> IioEnvironmentReport:
        return IioEnvironmentReport(
            healthy=False,
            status=IioEnvironmentStatus.USB_BACKEND_MISSING,
            message="native libiio has no USB backend",
            remediation="scripts/install_native_libiio.sh",
            python_executable="/usr/bin/python3",
        )

    report = local_doctor.diagnose_local_usb_radios(devices=(_device(),), environment_probe=broken)

    assert report.host_libiio is not None
    assert report.host_libiio.healthy is False
    assert report.host_libiio.remediation == "scripts/install_native_libiio.sh"


def test_a_failing_environment_probe_never_fails_the_sweep(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        local_doctor,
        "inspect_bound_iiod",
        lambda interface: _iiod_facts(local_doctor.LOCAL_POLICY.device_firmware),
    )

    def explodes() -> IioEnvironmentReport:
        raise RuntimeError("native loader blew up")

    report = local_doctor.diagnose_local_usb_radios(
        devices=(_device(),), environment_probe=explodes
    )

    assert report.host_libiio is None
    assert len(report.radios) == 1
