from __future__ import annotations

from pluto_plus.doctor import CANONICAL_POLICY, CANONICAL_UBOOT, diagnose_radio
from pluto_plus.models import (
    DoctorStatus,
    RadioCapabilities,
    RadioIdentity,
    RadioSettings,
    RadioSnapshot,
    RadioState,
    Transport,
)


def _snapshot(
    *,
    firmware: str | None = None,
    usb_path: str | None = "/sys/devices/3-8",
) -> RadioSnapshot:
    return RadioSnapshot(
        identity=RadioIdentity(
            radio_id="SERIAL_A",
            serial="SERIAL_A",
            uri="ip:192.168.1.15",
            transport=Transport.IIO_IP,
            model="Pluto+ Rev.C",
            firmware_version=firmware or CANONICAL_POLICY.device_firmware,
            usb_path=usb_path,
        ),
        capabilities=RadioCapabilities(),
        state=RadioState.READY,
        revision=0,
        requested_settings=RadioSettings(),
        actual_settings=RadioSettings(),
    )


def test_doctor_passes_only_with_complete_persistent_evidence() -> None:
    report = diagnose_radio(
        _snapshot(),
        {
            "phy_model": "ad9361",
            "buffer_metadata": True,
            "rx_scan_channels": ("voltage0", "voltage1", "voltage2", "voltage3"),
            "uboot": CANONICAL_UBOOT,
            "boot_provenance": "qspi_cold_boot_verified",
        },
        firmware_helper_available=True,
    )

    assert report.healthy
    assert all(finding.status is DoctorStatus.PASS for finding in report.findings)
    assert report.canonical_policy.asset_sha256 == (
        "948b46506febacb087f3955be86015e074f8c0e3370a9dfc6a942e735d97f882"
    )


def test_doctor_does_not_infer_persistence_from_active_firmware_or_channels() -> None:
    report = diagnose_radio(
        _snapshot(usb_path=None),
        {
            "phy_model": "ad9363a",
            "buffer_metadata": True,
            "rx_scan_channels": ("voltage0", "voltage1", "voltage2", "voltage3"),
        },
        firmware_helper_available=False,
    )
    findings = {finding.code: finding for finding in report.findings}

    assert not report.healthy
    assert findings["firmware.device_version"].status is DoctorStatus.PASS
    assert findings["rf.phy_model"].status is DoctorStatus.FAIL
    assert findings["setup.uboot_2r2t"].status is DoctorStatus.UNKNOWN
    assert findings["firmware.boot_provenance"].status is DoctorStatus.UNKNOWN
    assert findings["identity.usb_path"].status is DoctorStatus.WARN
    assert findings["firmware.helper"].status is DoctorStatus.WARN
    assert findings["rf.phy_model"].remediation is not None
    assert not findings["rf.phy_model"].remediation.automatable


def test_old_firmware_recommends_only_guarded_profile_aware_flash() -> None:
    report = diagnose_radio(
        _snapshot(firmware="v0.38-plutoplus-spf-gain-series-v4"),
        {},
        firmware_helper_available=True,
    )
    finding = next(
        item for item in report.findings if item.code == "firmware.device_version"
    )
    assert finding.status is DoctorStatus.FAIL
    assert finding.remediation is not None
    assert finding.remediation.remediation_id == "flash_canonical_firmware_mtd3"
    assert finding.remediation.requires_privileged_helper
    assert "volatile" in (finding.remediation.cli_hint or "")
