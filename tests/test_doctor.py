from __future__ import annotations

from pluto_plus.doctor import (
    CANONICAL_POLICY,
    CANONICAL_UBOOT,
    FEATURE_103_V1_RELEASE_PERSISTENT_POLICY,
    PERSISTENT_UPGRADE_POLICY,
    diagnose_radio,
)
from pluto_plus.models import (
    DoctorStatus,
    RadioCapabilities,
    RadioIdentity,
    RadioSettings,
    RadioSnapshot,
    RadioState,
    Transport,
)
from pluto_plus.setup_profiles import SET_ATTR_PROFILE


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


def test_persistent_upgrade_policy_selects_hardware_qualified_adaptive_scan_release() -> None:
    assert PERSISTENT_UPGRADE_POLICY is FEATURE_103_V1_RELEASE_PERSISTENT_POLICY
    assert PERSISTENT_UPGRADE_POLICY.hardware_qualified is True
    assert PERSISTENT_UPGRADE_POLICY.profile_id == (
        "adaptive-scan-v1-release-persistent-promotion"
    )
    assert PERSISTENT_UPGRADE_POLICY.device_firmware == (
        "v0.52-plutoplus-spf-adaptive-scan-v1"
    )


def test_doctor_passes_only_with_complete_persistent_evidence() -> None:
    report = diagnose_radio(
        _snapshot(),
        {
            "phy_model": "ad9361",
            "buffer_metadata": True,
            "rx_scan_channels": ("voltage0", "voltage1", "voltage2", "voltage3"),
            "rx_lo_5g8_accepted": True,
            "rx_lo_5g8_readback_hz": 5_800_000_000,
            "rx_lo_restored": True,
            "uboot": CANONICAL_UBOOT,
            "boot_provenance": "qspi_cold_boot_verified",
        },
        firmware_helper_available=True,
    )

    assert report.healthy
    assert all(finding.status is DoctorStatus.PASS for finding in report.findings)
    assert report.canonical_policy.asset_sha256 == (
        "8ffbb0bf0912285636ddbcf0b00e12deaca0f55612faf7d29efa067b22e61352"
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
    assert findings["rf.phy_model"].status is DoctorStatus.PASS
    assert findings["setup.uboot_2r2t"].status is DoctorStatus.UNKNOWN
    assert findings["firmware.boot_provenance"].status is DoctorStatus.UNKNOWN
    assert findings["identity.usb_path"].status is DoctorStatus.WARN
    assert findings["firmware.helper"].status is DoctorStatus.WARN
    assert findings["rf.phy_model"].remediation is None


def test_doctor_accepts_set_attr_profile_only_with_live_5g8_probe() -> None:
    report = diagnose_radio(
        _snapshot(),
        {
            "phy_model": "ad9361",
            "buffer_metadata": True,
            "rx_scan_channels": ("voltage0", "voltage1", "voltage2", "voltage3"),
            "rx_lo_5g8_accepted": True,
            "rx_lo_5g8_readback_hz": 5_800_000_000,
            "rx_lo_restored": True,
            "uboot": SET_ATTR_PROFILE.uboot,
            "boot_provenance": "qspi_cold_boot_verified",
        },
        firmware_helper_available=True,
    )
    findings = {finding.code: finding for finding in report.findings}

    assert report.healthy
    assert findings["setup.uboot_2r2t"].status is DoctorStatus.PASS
    assert findings["rf.rx_lo_5g8"].status is DoctorStatus.PASS


def test_old_firmware_recommends_only_guarded_profile_aware_flash() -> None:
    report = diagnose_radio(
        _snapshot(firmware="v0.38-plutoplus-spf-gain-series-v4"),
        {},
        firmware_helper_available=True,
    )
    finding = next(item for item in report.findings if item.code == "firmware.device_version")
    assert finding.status is DoctorStatus.FAIL
    assert finding.remediation is not None
    assert finding.remediation.remediation_id == "flash_canonical_firmware_mtd3"
    assert finding.remediation.requires_privileged_helper
    assert "volatile" in (finding.remediation.cli_hint or "")


def test_counter_utc_candidate_is_read_only_recognized_without_2r2t_repair_advice() -> None:
    report = diagnose_radio(
        _snapshot(firmware="v0.54-plutoplus-spf-counter-utc-v1-rc1"),
        {
            "phy_model": "ad9361",
            "buffer_metadata_abi": 3,
            "tandem_agc": True,
            "rx_scan_channels": ("voltage0", "voltage1", "voltage2", "voltage3"),
            "uboot": {"attr_name": None, "attr_val": None, "compatible": "ad9361", "mode": "1r1t"},
        },
        firmware_helper_available=True,
    )
    findings = {finding.code: finding for finding in report.findings}

    assert findings["firmware.device_version"].status is DoctorStatus.PASS
    assert findings["firmware.device_version"].remediation is None
    assert findings["firmware.buffer_metadata"].status is DoctorStatus.PASS
    assert findings["rf.dual_rx_scan"].status is DoctorStatus.PASS
    assert findings["rf.dual_rx_scan"].remediation is None
    assert findings["setup.uboot_2r2t"].remediation is None
    assert report.diagnostic_profile is not None
    assert "UTC accuracy unqualified" in report.diagnostic_profile.release_status
    assert report.canonical_policy.device_firmware != report.diagnostic_profile.firmware_version


def test_counter_utc_v052_candidate_remains_read_only_recognized() -> None:
    report = diagnose_radio(
        _snapshot(firmware="v0.52-plutoplus-spf-counter-utc-v1-rc1"),
        {
            "phy_model": "ad9363a",
            "buffer_metadata_abi": 3,
            "tandem_agc": True,
            "rx_scan_channels": ("voltage0", "voltage1"),
        },
        firmware_helper_available=True,
    )
    findings = {finding.code: finding for finding in report.findings}
    assert findings["firmware.device_version"].status is DoctorStatus.PASS
    assert findings["firmware.device_version"].remediation is None
    assert report.diagnostic_profile is not None
    assert report.diagnostic_profile.profile_id == "counter-utc-v1-rc1-candidate"
    assert "UTC accuracy unqualified" in report.diagnostic_profile.release_status
