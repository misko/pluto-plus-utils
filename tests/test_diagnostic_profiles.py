from __future__ import annotations

import pytest

from pluto_plus.diagnostic_profiles import (
    V5_PROFILE,
    V6_PROFILE,
    V6_TANDEM_ABI2_PROFILE,
    V6_TANDEM_LATCH_CLEAR_RAM_PROFILE,
    DiagnosticProfile,
    MetadataAbiState,
    parse_metadata_abi,
    select_diagnostic_profile,
)
from pluto_plus.doctor import CANONICAL_UBOOT, diagnose_radio
from pluto_plus.models import (
    DoctorStatus,
    RadioCapabilities,
    RadioIdentity,
    RadioSettings,
    RadioSnapshot,
    RadioState,
    Transport,
)


@pytest.mark.parametrize(
    ("raw", "abi", "state"),
    [
        ("1", 1, MetadataAbiState.AVAILABLE),
        ("2", 2, MetadataAbiState.AVAILABLE),
        (None, None, MetadataAbiState.ABSENT),
        ("", None, MetadataAbiState.ABSENT),
        ("garbage", None, MetadataAbiState.MALFORMED),
        ("3", 3, MetadataAbiState.AVAILABLE),
    ],
)
def test_metadata_abi_preserves_exact_observation(
    raw: object,
    abi: int | None,
    state: MetadataAbiState,
) -> None:
    observation = parse_metadata_abi(raw)

    assert observation.abi == abi
    assert observation.state is state


@pytest.mark.parametrize(
    ("profile", "metadata_abi", "tandem_agc"),
    [
        (V5_PROFILE, 1, False),
        (V6_PROFILE, 1, False),
        (V6_TANDEM_ABI2_PROFILE, 2, True),
        (V6_TANDEM_LATCH_CLEAR_RAM_PROFILE, 2, True),
    ],
)
def test_known_profiles_are_accepted_without_changing_mutation_policy(
    profile: DiagnosticProfile,
    metadata_abi: int,
    tandem_agc: bool,
) -> None:
    selected = select_diagnostic_profile(profile.firmware_version)
    assert selected is profile
    snapshot = RadioSnapshot(
        identity=RadioIdentity(
            radio_id="SERIAL_A",
            serial="SERIAL_A",
            uri="ip:192.168.1.15",
            transport=Transport.IIO_IP,
            model="Pluto+ Rev.C",
            firmware_version=profile.firmware_version,
            usb_path="/sys/devices/3-8",
        ),
        capabilities=RadioCapabilities(),
        state=RadioState.READY,
        revision=0,
        requested_settings=RadioSettings(),
        actual_settings=RadioSettings(),
    )

    report = diagnose_radio(
        snapshot,
        {
            "phy_model": "ad9361",
            "buffer_metadata_abi": metadata_abi,
            "tandem_agc": tandem_agc,
            "rx_scan_channels": ("voltage0", "voltage1", "voltage2", "voltage3"),
            "uboot": CANONICAL_UBOOT,
            "boot_provenance": "qspi_cold_boot_verified",
        },
        firmware_helper_available=True,
    )
    findings = {finding.code: finding for finding in report.findings}

    assert report.diagnostic_profile is not None
    assert report.diagnostic_profile.profile_id == profile.profile_id
    assert findings["firmware.device_version"].status is DoctorStatus.PASS
    assert findings["firmware.buffer_metadata"].status is DoctorStatus.PASS
    assert findings["firmware.tandem_agc"].status is DoctorStatus.PASS
    assert report.canonical_policy.device_firmware == V6_PROFILE.firmware_version


def test_unknown_future_metadata_abi_is_available_but_not_profile_compatible() -> None:
    snapshot = RadioSnapshot(
        identity=RadioIdentity(
            radio_id="SERIAL_A",
            serial="SERIAL_A",
            uri="ip:192.168.1.15",
            transport=Transport.IIO_IP,
            model="Pluto+ Rev.C",
            firmware_version=V6_PROFILE.firmware_version,
            usb_path="/sys/devices/3-8",
        ),
        capabilities=RadioCapabilities(),
        state=RadioState.READY,
        revision=0,
        requested_settings=RadioSettings(),
        actual_settings=RadioSettings(),
    )

    report = diagnose_radio(
        snapshot,
        {"buffer_metadata_abi": 3, "tandem_agc": False},
        firmware_helper_available=True,
    )
    finding = next(item for item in report.findings if item.code == "firmware.buffer_metadata")

    assert finding.status is DoctorStatus.FAIL
    assert finding.actual == 3
    assert "available but unsupported" in finding.summary


def test_unknown_firmware_is_an_explicit_unsupported_profile() -> None:
    assert select_diagnostic_profile("v99-future") is None
