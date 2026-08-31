from __future__ import annotations

import pytest

from pluto_plus.diagnostic_profiles import (
    DDR_BURST_V1_RC1_PROFILE,
    DDR_BURST_V1_RC2_PROFILE,
    DDR_BURST_V1_RC3_PROFILE,
    DDR_BURST_V1_RC5_PROFILE,
    DDR_BURST_V1_RELEASE_PROFILE,
    DDR_BURST_V2_RC1_PROFILE,
    DDR_BURST_V2_RC2_PROFILE,
    DDR_BURST_V2_RC3_PROFILE,
    DDR_BURST_V2_RELEASE_PROFILE,
    DDR_RING_PREFILL_V1_RC1_PROFILE,
    DDR_RING_PREFILL_V1_RELEASE_PROFILE,
    DDR_RING_V1_RC1_PROFILE,
    DDR_RING_V1_RC2_PROFILE,
    DDR_RING_V1_RELEASE_PROFILE,
    IIO_THROUGHPUT_AFFINITY_V1_RC1_PROFILE,
    IIO_THROUGHPUT_BUFFERED_SAMPLER_V7_RC1_PROFILE,
    IIO_THROUGHPUT_COVERAGE_WINDOW_V6_RC1_PROFILE,
    IIO_THROUGHPUT_COVERAGE_WINDOW_V6_RELEASE_PROFILE,
    IIO_THROUGHPUT_HOLD_V1_RC1_PROFILE,
    IIO_THROUGHPUT_HOLD_V2_RC1_PROFILE,
    IIO_THROUGHPUT_REFILL_SAMPLER_V4_RC1_PROFILE,
    IIO_THROUGHPUT_RW_AFFINITY_V2_RC1_PROFILE,
    IIO_THROUGHPUT_SAMPLER_POLL_V3_RC1_PROFILE,
    IIO_THROUGHPUT_SAMPLER_WAKE_V5_RC1_PROFILE,
    IIO_THROUGHPUT_TIMING_V1_RC1_PROFILE,
    IQ_DIRECT_ASYNC_RING_V1_RC1_PROFILE,
    SINGLE_RX_METADATA_RC1_PROFILE,
    TANDEM_AGC_V7_RELEASE_CANDIDATE_PROFILE,
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
        (TANDEM_AGC_V7_RELEASE_CANDIDATE_PROFILE, 2, True),
        (SINGLE_RX_METADATA_RC1_PROFILE, 3, True),
        (DDR_BURST_V1_RC1_PROFILE, 3, True),
        (DDR_BURST_V1_RC2_PROFILE, 3, True),
        (DDR_BURST_V1_RC3_PROFILE, 3, True),
        (DDR_BURST_V1_RC5_PROFILE, 3, True),
        (DDR_BURST_V1_RELEASE_PROFILE, 3, True),
        (DDR_BURST_V2_RC1_PROFILE, 3, True),
        (DDR_BURST_V2_RC2_PROFILE, 3, True),
        (DDR_BURST_V2_RC3_PROFILE, 3, True),
        (DDR_BURST_V2_RELEASE_PROFILE, 3, True),
        (DDR_RING_V1_RC1_PROFILE, 3, True),
        (DDR_RING_V1_RC2_PROFILE, 3, True),
        (DDR_RING_V1_RELEASE_PROFILE, 3, True),
        (DDR_RING_PREFILL_V1_RC1_PROFILE, 3, True),
        (DDR_RING_PREFILL_V1_RELEASE_PROFILE, 3, True),
        (IIO_THROUGHPUT_HOLD_V1_RC1_PROFILE, 3, True),
        (IIO_THROUGHPUT_HOLD_V2_RC1_PROFILE, 3, True),
        (IIO_THROUGHPUT_TIMING_V1_RC1_PROFILE, 3, True),
        (IIO_THROUGHPUT_AFFINITY_V1_RC1_PROFILE, 3, True),
        (IIO_THROUGHPUT_RW_AFFINITY_V2_RC1_PROFILE, 3, True),
        (IIO_THROUGHPUT_SAMPLER_POLL_V3_RC1_PROFILE, 3, True),
        (IIO_THROUGHPUT_REFILL_SAMPLER_V4_RC1_PROFILE, 3, True),
        (IIO_THROUGHPUT_SAMPLER_WAKE_V5_RC1_PROFILE, 3, True),
        (IIO_THROUGHPUT_COVERAGE_WINDOW_V6_RC1_PROFILE, 3, True),
        (IIO_THROUGHPUT_COVERAGE_WINDOW_V6_RELEASE_PROFILE, 3, True),
        (IIO_THROUGHPUT_BUFFERED_SAMPLER_V7_RC1_PROFILE, 3, True),
        (IQ_DIRECT_ASYNC_RING_V1_RC1_PROFILE, 3, True),
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


def test_upgrade_target_is_strictly_upgrade_only() -> None:
    from pluto_plus.diagnostic_profiles import (
        UPGRADE_TARGET_PROFILE,
        select_diagnostic_profile,
        upgrade_target_for,
    )

    older = select_diagnostic_profile("v0.38-plutoplus-spf-libiio-metadata-v5")
    intermediate = select_diagnostic_profile("v0.40-plutoplus-spf-tandem-agc-v7")
    at_target = select_diagnostic_profile("v0.43-plutoplus-spf-ddr-ring-v1")

    assert upgrade_target_for(older) is UPGRADE_TARGET_PROFILE
    # Never a sideways move, never a downgrade, never a guess.
    assert upgrade_target_for(intermediate) is UPGRADE_TARGET_PROFILE
    assert upgrade_target_for(at_target) is None
    assert upgrade_target_for(None) is None


def test_upgrade_target_is_a_full_release_not_a_candidate() -> None:
    from pluto_plus.diagnostic_profiles import UPGRADE_TARGET_PROFILE

    assert UPGRADE_TARGET_PROFILE.release_status == "hardware-qualified release"


def test_release_ranks_are_unique_and_ordered() -> None:
    from pluto_plus.diagnostic_profiles import DIAGNOSTIC_PROFILES

    ranks = [profile.release_rank for profile in DIAGNOSTIC_PROFILES]
    assert len(set(ranks)) == len(ranks)
    assert ranks == sorted(ranks)
