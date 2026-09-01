from __future__ import annotations

import pytest
from pydantic import ValidationError

from pluto_plus.rf_profile import (
    Ad936xChannelMode,
    Ad936xDriverProfile,
    PhysicalRfic,
    PhysicalRficAttestation,
    PhysicalRficEvidenceKind,
    ReceiverLayout,
    RfConfiguration,
    RfOperatingProfile,
    RfSupportTier,
)
from pluto_plus.setup_profiles import (
    AD9361_1R1T_CLEAR_ATTR_PROFILE,
    AD9361_1R1T_SET_ATTR_PROFILE,
    AD9363A_1R1T_CLEAR_ATTR_PROFILE,
    AD9363A_1R1T_SET_ATTR_PROFILE,
    ALL_SETUP_ENVIRONMENT_PROFILES,
    SETUP_ENVIRONMENT_PROFILES,
    SetupTarget,
    environment_profile_for_uboot,
    environment_profiles_for_target,
    setup_operating_profile,
    setup_target_profile,
)


def _runtime_configuration() -> RfConfiguration:
    return RfConfiguration(
        driver_profile=Ad936xDriverProfile.AD9361,
        channel_mode=Ad936xChannelMode.TWO_RX_TWO_TX,
        receiver_layout=ReceiverLayout.SINGLE_STREAM,
    )


def test_runtime_configuration_does_not_claim_a_physical_rfic_or_support_tier() -> None:
    configuration = _runtime_configuration()

    assert configuration.model_dump(mode="json") == {
        "schema_version": 1,
        "driver_profile": "ad9361",
        "channel_mode": "2r2t",
        "receiver_layout": "single_stream",
    }
    assert "physical_rfic" not in type(configuration).model_fields
    assert "support_tier" not in type(configuration).model_fields


def test_1r1t_configuration_exposes_only_one_digital_stream() -> None:
    with pytest.raises(ValidationError, match="1r1t mode exposes one"):
        RfConfiguration(
            driver_profile=Ad936xDriverProfile.AD9363A,
            channel_mode=Ad936xChannelMode.ONE_RX_ONE_TX,
            receiver_layout=ReceiverLayout.DUAL_STREAM,
        )


def test_ad9364_configuration_cannot_claim_2r2t() -> None:
    with pytest.raises(ValidationError, match="AD9364 driver profile requires"):
        RfConfiguration(
            driver_profile=Ad936xDriverProfile.AD9364,
            channel_mode=Ad936xChannelMode.TWO_RX_TWO_TX,
            receiver_layout=ReceiverLayout.SINGLE_STREAM,
        )


def test_physical_rfic_inventory_requires_typed_evidence() -> None:
    with pytest.raises(ValidationError, match="evidence"):
        PhysicalRficAttestation.model_validate({"physical_rfic": "ad9363"})

    attestation = PhysicalRficAttestation(
        physical_rfic=PhysicalRfic.AD9363,
        evidence_kind=PhysicalRficEvidenceKind.VISUAL_MARKING,
        evidence_reference="asset://radio-serial/pcb-photo/sha256-example",
    )
    assert attestation.physical_rfic is PhysicalRfic.AD9363


def test_hardware_qualified_policy_requires_a_qualification_reference() -> None:
    with pytest.raises(ValidationError, match="qualification reference"):
        RfOperatingProfile(
            profile_id="ad9361-2r2t-dual-rx",
            target_configuration=_runtime_configuration(),
            support_tier=RfSupportTier.HARDWARE_QUALIFIED,
        )

    policy = RfOperatingProfile(
        profile_id="starlink-rx0-15m",
        target_configuration=_runtime_configuration(),
        intended_physical_rfic=PhysicalRfic.AD9363,
        support_tier=RfSupportTier.DEVELOPMENT,
    )
    assert policy.qualification_reference is None


def test_existing_setup_profiles_declare_their_exposed_receiver_layout() -> None:
    assert {profile.configuration.driver_profile for profile in SETUP_ENVIRONMENT_PROFILES} == {
        Ad936xDriverProfile.AD9361
    }
    assert {profile.configuration.channel_mode for profile in SETUP_ENVIRONMENT_PROFILES} == {
        Ad936xChannelMode.TWO_RX_TWO_TX
    }
    assert {profile.configuration.receiver_layout for profile in SETUP_ENVIRONMENT_PROFILES} == {
        ReceiverLayout.DUAL_STREAM
    }


def test_native_target_is_bounded_without_claiming_physical_rfic_or_support() -> None:
    target = setup_target_profile(SetupTarget.AD9363A_1R1T)

    assert target.configuration == RfConfiguration(
        driver_profile=Ad936xDriverProfile.AD9363A,
        channel_mode=Ad936xChannelMode.ONE_RX_ONE_TX,
        receiver_layout=ReceiverLayout.SINGLE_STREAM,
    )
    assert target.expected_live_phy_models == ("ad9363a",)
    assert target.expected_rx_scan_channels == ("voltage0", "voltage1")
    assert target.require_paired_rx_recovery is False
    assert not hasattr(target, "physical_rfic")
    assert not hasattr(target, "support_tier")

    support = setup_operating_profile(target.target)
    assert support.support_tier is RfSupportTier.DEVELOPMENT
    assert support.intended_physical_rfic is None


def test_ad9361_driver_and_1r1t_channel_mode_are_independently_selectable() -> None:
    target = setup_target_profile(SetupTarget.AD9361_1R1T)

    assert target.configuration == RfConfiguration(
        driver_profile=Ad936xDriverProfile.AD9361,
        channel_mode=Ad936xChannelMode.ONE_RX_ONE_TX,
        receiver_layout=ReceiverLayout.SINGLE_STREAM,
    )
    assert target.expected_live_phy_models == ("ad9361",)
    assert target.expected_rx_scan_channels == ("voltage0", "voltage1")
    assert target.require_5g8_rx_lo is True
    assert target.require_paired_rx_recovery is False
    assert AD9361_1R1T_CLEAR_ATTR_PROFILE.uboot == {
        "attr_name": None,
        "attr_val": None,
        "compatible": "ad9361",
        "mode": "1r1t",
    }
    assert AD9361_1R1T_SET_ATTR_PROFILE.uboot == {
        "attr_name": "compatible",
        "attr_val": "ad9361",
        "compatible": "ad9361",
        "mode": "1r1t",
    }
    assert setup_operating_profile(target.target).support_tier is RfSupportTier.DEVELOPMENT


def test_native_target_has_only_two_exact_persistent_environment_candidates() -> None:
    clear = AD9363A_1R1T_CLEAR_ATTR_PROFILE.uboot
    explicit = AD9363A_1R1T_SET_ATTR_PROFILE.uboot

    assert clear == {
        "attr_name": None,
        "attr_val": None,
        "compatible": "ad9363a",
        "mode": "1r1t",
    }
    assert explicit == {
        "attr_name": "compatible",
        "attr_val": "ad9363a",
        "compatible": "ad9363a",
        "mode": "1r1t",
    }
    assert len(ALL_SETUP_ENVIRONMENT_PROFILES) == 6
    assert (
        environment_profile_for_uboot(explicit, SetupTarget.AD9363A_1R1T)
        is AD9363A_1R1T_SET_ATTR_PROFILE
    )
    assert environment_profile_for_uboot(explicit) is None


def test_native_profile_order_is_firmware_specific_and_bounded() -> None:
    assert environment_profiles_for_target(
        SetupTarget.AD9363A_1R1T,
        "v0.48-plutoplus-spf-iq-direct-async-v3",
    ) == (
        AD9363A_1R1T_SET_ATTR_PROFILE,
        AD9363A_1R1T_CLEAR_ATTR_PROFILE,
    )
    assert environment_profiles_for_target(
        SetupTarget.AD9363A_1R1T,
        "v0.39-plutoplus-spf-libiio-metadata-v6",
    ) == (
        AD9363A_1R1T_CLEAR_ATTR_PROFILE,
        AD9363A_1R1T_SET_ATTR_PROFILE,
    )

    assert environment_profiles_for_target(
        SetupTarget.AD9361_1R1T,
        "v0.48-plutoplus-spf-iq-direct-async-v3",
    ) == (
        AD9361_1R1T_SET_ATTR_PROFILE,
        AD9361_1R1T_CLEAR_ATTR_PROFILE,
    )
