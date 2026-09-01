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
from pluto_plus.setup_profiles import SETUP_ENVIRONMENT_PROFILES


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
