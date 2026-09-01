"""Bounded persistent AD936x setup targets and environment profiles.

Pluto boot scripts in the qualified firmware families do not all interpret
``attr_name``/``attr_val`` the same way. Keep two bounded candidate tuples for
each target explicit and let post-reboot hardware behaviour decide which one
works.

These targets describe requested driver/interface/layout state only.  They do
not attest the physically fitted RFIC, select firmware bytes, or imply a support
tier.  Those remain separate inventory and policy contracts.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

from pluto_plus.diagnostic_profiles import SUPPORTED_AD936X_PHY_MODELS
from pluto_plus.rf_profile import (
    Ad936xChannelMode,
    Ad936xDriverProfile,
    ReceiverLayout,
    RfConfiguration,
    RfOperatingProfile,
    RfSupportTier,
    RxLayoutExpectation,
)

RX_LO_5G8_HZ = 5_800_000_000
UBOOT_KEYS = ("attr_name", "attr_val", "compatible", "mode")


@dataclass(frozen=True, slots=True)
class SetupEnvironmentProfile:
    profile_id: str
    uboot_items: tuple[tuple[str, str | None], ...]
    configuration: RfConfiguration

    @property
    def uboot(self) -> dict[str, str | None]:
        return dict(self.uboot_items)


class SetupTarget(StrEnum):
    """Explicit setup destination; this is not a physical-RFIC attestation."""

    AD9361_2R2T = "ad9361-2r2t"
    AD9361_1R1T = "ad9361-1r1t"
    AD9363A_1R1T = "ad9363a-1r1t"


DEFAULT_SETUP_TARGET = SetupTarget.AD9361_2R2T


@dataclass(frozen=True, slots=True)
class SetupTargetProfile:
    """Runtime facts required after applying one target's bounded environment."""

    target: SetupTarget
    configuration: RfConfiguration
    environment_profiles: tuple[SetupEnvironmentProfile, SetupEnvironmentProfile]
    expected_live_phy_models: tuple[str, ...]
    expected_rx_scan_channels: tuple[str, ...]
    allow_additional_rx_scan_channels: bool
    require_5g8_rx_lo: bool

    def __post_init__(self) -> None:
        if any(
            profile.configuration != self.configuration for profile in self.environment_profiles
        ):
            raise ValueError("setup target environment has a different RF configuration")
        if not self.expected_live_phy_models or not self.expected_rx_scan_channels:
            raise ValueError("setup target must declare live PHY and RX scan expectations")

    @property
    def require_paired_rx_recovery(self) -> bool:
        return self.configuration.channel_mode is Ad936xChannelMode.TWO_RX_TWO_TX

    @property
    def rx_layout_expectation(self) -> RxLayoutExpectation:
        """Return the neutral hardware-open contract for this target."""

        return RxLayoutExpectation(
            live_phy_models=self.expected_live_phy_models,
            scan_channels=self.expected_rx_scan_channels,
            receiver_channels=(0, 1) if self.require_paired_rx_recovery else (0,),
            allow_additional_scan_channels=self.allow_additional_rx_scan_channels,
        )


AD9361_2R2T_CONFIGURATION = RfConfiguration(
    driver_profile=Ad936xDriverProfile.AD9361,
    channel_mode=Ad936xChannelMode.TWO_RX_TWO_TX,
    receiver_layout=ReceiverLayout.DUAL_STREAM,
)


CLEAR_ATTR_PROFILE = SetupEnvironmentProfile(
    profile_id="ad9361-2r2t-clear-attr-pair",
    uboot_items=(
        ("attr_name", None),
        ("attr_val", None),
        ("compatible", "ad9361"),
        ("mode", "2r2t"),
    ),
    configuration=AD9361_2R2T_CONFIGURATION,
)

SET_ATTR_PROFILE = SetupEnvironmentProfile(
    profile_id="ad9361-2r2t-set-attr-pair",
    uboot_items=(
        ("attr_name", "compatible"),
        ("attr_val", "ad9361"),
        ("compatible", "ad9361"),
        ("mode", "2r2t"),
    ),
    configuration=AD9361_2R2T_CONFIGURATION,
)

# Compatibility export: existing Doctor and callers use this name for only the
# hardware-qualified AD9361/2R2T profiles.  Do not broaden it to development
# targets and accidentally make the legacy 2R2T finding accept 1R1T.
SETUP_ENVIRONMENT_PROFILES = (CLEAR_ATTR_PROFILE, SET_ATTR_PROFILE)


AD9361_1R1T_CONFIGURATION = RfConfiguration(
    driver_profile=Ad936xDriverProfile.AD9361,
    channel_mode=Ad936xChannelMode.ONE_RX_ONE_TX,
    receiver_layout=ReceiverLayout.SINGLE_STREAM,
)

AD9361_1R1T_CLEAR_ATTR_PROFILE = SetupEnvironmentProfile(
    profile_id="ad9361-1r1t-clear-attr-pair",
    uboot_items=(
        ("attr_name", None),
        ("attr_val", None),
        ("compatible", "ad9361"),
        ("mode", "1r1t"),
    ),
    configuration=AD9361_1R1T_CONFIGURATION,
)

AD9361_1R1T_SET_ATTR_PROFILE = SetupEnvironmentProfile(
    profile_id="ad9361-1r1t-set-attr-pair",
    uboot_items=(
        ("attr_name", "compatible"),
        ("attr_val", "ad9361"),
        ("compatible", "ad9361"),
        ("mode", "1r1t"),
    ),
    configuration=AD9361_1R1T_CONFIGURATION,
)


AD9363A_1R1T_CONFIGURATION = RfConfiguration(
    driver_profile=Ad936xDriverProfile.AD9363A,
    channel_mode=Ad936xChannelMode.ONE_RX_ONE_TX,
    receiver_layout=ReceiverLayout.SINGLE_STREAM,
)


AD9363A_1R1T_CLEAR_ATTR_PROFILE = SetupEnvironmentProfile(
    profile_id="ad9363a-1r1t-clear-attr-pair",
    uboot_items=(
        ("attr_name", None),
        ("attr_val", None),
        ("compatible", "ad9363a"),
        ("mode", "1r1t"),
    ),
    configuration=AD9363A_1R1T_CONFIGURATION,
)

AD9363A_1R1T_SET_ATTR_PROFILE = SetupEnvironmentProfile(
    profile_id="ad9363a-1r1t-set-attr-pair",
    uboot_items=(
        ("attr_name", "compatible"),
        ("attr_val", "ad9363a"),
        ("compatible", "ad9363a"),
        ("mode", "1r1t"),
    ),
    configuration=AD9363A_1R1T_CONFIGURATION,
)

AD9361_2R2T_TARGET_PROFILE = SetupTargetProfile(
    target=SetupTarget.AD9361_2R2T,
    configuration=AD9361_2R2T_CONFIGURATION,
    environment_profiles=SETUP_ENVIRONMENT_PROFILES,
    # Preserve the existing default behaviour: live AD936x identity plus the
    # 5.8 GHz functional proof remains authoritative for this qualified path.
    expected_live_phy_models=SUPPORTED_AD936X_PHY_MODELS,
    expected_rx_scan_channels=("voltage0", "voltage1", "voltage2", "voltage3"),
    allow_additional_rx_scan_channels=True,
    require_5g8_rx_lo=True,
)

AD9361_1R1T_TARGET_PROFILE = SetupTargetProfile(
    target=SetupTarget.AD9361_1R1T,
    configuration=AD9361_1R1T_CONFIGURATION,
    environment_profiles=(
        AD9361_1R1T_CLEAR_ATTR_PROFILE,
        AD9361_1R1T_SET_ATTR_PROFILE,
    ),
    expected_live_phy_models=("ad9361",),
    expected_rx_scan_channels=("voltage0", "voltage1"),
    allow_additional_rx_scan_channels=False,
    # Unlike the native AD9363A target, this development path specifically
    # selects the wider AD9361 driver envelope and retains the restored 5.8 GHz
    # proof that the override is live.
    require_5g8_rx_lo=True,
)

AD9363A_1R1T_TARGET_PROFILE = SetupTargetProfile(
    target=SetupTarget.AD9363A_1R1T,
    configuration=AD9363A_1R1T_CONFIGURATION,
    environment_profiles=(
        AD9363A_1R1T_CLEAR_ATTR_PROFILE,
        AD9363A_1R1T_SET_ATTR_PROFILE,
    ),
    expected_live_phy_models=("ad9363a",),
    expected_rx_scan_channels=("voltage0", "voltage1"),
    allow_additional_rx_scan_channels=False,
    # AD9363A's native range cannot satisfy the legacy 5.8 GHz probe.  This
    # development target proves driver, 1R1T scan geometry, and TX safety; RF
    # tuning qualification remains a separate hardware checkpoint.
    require_5g8_rx_lo=False,
)

SETUP_TARGET_PROFILES = (
    AD9361_2R2T_TARGET_PROFILE,
    AD9361_1R1T_TARGET_PROFILE,
    AD9363A_1R1T_TARGET_PROFILE,
)

ALL_SETUP_ENVIRONMENT_PROFILES = tuple(
    environment
    for target_profile in SETUP_TARGET_PROFILES
    for environment in target_profile.environment_profiles
)

# Support policy is deliberately separate from the mutation target.  Neither
# policy claims which RFIC is physically fitted; that requires a
# PhysicalRficAttestation in inventory.
SETUP_OPERATING_PROFILES = (
    RfOperatingProfile(
        profile_id=SetupTarget.AD9361_2R2T.value,
        target_configuration=AD9361_2R2T_CONFIGURATION,
        support_tier=RfSupportTier.HARDWARE_QUALIFIED,
        qualification_reference=("docs/FLASHING_AND_DOCTOR.md#canonical-ad93612r2t-setup"),
    ),
    RfOperatingProfile(
        profile_id=SetupTarget.AD9361_1R1T.value,
        target_configuration=AD9361_1R1T_CONFIGURATION,
        support_tier=RfSupportTier.DEVELOPMENT,
    ),
    RfOperatingProfile(
        profile_id=SetupTarget.AD9363A_1R1T.value,
        target_configuration=AD9363A_1R1T_CONFIGURATION,
        support_tier=RfSupportTier.DEVELOPMENT,
    ),
)

# This exact release is the first qualified setup family observed to require
# attr_name=compatible and attr_val=ad9361 for the live PHY to expose 5.8 GHz.
# Unknown/new firmware remains fail-closed behind the setup firmware allowlist;
# adding another preference is a reviewed policy change.
_SET_ATTR_FIRST_FIRMWARES = frozenset({"v0.43-plutoplus-spf-ddr-ring-v1"})

# On this modern family the explicit compatible override is the primary native
# target; the static-DT/cleared-pair tuple remains the one bounded fallback.
_AD9363A_SET_ATTR_FIRST_FIRMWARES = frozenset({"v0.48-plutoplus-spf-iq-direct-async-v3"})
_AD9361_1R1T_SET_ATTR_FIRST_FIRMWARES = frozenset(
    {"v0.48-plutoplus-spf-iq-direct-async-v3"}
)


def setup_target_profile(target: SetupTarget) -> SetupTargetProfile:
    """Resolve one bounded runtime target without consulting firmware policy."""

    return next(profile for profile in SETUP_TARGET_PROFILES if profile.target is target)


def setup_operating_profile(target: SetupTarget) -> RfOperatingProfile:
    """Return separately declared support policy for one setup target."""

    return next(
        profile
        for profile in SETUP_OPERATING_PROFILES
        if profile.profile_id == target.value
    )


def environment_profiles_for_firmware(
    firmware_version: str,
) -> tuple[SetupEnvironmentProfile, SetupEnvironmentProfile]:
    """Return both profiles in the safest known order for an exact firmware."""

    if firmware_version in _SET_ATTR_FIRST_FIRMWARES:
        return SET_ATTR_PROFILE, CLEAR_ATTR_PROFILE
    return CLEAR_ATTR_PROFILE, SET_ATTR_PROFILE


def environment_profiles_for_target(
    target: SetupTarget,
    firmware_version: str,
) -> tuple[SetupEnvironmentProfile, SetupEnvironmentProfile]:
    """Return only one target's bounded profiles in firmware-specific order."""

    if target is SetupTarget.AD9361_2R2T:
        return environment_profiles_for_firmware(firmware_version)
    if target is SetupTarget.AD9361_1R1T:
        if firmware_version in _AD9361_1R1T_SET_ATTR_FIRST_FIRMWARES:
            return AD9361_1R1T_SET_ATTR_PROFILE, AD9361_1R1T_CLEAR_ATTR_PROFILE
        return AD9361_1R1T_CLEAR_ATTR_PROFILE, AD9361_1R1T_SET_ATTR_PROFILE
    if firmware_version in _AD9363A_SET_ATTR_FIRST_FIRMWARES:
        return AD9363A_1R1T_SET_ATTR_PROFILE, AD9363A_1R1T_CLEAR_ATTR_PROFILE
    return AD9363A_1R1T_CLEAR_ATTR_PROFILE, AD9363A_1R1T_SET_ATTR_PROFILE


def environment_profile_for_uboot(
    values: Mapping[str, str | None],
    target: SetupTarget = DEFAULT_SETUP_TARGET,
) -> SetupEnvironmentProfile | None:
    observed = {key: values.get(key) for key in UBOOT_KEYS}
    return next(
        (
            profile
            for profile in setup_target_profile(target).environment_profiles
            if observed == profile.uboot
        ),
        None,
    )


def is_supported_environment(
    values: Mapping[str, str | None],
    target: SetupTarget = DEFAULT_SETUP_TARGET,
) -> bool:
    return environment_profile_for_uboot(values, target) is not None
