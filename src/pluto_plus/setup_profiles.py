"""Bounded persistent AD9361/2R2T environment profiles.

Pluto boot scripts in the qualified firmware families do not all interpret
``attr_name``/``attr_val`` the same way.  Keep the two observed-safe tuples
explicit and let post-reboot hardware behaviour decide which one works.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

RX_LO_5G8_HZ = 5_800_000_000
UBOOT_KEYS = ("attr_name", "attr_val", "compatible", "mode")


@dataclass(frozen=True, slots=True)
class SetupEnvironmentProfile:
    profile_id: str
    uboot_items: tuple[tuple[str, str | None], ...]

    @property
    def uboot(self) -> dict[str, str | None]:
        return dict(self.uboot_items)


CLEAR_ATTR_PROFILE = SetupEnvironmentProfile(
    profile_id="ad9361-2r2t-clear-attr-pair",
    uboot_items=(
        ("attr_name", None),
        ("attr_val", None),
        ("compatible", "ad9361"),
        ("mode", "2r2t"),
    ),
)

SET_ATTR_PROFILE = SetupEnvironmentProfile(
    profile_id="ad9361-2r2t-set-attr-pair",
    uboot_items=(
        ("attr_name", "compatible"),
        ("attr_val", "ad9361"),
        ("compatible", "ad9361"),
        ("mode", "2r2t"),
    ),
)

SETUP_ENVIRONMENT_PROFILES = (CLEAR_ATTR_PROFILE, SET_ATTR_PROFILE)

# This exact release is the first qualified setup family observed to require
# attr_name=compatible and attr_val=ad9361 for the live PHY to expose 5.8 GHz.
# Unknown/new firmware remains fail-closed behind the setup firmware allowlist;
# adding another preference is a reviewed policy change.
_SET_ATTR_FIRST_FIRMWARES = frozenset({"v0.43-plutoplus-spf-ddr-ring-v1"})


def environment_profiles_for_firmware(
    firmware_version: str,
) -> tuple[SetupEnvironmentProfile, SetupEnvironmentProfile]:
    """Return both profiles in the safest known order for an exact firmware."""

    if firmware_version in _SET_ATTR_FIRST_FIRMWARES:
        return SET_ATTR_PROFILE, CLEAR_ATTR_PROFILE
    return CLEAR_ATTR_PROFILE, SET_ATTR_PROFILE


def environment_profile_for_uboot(
    values: Mapping[str, str | None],
) -> SetupEnvironmentProfile | None:
    observed = {key: values.get(key) for key in UBOOT_KEYS}
    return next(
        (profile for profile in SETUP_ENVIRONMENT_PROFILES if observed == profile.uboot),
        None,
    )


def is_supported_environment(values: Mapping[str, str | None]) -> bool:
    return environment_profile_for_uboot(values) is not None
