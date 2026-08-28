"""Read-only firmware capability profiles used by doctor surfaces.

These profiles classify observed radios. They deliberately do not authorize
firmware or setup mutations; those remain bound to an exact ``FirmwarePolicy``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

SUPPORTED_AD936X_PHY_MODELS = ("ad9361", "ad9363a", "ad9364")


class MetadataAbiState(StrEnum):
    AVAILABLE = "available"
    ABSENT = "absent"
    MALFORMED = "malformed"


@dataclass(frozen=True, slots=True)
class MetadataAbi:
    raw: str | None
    abi: int | None
    state: MetadataAbiState


@dataclass(frozen=True, slots=True)
class DiagnosticProfile:
    profile_id: str
    firmware_version: str
    metadata_abis: tuple[int, ...]
    tandem_agc_required: bool
    release_status: str
    # Explicit chronological rank.  Upgrade decisions must never infer order from
    # DIAGNOSTIC_PROFILES tuple position: reordering it would silently propose a
    # firmware downgrade.
    release_rank: int


V5_PROFILE = DiagnosticProfile(
    profile_id="libiio-metadata-v5",
    firmware_version="v0.38-plutoplus-spf-libiio-metadata-v5",
    metadata_abis=(1,),
    tandem_agc_required=False,
    release_status="hardware-qualified release",
    release_rank=1,
)

V6_PROFILE = DiagnosticProfile(
    profile_id="libiio-metadata-v6",
    firmware_version="v0.39-plutoplus-spf-libiio-metadata-v6",
    metadata_abis=(1,),
    tandem_agc_required=False,
    release_status="hardware-qualified release",
    release_rank=2,
)

V6_TANDEM_ABI2_PROFILE = DiagnosticProfile(
    profile_id="libiio-metadata-v6-tandem-abi2-development",
    firmware_version="v0.39-plutoplus-spf-libiio-metadata-v6-35-g7f812",
    metadata_abis=(2,),
    tandem_agc_required=True,
    release_status="recognized development build; diagnostic-only",
    release_rank=3,
)

V6_TANDEM_LATCH_CLEAR_RAM_PROFILE = DiagnosticProfile(
    profile_id="libiio-metadata-v6-tandem-latch-clear-ram",
    firmware_version="v0.39-plutoplus-spf-libiio-metadata-v6-36-gab79b",
    metadata_abis=(2,),
    tandem_agc_required=True,
    release_status="RAM-only hardware-promotion candidate; never persistence-qualified",
    release_rank=4,
)

TANDEM_AGC_V7_RELEASE_CANDIDATE_PROFILE = DiagnosticProfile(
    profile_id="tandem-agc-v7-release-candidate",
    firmware_version="v0.40-plutoplus-spf-tandem-agc-v7",
    metadata_abis=(2,),
    tandem_agc_required=True,
    release_status="hardware-qualified release candidate; persistence qualified",
    release_rank=5,
)

SINGLE_RX_METADATA_RC1_PROFILE = DiagnosticProfile(
    profile_id="single-rx-metadata-rc1",
    firmware_version="v0.42-plutoplus-spf-single-rx-metadata-rc1",
    metadata_abis=(3,),
    tandem_agc_required=True,
    release_status="RAM-only single-RX metadata candidate; never persistence-qualified",
    release_rank=6,
)

DDR_BURST_V1_RC1_PROFILE = DiagnosticProfile(
    profile_id="ddr-burst-v1-rc1",
    firmware_version="v0.42-plutoplus-spf-ddr-burst-v1-rc1",
    metadata_abis=(3,),
    tandem_agc_required=True,
    release_status="RAM-only opt-in DDR burst candidate; never persistence-qualified",
    release_rank=7,
)

DDR_BURST_V1_RC2_PROFILE = DiagnosticProfile(
    profile_id="ddr-burst-v1-rc2",
    firmware_version="v0.42-plutoplus-spf-ddr-burst-v1-rc2",
    metadata_abis=(3,),
    tandem_agc_required=True,
    release_status="RAM-only opt-in DDR burst RC2 candidate; never persistence-qualified",
    release_rank=8,
)

DDR_BURST_V1_RC3_PROFILE = DiagnosticProfile(
    profile_id="ddr-burst-v1-rc3",
    firmware_version="v0.42-plutoplus-spf-ddr-burst-v1-rc3",
    metadata_abis=(3,),
    tandem_agc_required=True,
    release_status="RAM-only opt-in DDR burst RC3 candidate; never persistence-qualified",
    release_rank=9,
)

DDR_BURST_V1_RC5_PROFILE = DiagnosticProfile(
    profile_id="ddr-burst-v1-rc5",
    firmware_version="v0.42-plutoplus-spf-ddr-burst-v1-rc5",
    metadata_abis=(3,),
    tandem_agc_required=True,
    release_status="RAM-only opt-in DDR burst RC5 candidate; never persistence-qualified",
    release_rank=10,
)

DDR_BURST_V1_RELEASE_PROFILE = DiagnosticProfile(
    profile_id="ddr-burst-v1",
    firmware_version="v0.42-plutoplus-spf-ddr-burst-v1",
    metadata_abis=(3,),
    tandem_agc_required=True,
    release_status="hardware-qualified release",
    release_rank=11,
)

DDR_BURST_V2_RC1_PROFILE = DiagnosticProfile(
    profile_id="ddr-burst-v2-rc1",
    firmware_version="v0.42-plutoplus-spf-ddr-burst-v2-rc1",
    metadata_abis=(3,),
    tandem_agc_required=True,
    release_status="RAM-only DDR burst v2 candidate; never persistence-qualified",
    release_rank=12,
)

DDR_BURST_V2_RC2_PROFILE = DiagnosticProfile(
    profile_id="ddr-burst-v2-rc2",
    firmware_version="v0.42-plutoplus-spf-ddr-burst-v2-rc2",
    metadata_abis=(3,),
    tandem_agc_required=True,
    release_status="RAM-only DDR burst v2 RC2 candidate; never persistence-qualified",
    release_rank=13,
)

DDR_BURST_V2_RC3_PROFILE = DiagnosticProfile(
    profile_id="ddr-burst-v2-rc3",
    firmware_version="v0.42-plutoplus-spf-ddr-burst-v2-rc3",
    metadata_abis=(3,),
    tandem_agc_required=True,
    release_status="RAM-only DDR burst v2 RC3 candidate; never persistence-qualified",
    release_rank=14,
)

DDR_BURST_V2_RELEASE_PROFILE = DiagnosticProfile(
    profile_id="ddr-burst-v2",
    firmware_version="v0.42-plutoplus-spf-ddr-burst-v2",
    metadata_abis=(3,),
    tandem_agc_required=True,
    release_status="final bytes under RAM-only hardware qualification",
    release_rank=15,
)

DIAGNOSTIC_PROFILES = (
    V5_PROFILE,
    V6_PROFILE,
    V6_TANDEM_ABI2_PROFILE,
    V6_TANDEM_LATCH_CLEAR_RAM_PROFILE,
    TANDEM_AGC_V7_RELEASE_CANDIDATE_PROFILE,
    SINGLE_RX_METADATA_RC1_PROFILE,
    DDR_BURST_V1_RC1_PROFILE,
    DDR_BURST_V1_RC2_PROFILE,
    DDR_BURST_V1_RC3_PROFILE,
    DDR_BURST_V1_RC5_PROFILE,
    DDR_BURST_V1_RELEASE_PROFILE,
    DDR_BURST_V2_RC1_PROFILE,
    DDR_BURST_V2_RC2_PROFILE,
    DDR_BURST_V2_RC3_PROFILE,
    DDR_BURST_V2_RELEASE_PROFILE,
)
_PROFILES_BY_FIRMWARE = {profile.firmware_version: profile for profile in DIAGNOSTIC_PROFILES}


def select_diagnostic_profile(firmware_version: str | None) -> DiagnosticProfile | None:
    """Return the exact known profile; never infer compatibility by tag prefix."""

    if firmware_version is None:
        return None
    return _PROFILES_BY_FIRMWARE.get(firmware_version.strip())


def parse_metadata_abi(value: object) -> MetadataAbi:
    """Preserve a positive metadata ABI integer and classify bad observations."""

    if value is None:
        return MetadataAbi(raw=None, abi=None, state=MetadataAbiState.ABSENT)
    if isinstance(value, bool):
        return MetadataAbi(
            raw="1" if value else "0",
            abi=1 if value else None,
            state=MetadataAbiState.AVAILABLE if value else MetadataAbiState.ABSENT,
        )
    raw = value.decode(errors="replace").strip() if isinstance(value, bytes) else str(value).strip()
    if not raw:
        return MetadataAbi(raw=None, abi=None, state=MetadataAbiState.ABSENT)
    try:
        abi = int(raw, 10)
    except ValueError:
        return MetadataAbi(raw=raw, abi=None, state=MetadataAbiState.MALFORMED)
    if abi < 1:
        return MetadataAbi(raw=raw, abi=None, state=MetadataAbiState.MALFORMED)
    return MetadataAbi(raw=raw, abi=abi, state=MetadataAbiState.AVAILABLE)


# The release doctor proposes as an upgrade target: the newest full
# hardware-qualified release.  Release candidates, development builds, and
# RAM-only promotion candidates are deliberately excluded, so doctor never
# proposes moving a radio onto an image that was not qualified for persistence.
UPGRADE_TARGET_PROFILE = DDR_BURST_V1_RELEASE_PROFILE


def upgrade_target_for(profile: DiagnosticProfile | None) -> DiagnosticProfile | None:
    """Return the upgrade target only when a radio is strictly older than it.

    Never proposes a downgrade or a sideways move, and never ranks a firmware
    with no known profile.
    """

    if profile is None:
        return None
    if profile.release_rank >= UPGRADE_TARGET_PROFILE.release_rank:
        return None
    return UPGRADE_TARGET_PROFILE
