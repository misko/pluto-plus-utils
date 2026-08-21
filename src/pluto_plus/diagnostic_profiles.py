"""Read-only firmware capability profiles used by doctor surfaces.

These profiles classify observed radios. They deliberately do not authorize
firmware or setup mutations; those remain bound to an exact ``FirmwarePolicy``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


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

TANDEM_AGC_V8_RC1_PROFILE = DiagnosticProfile(
    profile_id="tandem-agc-v8-rc1",
    firmware_version="v0.41-plutoplus-spf-tandem-agc-v8-rc1",
    metadata_abis=(2,),
    tandem_agc_required=True,
    release_status="two-radio hardware-qualified persistent prerelease",
    release_rank=6,
)

DIAGNOSTIC_PROFILES = (
    V5_PROFILE,
    V6_PROFILE,
    V6_TANDEM_ABI2_PROFILE,
    V6_TANDEM_LATCH_CLEAR_RAM_PROFILE,
    TANDEM_AGC_V7_RELEASE_CANDIDATE_PROFILE,
    TANDEM_AGC_V8_RC1_PROFILE,
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
UPGRADE_TARGET_PROFILE = V6_PROFILE


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
