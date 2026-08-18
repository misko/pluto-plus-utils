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


V5_PROFILE = DiagnosticProfile(
    profile_id="libiio-metadata-v5",
    firmware_version="v0.38-plutoplus-spf-libiio-metadata-v5",
    metadata_abis=(1,),
    tandem_agc_required=False,
    release_status="hardware-qualified release",
)

V6_PROFILE = DiagnosticProfile(
    profile_id="libiio-metadata-v6",
    firmware_version="v0.39-plutoplus-spf-libiio-metadata-v6",
    metadata_abis=(1,),
    tandem_agc_required=False,
    release_status="hardware-qualified release",
)

V6_TANDEM_ABI2_PROFILE = DiagnosticProfile(
    profile_id="libiio-metadata-v6-tandem-abi2-development",
    firmware_version="v0.39-plutoplus-spf-libiio-metadata-v6-36-gab79b",
    metadata_abis=(2,),
    tandem_agc_required=True,
    release_status="recognized development build; diagnostic-only",
)

DIAGNOSTIC_PROFILES = (V5_PROFILE, V6_PROFILE, V6_TANDEM_ABI2_PROFILE)
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
