"""Only reviewed, shipped records authorize live recovery operations."""

from importlib.resources import files

from .contracts import Observation, Profile, RecoveryError, digest

# General hardware qualification is still pending. This shipped incident recipe
# is restricted to one measured flash UID, one original image and low-bank writes.
PROFILES: tuple[Profile, ...] = (
    Profile.model_validate_json(
        files("pluto_plus.recovery").joinpath("assets/incident114-profile.json").read_bytes()
    ),
)


def get_profile(profile_id: str, profiles: tuple[Profile, ...] | None = None) -> Profile:
    matches = [
        p for p in (PROFILES if profiles is None else profiles) if p.profile_id == profile_id
    ]
    if len(matches) != 1:
        raise RecoveryError(
            "profile_unqualified",
            "no shipped qualification for this profile; retain diagnostics and request "
            "firmware-owned SD reader/writer and cold-boot qualification",
        )
    # Revalidate mutable nested containers and any incorrectly constructed records.
    return Profile.model_validate_json(matches[0].model_dump_json())


def qualify(profile: Profile, observed: Observation, *, mutation: bool = False) -> None:
    if profile.target_uid_sha256 is not None and (
        not observed.target.uid or digest(observed.target.uid.encode()) != profile.target_uid_sha256
    ):
        raise RecoveryError("target_mismatch", "flash unique ID differs from incident binding")
    for key in ("board", "soc", "ddr_bytes", "jedec"):
        if getattr(profile, key) != getattr(observed.target, key):
            raise RecoveryError("target_mismatch", f"qualified {key} differs")
    for key in ("geometry", "bootstrap_sha256", "writer_sha256", "qualification_id"):
        if getattr(profile, key) != getattr(observed, key):
            raise RecoveryError("writer_unqualified", f"qualified {key} differs")
    if profile.read_limit != observed.geometry.capacity:
        raise RecoveryError("reader_unqualified", "complete physical flash is not qualified")
    if mutation and (not observed.target.uid or observed.flash_protected):
        raise RecoveryError(
            "target_unbound", "unique identity and writable protection state required"
        )
