"""Pure provenance-based reconstruction and complete-sector repair planning."""

from __future__ import annotations

import zlib
from collections.abc import Callable
from typing import Literal

from pluto_plus.flash_ranges import Interval, validate_write_intervals
from pluto_plus.flash_safety import POLICY_VERSION, decode_environment

from .contracts import (
    Blob,
    HistoricalBoot,
    Observation,
    Patch,
    Plan,
    Profile,
    Provenance,
    RecoveryError,
    Region,
    Sector,
    canonical,
    digest,
)
from .fit import validate_fit
from .profiles import qualify


def _environment_values(raw: bytes, opaque_padding: bool) -> dict[bytes, bytes]:
    if not opaque_padding:
        return decode_environment(raw)
    if len(raw) != 0x20000 or int.from_bytes(raw[:4], "little") != zlib.crc32(raw[4:]):
        raise RecoveryError("environment_unknown", "invalid captured environment size or CRC")
    end = raw[4:].find(b"\0\0")
    if end < 0:
        raise RecoveryError("environment_unknown", "missing environment terminator")
    data = raw[4 : 4 + end + 2].ljust(len(raw) - 4, b"\0")
    # U-Boot imports entries only through the first double NUL. Normalize padding
    # solely for semantic parsing; the actual original padding is never rewritten.
    return decode_environment(zlib.crc32(data).to_bytes(4, "little") + data)


def environment_with_fit_size(raw: bytes, size: int, *, opaque_padding: bool = False) -> bytes:
    values = _environment_values(raw, opaque_padding)
    if b"fit_size" not in values:
        raise RecoveryError("environment_unknown", "captured environment lacks fit_size")
    old = b"fit_size=" + values[b"fit_size"]
    new = b"fit_size=" + f"{size:X}".encode()
    if opaque_padding and len(old) != len(new):
        raise RecoveryError("environment_unknown", "incident fit_size must preserve byte offsets")
    data = raw[4:]
    terminator = data.index(b"\0\0")
    entries = data[:terminator].split(b"\0")
    entries[entries.index(old)] = new
    encoded = b"\0".join(entries) + b"\0\0"
    if len(encoded) > len(data):
        raise RecoveryError("environment_unknown", "environment has no room for fit_size")
    # Keep original bytes at all padding offsets still outside the new data.
    old_end = terminator + 2
    if len(encoded) < old_end:
        pad = data[old_end : old_end + 1] or b"\0"
        encoded += pad * (old_end - len(encoded))
    encoded += data[len(encoded) :]
    result = zlib.crc32(encoded).to_bytes(4, "little") + encoded
    expected = values | {b"fit_size": f"{size:X}".encode()}
    if _environment_values(result, opaque_padding) != expected:
        raise RecoveryError("environment_unknown", "unexpected serialization change")
    return result


def build_plan(
    *,
    session_id: str,
    profile: Profile,
    observed: Observation,
    original: bytes,
    boot: bytes,
    fit: bytes,
    provenance: Provenance,
    history: bytes,
    put: Callable[[bytes], Blob],
) -> Plan:
    qualify(profile, observed, mutation=True)
    historical = HistoricalBoot.model_validate_json(history)
    if (
        canonical(historical) != history
        or digest(history) != provenance.historical_record_sha256
        or historical.target_uid != provenance.target_uid
        or historical.boot_sha256 != provenance.historical_boot_sha256
    ):
        raise RecoveryError("provenance_missing", "historical target boot receipt differs")
    if len(original) != observed.geometry.capacity:
        raise RecoveryError("backup_invalid", "backup does not cover full physical flash")
    if provenance.target_uid != observed.target.uid:
        raise RecoveryError("provenance_missing", "boot provenance belongs to another target")
    boot_region = observed.geometry.region("boot")
    env_region = observed.geometry.region("environment")
    fit_region = observed.geometry.region("fit")
    if (
        len(boot) != boot_region.size
        or digest(boot) != provenance.boot_source_sha256
        or digest(boot) != provenance.historical_boot_sha256
    ):
        raise RecoveryError(
            "provenance_missing", "full boot image must match target historical digest"
        )
    if digest(fit) != provenance.rollback_sha256:
        raise RecoveryError("provenance_missing", "rollback provenance differs")
    boot_start = provenance.boot_restore_start
    boot_end = boot_start + provenance.boot_restore_size
    if not boot_region.start <= boot_start < boot_end <= boot_region.end:
        raise RecoveryError(
            "provenance_missing", "explicit boot restoration exceeds boot partition"
        )
    restored_boot = bytearray(original[boot_region.start : boot_region.end])
    relative_start, relative_end = boot_start - boot_region.start, boot_end - boot_region.start
    restored_boot[relative_start:relative_end] = boot[relative_start:relative_end]
    if restored_boot != boot:
        raise RecoveryError(
            "provenance_missing", "unexplained boot changes outside approved restoration"
        )
    validate_fit(fit, profile.rollback, observed.target.soc)
    env_before = original[env_region.start : env_region.end]
    env_after = environment_with_fit_size(
        env_before, len(fit), opaque_padding=profile.opaque_environment_padding
    )
    expected = bytearray(original)
    patches: list[Patch] = []
    sectors: list[Sector] = []
    repairs: tuple[tuple[Literal["fit", "environment", "boot"], Region, int, bytes], ...] = (
        ("fit", fit_region, fit_region.start, fit),
        ("environment", env_region, env_region.start, env_after),
        ("boot", boot_region, boot_start, boot[relative_start:relative_end]),
    )
    for kind, region, payload_start, payload in repairs:
        if payload_start + len(payload) > region.end:
            raise RecoveryError("flash_range_unqualified", "payload exceeds partition")
        payload_end = payload_start + len(payload)
        expected[payload_start:payload_end] = payload
        patches.append(
            Patch(
                kind=kind,
                start=payload_start,
                payload=put(payload),
                before_sha256=digest(original[payload_start:payload_end]),
            )
        )
        first_sector = payload_start - (payload_start - region.start) % region.erase_size
        for start in range(first_sector, payload_end, region.erase_size):
            end = start + region.erase_size
            before, after = original[start:end], bytes(expected[start:end])
            if before == after:
                continue
            try:
                validate_write_intervals(
                    Interval(max(start, payload_start), min(end, payload_end)),
                    Interval(start, end),
                    destination=Interval(region.start, region.end),
                    address_limit=profile.write_limit,
                    protected=tuple(
                        Interval(p.start, p.end)
                        for p in observed.geometry.regions
                        if p.name != region.name
                    ),
                )
            except ValueError as error:
                raise RecoveryError("flash_range_unqualified", str(error)) from error
            sectors.append(
                Sector(
                    kind=kind,
                    start=start,
                    size=region.erase_size,
                    before_sha256=digest(before),
                    after=put(after),
                )
            )
    return Plan(
        policy_version=POLICY_VERSION,
        session_id=session_id,
        profile_sha256=profile.sha256,
        observation=observed,
        original=put(original),
        current=put(original),
        expected=put(bytes(expected)),
        provenance=provenance,
        history=put(history),
        boot_source=put(boot),
        patches=tuple(patches),
        sectors=tuple(sectors),
    )


def validate_plan(plan: Plan, profile: Profile, get: Callable[[Blob], bytes]) -> None:
    """Rebuild authority from immutable source bytes; never trust serialized intervals."""
    if plan.policy_version != POLICY_VERSION or plan.profile_sha256 != profile.sha256:
        raise RecoveryError("plan_stale", "policy or qualification changed")
    by_kind = {patch.kind: patch for patch in plan.patches}
    if set(by_kind) != {"boot", "environment", "fit"} or len(plan.patches) != 3:
        raise RecoveryError("plan_invalid", "repair patch set differs")
    blobs: dict[str, bytes] = {}

    def remember(data: bytes) -> Blob:
        blob = Blob(sha256=digest(data), size=len(data))
        blobs[blob.sha256] = data
        return blob

    rebuilt = build_plan(
        session_id=plan.session_id,
        profile=profile,
        observed=plan.observation,
        original=get(plan.original),
        boot=get(plan.boot_source),
        fit=get(by_kind["fit"].payload),
        provenance=plan.provenance,
        history=get(plan.history),
        put=remember,
    )
    if plan.patches != rebuilt.patches or plan.expected != rebuilt.expected:
        raise RecoveryError("plan_invalid", "expected image or patches differ from reconstruction")
    current = get(plan.current)
    expected = get(plan.expected)
    if len(current) != len(expected):
        raise RecoveryError("plan_invalid", "current flash length differs")
    expected_sectors = []
    for sector in rebuilt.sectors:
        before = current[sector.start : sector.start + sector.size]
        if digest(before) != sector.after.sha256:
            expected_sectors.append(sector.model_copy(update={"before_sha256": digest(before)}))
    if tuple(expected_sectors) != plan.sectors:
        raise RecoveryError("plan_invalid", "sector program differs from reconstructed image")
    # Changed bytes must be entirely contained in the original justified sectors.
    reconciled = bytearray(current)
    original = get(plan.original)
    for sector in rebuilt.sectors:
        end = sector.start + sector.size
        reconciled[sector.start : end] = original[sector.start : end]
    if reconciled != original:
        raise RecoveryError("plan_invalid", "unexplained changes outside repair footprint")
    for sector in plan.sectors:
        if get(sector.after) != expected[sector.start : sector.start + sector.size]:
            raise RecoveryError("plan_invalid", "sector payload differs")
