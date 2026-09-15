"""Physical flash policy. Transport, image labels and model strings grant no range."""

from __future__ import annotations

import hashlib
import json
import re
import zlib
from dataclasses import asdict, dataclass

from pluto_plus.flash_ranges import Interval, validate_write_intervals
from pluto_plus.flash_writer import ISSUE99_TOOLS_SHA256S, ISSUE99_UPDATER_SHA256

POLICY_VERSION = "ppu-physical-flash-v1"
LEGACY_ADDRESS_LIMIT = 0x1000000
MAX_FLASH_BYTES = 128 * 1024 * 1024
# Reviewed synchronous firmware-only updater; this identifies its footprint,
# not qualification for bank addressing. No extended-range grants ship.
LEGACY_UPDATER_SHA256 = "d8a3693f88ca9f3f7e4f9e7b4ac4a62abb8976d610df058fc74bbd6a6ee915f0"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class FlashSafetyError(ValueError):
    """An operation cannot establish the required physical safety evidence."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


def _integer(value: int, label: str, *, zero: bool = False) -> None:
    if type(value) is not int or not (0 if zero else 1) <= value <= MAX_FLASH_BYTES:
        raise FlashSafetyError("flash_geometry_invalid", f"invalid {label}: {value!r}")


@dataclass(frozen=True, slots=True)
class FlashPartition:
    index: int
    name: str
    start: int
    size: int
    erase_size: int

    @property
    def end(self) -> int:
        return self.start + self.size


@dataclass(frozen=True, slots=True)
class FlashObservation:
    serial: str
    boot_id: str
    kernel: str
    updater_sha256: str
    tools_sha256: str
    boot_sha256: str
    flash_identity: str
    capacity: int
    partitions: tuple[FlashPartition, ...]
    environment_sha256: str
    report_sha256: str
    board_identity: str = ""

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(json.dumps(asdict(self), sort_keys=True).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class FlashQualification:
    """A reviewed hardware/write/boot combination, never supplied by an API client."""

    qualification_id: str
    flash_identity: str
    kernel: str
    updater_sha256: str
    tools_sha256: str
    boot_sha256: str
    partitions: tuple[FlashPartition, ...]
    capacity: int
    address_limit: int
    write_evidence_sha256: str
    cold_boot_evidence_sha256: str
    board_identity: str = ""


QUALIFICATIONS: tuple[FlashQualification, ...] = ()


@dataclass(frozen=True, slots=True)
class FlashDecision:
    policy_version: str
    observation: FlashObservation
    fit_sha256: str
    fit_size: int
    payload_start: int
    payload_end: int
    erase_start: int
    erase_end: int
    environment_start: int
    environment_end: int
    address_limit: int
    qualification_id: str | None
    qualification_sha256: str | None


def validate_flash(
    observation: FlashObservation,
    fit: bytes,
    *,
    qualifications: tuple[FlashQualification, ...] | None = None,
) -> FlashDecision:
    """Validate authoritative FIT bytes and every legacy updater write/erase span."""
    # Local import keeps the image validator authoritative without an import cycle.
    from pluto_plus.firmware import _validate_fit

    _validate_fit(fit)
    _integer(len(fit), "FIT size")
    _integer(observation.capacity, "flash capacity")
    if not observation.serial or not observation.boot_id or not observation.kernel:
        raise FlashSafetyError("flash_identity_unknown", "serial, boot ID and kernel are required")
    if not observation.flash_identity or not _DIGEST.fullmatch(observation.board_identity):
        raise FlashSafetyError("flash_identity_unknown", "actual flash identity is unavailable")
    jedec = observation.flash_identity.rsplit(":", 1)[-1]
    if not re.fullmatch(r"[0-9a-f]{6,12}", jedec):
        raise FlashSafetyError("flash_identity_unknown", "unsupported JEDEC identity")
    density = int(jedec[4:6], 16)
    if density not in range(20, 28) or observation.capacity != 1 << density:
        raise FlashSafetyError("flash_geometry_invalid", "partition capacity disagrees with JEDEC")
    for digest in (
        observation.updater_sha256,
        observation.tools_sha256,
        observation.boot_sha256,
        observation.environment_sha256,
        observation.report_sha256,
    ):
        if not _DIGEST.fullmatch(digest):
            raise FlashSafetyError("flash_observation_invalid", "missing build/content digest")
    if observation.updater_sha256 == ISSUE99_UPDATER_SHA256:
        if observation.tools_sha256 not in ISSUE99_TOOLS_SHA256S:
            raise FlashSafetyError("flash_writer_unknown", "updater dependencies are not reviewed")
    elif observation.updater_sha256 != LEGACY_UPDATER_SHA256:
        raise FlashSafetyError("flash_writer_unknown", "updater footprint is not reviewed")
    parts = observation.partitions
    # The reviewed updater targets mtd3 and fw_env.config targets mtd1. Different
    # offsets are supported; different destinations/contracts require a review.
    if {p.index for p in parts} != {0, 1, 2, 3} or len(parts) != 4:
        raise FlashSafetyError("flash_geometry_invalid", "expected exactly four flash partitions")
    names = {0: "qspi-fsbl-uboot", 1: "qspi-uboot-env", 2: "qspi-nvmfs", 3: "qspi-linux"}
    if any(p.name != names[p.index] for p in parts):
        raise FlashSafetyError("flash_geometry_invalid", "partition roles do not match the writer")
    for p in parts:
        if type(p.index) is not int:
            raise FlashSafetyError("flash_geometry_invalid", "invalid partition index")
        _integer(p.start, "partition offset", zero=True)
        _integer(p.size, "partition size")
        _integer(p.erase_size, "erase size")
        if (
            p.start % p.erase_size
            or p.size % p.erase_size
            or p.end > observation.capacity
            or not p.name
        ):
            raise FlashSafetyError("flash_geometry_invalid", "unaligned or out-of-flash partition")
    ordered = sorted(parts, key=lambda p: p.start)
    if (
        ordered[0].start != 0
        or ordered[0].index != 0
        or ordered[-1].end != observation.capacity
        or any(a.end != b.start for a, b in zip(ordered, ordered[1:], strict=False))
    ):
        raise FlashSafetyError("flash_geometry_invalid", "overlapping or incomplete partition map")
    firmware = next(p for p in parts if p.index == 3)
    env = next(p for p in parts if p.index == 1)
    if env.size != 0x20000 or env.erase_size > 0x20000:
        raise FlashSafetyError("flash_environment_unknown", "unsupported environment geometry")
    limit = min(observation.capacity, LEGACY_ADDRESS_LIMIT)
    qualification_id = qualification_digest = None
    for record in QUALIFICATIONS if qualifications is None else qualifications:
        if all(
            getattr(record, key) == getattr(observation, key)
            for key in (
                "flash_identity",
                "board_identity",
                "kernel",
                "updater_sha256",
                "tools_sha256",
                "boot_sha256",
                "partitions",
                "capacity",
            )
        ):
            _integer(record.address_limit, "qualified address limit")
            if (
                not record.qualification_id
                or not _DIGEST.fullmatch(record.write_evidence_sha256)
                or not _DIGEST.fullmatch(record.cold_boot_evidence_sha256)
                or record.address_limit > observation.capacity
            ):
                raise FlashSafetyError("flash_qualification_invalid", "incomplete qualification")
            limit = record.address_limit
            qualification_id = record.qualification_id
            qualification_digest = hashlib.sha256(
                json.dumps(asdict(record), sort_keys=True).encode()
            ).hexdigest()
            break
    end = firmware.start + len(fit)
    erase_end = firmware.start + (
        (len(fit) + firmware.erase_size - 1) // firmware.erase_size * firmware.erase_size
    )
    allowed_end = min(limit, firmware.end)
    if end > allowed_end or erase_end > allowed_end:
        maximum = max(
            0, (allowed_end - firmware.start) // firmware.erase_size * firmware.erase_size
        )
        raise FlashSafetyError(
            "flash_range_unqualified",
            f"FIT {len(fit)} bytes ends at 0x{end:X}; erase ends at 0x{erase_end:X}. "
            f"Allowed FIT <= {maximum} bytes, physical end <= 0x{allowed_end:X}. "
            "Use a smaller artifact or a qualified RAM/SD bootstrap, then create a new plan.",
        )
    try:
        validate_write_intervals(
            Interval(firmware.start, end),
            Interval(firmware.start, erase_end),
            destination=Interval(firmware.start, firmware.end),
            address_limit=limit,
            protected=tuple(Interval(p.start, p.end) for p in parts if p.index != 3),
        )
        validate_write_intervals(
            Interval(env.start, env.end),
            Interval(env.start, env.end),
            destination=Interval(env.start, env.end),
            address_limit=limit,
            protected=tuple(Interval(p.start, p.end) for p in parts if p.index != 1),
        )
    except ValueError as error:
        raise FlashSafetyError("flash_range_unqualified", str(error)) from error
    if any(p.end > limit for p in parts if p.index != 3):
        raise FlashSafetyError(
            "flash_range_unqualified", "protected/environment range exceeds limit"
        )
    return FlashDecision(
        POLICY_VERSION,
        observation,
        hashlib.sha256(fit).hexdigest(),
        len(fit),
        firmware.start,
        end,
        firmware.start,
        erase_end,
        env.start,
        env.end,
        limit,
        qualification_id,
        qualification_digest,
    )


def require_same_flash(expected: FlashDecision | None, current: FlashDecision) -> None:
    if expected is None or expected != current:
        raise FlashSafetyError(
            "flash_observation_changed",
            "image, target, boot, writer, layout or policy changed; create a new attested plan",
        )


def reject_uncontrolled_persistence() -> None:
    raise FlashSafetyError(
        "flash_transport_unqualified",
        "legacy mass-storage/helper persistence has no controlled pre-reboot integrity gate; "
        "use explicitly selected, attested SSH/FRM or qualified RAM/SD recovery",
    )


def decode_environment(raw: bytes, *, opaque_padding: bool = False) -> dict[bytes, bytes]:
    """Decode the reviewed single-copy, little-endian U-Boot environment."""
    if len(raw) != 0x20000 or int.from_bytes(raw[:4], "little") != zlib.crc32(raw[4:]):
        raise FlashSafetyError("protected_region_changed", "invalid environment size/CRC")
    data = raw[4:]
    terminator = data.find(b"\0\0")
    if terminator < 0 or (
        not opaque_padding and any(byte not in (0, 255) for byte in data[terminator + 2 :])
    ):
        raise FlashSafetyError("protected_region_changed", "invalid environment encoding/padding")
    values: dict[bytes, bytes] = {}
    for entry in data[:terminator].split(b"\0"):
        key, separator, value = entry.partition(b"=")
        if not separator or not key or key in values:
            raise FlashSafetyError("protected_region_changed", "invalid/duplicate environment key")
        values[key] = value
    return values


def verify_protected(
    before: dict[int, bytes],
    after: dict[int, bytes],
    fit_size: int,
    *,
    opaque_padding: bool = False,
) -> None:
    if set(before) != {0, 1, 2} or set(after) != set(before):
        raise FlashSafetyError(
            "protected_verification_unavailable", "incomplete protected readback"
        )
    for index in (0, 2):
        if not before[index] or after[index] != before[index]:
            raise FlashSafetyError("protected_region_changed", f"mtd{index} changed; do not reboot")
    expected = decode_environment(before[1], opaque_padding=opaque_padding)
    expected[b"fit_size"] = f"{fit_size:X}".encode()
    if decode_environment(after[1], opaque_padding=opaque_padding) != expected:
        raise FlashSafetyError("protected_region_changed", "unexpected U-Boot environment changes")
